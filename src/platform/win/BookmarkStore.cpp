#include "BookmarkStore.h"
#include "Console.h"
#include <filesystem>
#include <fstream>
#include <sstream>
#include <algorithm>
#include <vector>

#pragma comment(lib, "wevtapi.lib")

namespace elf {

BookmarkStore::~BookmarkStore() {
    // Best-effort: persist the latest bookmark positions before the handles
    // are closed. This protects against a crash during shutdown that would
    // otherwise lose the in-memory updates since the last periodic save.
    // We do NOT hold the mutex here (the destructor is single-threaded by
    // contract) but saveAll() takes it.
    saveAll();
    for (auto& [ch, h] : m_bookmarks) {
        if (h) EvtClose(h);
    }
}

void BookmarkStore::setDirectory(const std::string& dir) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_dir = dir;
    // Ensure trailing separator so m_dir + filename works directly.
    if (!m_dir.empty() && m_dir.back() != '\\' && m_dir.back() != '/') {
        m_dir += "\\";
    }
    std::error_code ec;
    std::filesystem::create_directories(m_dir, ec);
    if (ec) {
        logError("[BookmarkStore] Could not create bookmark directory '" +
                 m_dir + "': " + ec.message());
    }
}

std::string BookmarkStore::sanitizeChannel(const std::string& channel) {
    // Channel paths contain backslashes (e.g. "Microsoft-Windows-Sysmon/
    // Operational" uses forward slashes; "Microsoft-Windows-PowerShell/
    // Operational" too). Replace any path separator with an underscore so
    // the channel name becomes a flat, safe filename. Also replace colons
    // and other illegal filename chars for robustness.
    std::string out = channel;
    std::replace_if(out.begin(), out.end(),
        [](char c) {
            return c == '\\' || c == '/' || c == ':' || c == '*' ||
                   c == '?' || c == '"' || c == '<' || c == '>' || c == '|';
        },
        '_');
    return out + ".xml";
}

std::string BookmarkStore::renderBookmarkXml(EVT_HANDLE hBookmark) {
    if (!hBookmark) return {};
    // EvtRender the bookmark to a wide string. First call with null buffer
    // to get the required size; allocate; second call fills it.
    DWORD bufUsed = 0;
    BOOL ok = EvtRender(nullptr, hBookmark, EvtRenderBookmark, 0, nullptr,
                       &bufUsed, nullptr);
    if (!ok) {
        DWORD err = GetLastError();
        if (err != ERROR_INSUFFICIENT_BUFFER) {
            logError("[BookmarkStore] EvtRender (size probe) failed: " +
                     std::to_string(err));
            return {};
        }
    }
    if (bufUsed == 0) return {};
    std::wstring w(bufUsed / sizeof(wchar_t), L'\0');
    ok = EvtRender(nullptr, hBookmark, EvtRenderBookmark,
                   bufUsed, w.data(), &bufUsed, nullptr);
    if (!ok) {
        logError("[BookmarkStore] EvtRender failed: " +
                 std::to_string(GetLastError()));
        return {};
    }
    // Trim the trailing NUL if present (EvtRender counts it in bufUsed).
    if (!w.empty() && w.back() == L'\0') w.pop_back();
    return std::string(w.begin(), w.end());
}

EVT_HANDLE BookmarkStore::load(const std::string& channel) {
    // If an in-memory handle already exists for this channel, return it.
    // This is critical for resubscribe: the delivery callback has been
    // advancing the in-memory bookmark on every event, so the in-memory
    // position is always >= the on-disk position (which is only flushed
    // every ~30s by the save thread). Re-reading the STALE on-disk bookmark
    // here would create a handle pointing BEHIND the current position, and
    // EvtSubscribeStartAfterBookmark would then RE-DELIVER every event
    // between the stale on-disk position and the live position; on a busy
    // host that is thousands of events re-evaluated and re-forwarded on
    // every ruleset reload. The in-memory handle is the source of truth
    // while the agent is running; the on-disk copy only matters across
    // process restarts (where the in-memory map is empty).
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        auto it = m_bookmarks.find(channel);
        if (it != m_bookmarks.end() && it->second) {
            return it->second;
        }
    }

    std::string xml = loadXml(channel);
    if (xml.empty()) return nullptr;
    // EvtCreateBookmark takes a wide XML string.
    std::wstring wxml(xml.begin(), xml.end());
    EVT_HANDLE h = EvtCreateBookmark(wxml.c_str());
    if (!h) {
        logError("[BookmarkStore] EvtCreateBookmark failed for channel " +
                 channel + ": " + std::to_string(GetLastError()));
        return nullptr;
    }
    std::lock_guard<std::mutex> lock(m_mutex);
    m_bookmarks[channel] = h;
    // A bookmark loaded from disk has a real persisted position, so it is
    // safe to use with EvtSubscribeStartAfterBookmark.
    m_updated.insert(channel);
    return h;
}

std::string BookmarkStore::loadXml(const std::string& channel) {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (m_dir.empty()) return {};
    std::string path = m_dir + sanitizeChannel(channel);
    std::ifstream f(path);
    if (!f.is_open()) return {};  // no saved bookmark (first run)
    std::ostringstream oss;
    oss << f.rdbuf();
    return oss.str();
}

void BookmarkStore::update(const std::string& channel, EVT_HANDLE hEvent) {
    std::lock_guard<std::mutex> lock(m_mutex);
    auto it = m_bookmarks.find(channel);
    if (it == m_bookmarks.end() || !it->second) return;
    // EvtUpdateBookmark advances the bookmark to point at the given event.
    if (!EvtUpdateBookmark(it->second, hEvent)) {
        // Non-fatal: we'll just save the previous position. Log at debug
        // to avoid spamming on a transient issue.
        logError("[BookmarkStore] EvtUpdateBookmark failed for channel " +
                 channel + ": " + std::to_string(GetLastError()));
        return;
    }
    // Mark this channel's bookmark as having a real position so the next
    // resubscribe can safely use EvtSubscribeStartAfterBookmark.
    m_updated.insert(channel);
}

bool BookmarkStore::isUpdated(const std::string& channel) {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_updated.count(channel) > 0;
}

EVT_HANDLE BookmarkStore::createForChannel(const std::string& channel) {
    // EvtCreateBookmark with NULL creates an empty bookmark that can be
    // updated as events arrive. This lets us track position for channels
    // that had no saved bookmark, so the NEXT restart can resume.
    EVT_HANDLE h = EvtCreateBookmark(nullptr);
    if (!h) {
        logError("[BookmarkStore] EvtCreateBookmark (empty) failed for " +
                 channel + ": " + std::to_string(GetLastError()));
        return nullptr;
    }
    std::lock_guard<std::mutex> lock(m_mutex);
    // If a handle already exists for this channel, close it first to avoid
    // a leak (e.g. load() then createForChannel() on a fresh start).
    auto it = m_bookmarks.find(channel);
    if (it != m_bookmarks.end() && it->second) {
        EvtClose(it->second);
    }
    m_bookmarks[channel] = h;
    return h;
}

bool BookmarkStore::save(const std::string& channel) {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (m_dir.empty()) return false;
    auto it = m_bookmarks.find(channel);
    if (it == m_bookmarks.end() || !it->second) return false;
    std::string xml = renderBookmarkXml(it->second);
    if (xml.empty()) return false;
    std::string path = m_dir + sanitizeChannel(channel);
    // Write to a temp file then rename for atomicity; a crash mid-write
    // would otherwise corrupt the bookmark and lose the position.
    std::string tmp = path + ".tmp";
    {
        std::ofstream f(tmp, std::ios::out | std::ios::trunc);
        if (!f.is_open()) {
            logError("[BookmarkStore] Could not open bookmark temp '" +
                     tmp + "' for writing.");
            return false;
        }
        f << xml;
    }
    std::error_code ec;
    std::filesystem::rename(tmp, path, ec);
    if (ec) {
        // rename can fail across volumes or if the target exists on some
        // filesystems; fall back to a plain copy + remove.
        std::filesystem::copy_file(tmp, path,
            std::filesystem::copy_options::overwrite_existing, ec);
        if (ec) {
            logError("[BookmarkStore] Failed to save bookmark for " +
                     channel + ": " + ec.message());
            std::filesystem::remove(tmp, ec);
            return false;
        }
        std::filesystem::remove(tmp, ec);
    }
    return true;
}

int BookmarkStore::saveAll() {
    // We can't call save() (which re-locks m_mutex) while holding m_mutex
    // (non-recursive). Instead, snapshot the (channel, handle) pairs under
    // the lock, then render+write each one WITHOUT the lock. The handles
    // are stable for the lifetime of the BookmarkStore (only created in
    // load()/createForChannel(), never replaced except in
    // createForChannel() which is called at startup, not concurrently with
    // saveAll()), so reading them outside the lock is safe.
    std::vector<std::pair<std::string, EVT_HANDLE>> snapshot;
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        snapshot.reserve(m_bookmarks.size());
        for (const auto& [ch, h] : m_bookmarks) {
            snapshot.emplace_back(ch, h);
        }
    }
    int saved = 0;
    for (const auto& [ch, h] : snapshot) {
        if (!h) continue;
        std::string xml = renderBookmarkXml(h);
        if (xml.empty()) continue;
        std::lock_guard<std::mutex> lock(m_mutex);
        if (m_dir.empty()) continue;
        std::string path = m_dir + sanitizeChannel(ch);
        std::string tmp = path + ".tmp";
        {
            std::ofstream f(tmp, std::ios::out | std::ios::trunc);
            if (!f.is_open()) {
                logError("[BookmarkStore] Could not open bookmark temp '" +
                         tmp + "' for writing.");
                continue;
            }
            f << xml;
        }
        std::error_code ec;
        std::filesystem::rename(tmp, path, ec);
        if (ec) {
            std::filesystem::copy_file(tmp, path,
                std::filesystem::copy_options::overwrite_existing, ec);
            if (ec) {
                logError("[BookmarkStore] Failed to save bookmark for " +
                         ch + ": " + ec.message());
                std::filesystem::remove(tmp, ec);
                continue;
            }
            std::filesystem::remove(tmp, ec);
        }
        ++saved;
    }
    return saved;
}

} // namespace elf
