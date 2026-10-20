#include "EventCollector.h"
#include "EventRender.h"
#include "HttpClient.h"
#include "Console.h"
#include <iostream>
#include <sstream>
#include <algorithm>

#pragma comment(lib, "wevtapi.lib")

namespace elf {

EventCollector::EventCollector(EventBuffer& buffer) : m_buffer(buffer) {}

EventCollector::~EventCollector() {
    stop();
}

DWORD WINAPI EventCollector::notifyCallback(EVT_SUBSCRIBE_NOTIFY_ACTION action,
                                            PVOID pContext, EVT_HANDLE hEvent) {
    // This runs on a wevtapi thread-pool thread. Nothing may escape it:
    // an exception thrown into the Windows callback dispatcher is a crash
    // with no usable report. Everything below is wrapped.
    try {
        auto* ctx = reinterpret_cast<SubscribeContext*>(pContext);
        if (!ctx) return ERROR_SUCCESS;
        if (action == EvtSubscribeActionError) {
            // Windows reports a subscription error here; hEvent carries the
            // Win32 error code, not an event handle. Count it and log it:
            // ignored, a subscription that has stopped delivering looks
            // exactly like a quiet channel.
            DWORD code = static_cast<DWORD>(reinterpret_cast<DWORD_PTR>(hEvent));
            if (ctx->owner) ctx->owner->m_subscribeErrors.fetch_add(1);
            logError("[EventCollector] Subscription error on channel " +
                     ctx->channel + ": Win32 error " + std::to_string(code));
            return ERROR_SUCCESS;
        }
        if (action != EvtSubscribeActionDeliver) return ERROR_SUCCESS;
        if (!ctx->buffer) return ERROR_SUCCESS;
        std::wstring xml = renderEventXml(hEvent);
        if (!xml.empty()) {
            ctx->buffer->push(xml);
        } else if (ctx->owner) {
            // The event is lost (we have no XML to evaluate). The bookmark
            // still advances below on purpose: a record that can never be
            // rendered must not pin the bookmark and re-deliver forever.
            uint64_t n = ctx->owner->m_renderFailures.fetch_add(1) + 1;
            if (n == 1 || n % 1000 == 0) {
                logError("[EventCollector] EvtRender failed on channel " +
                         ctx->channel + " (err " + std::to_string(GetLastError()) +
                         "); " + std::to_string(n) + " render failure(s) so far");
            }
        }
        // Update the bookmark so it tracks the just-delivered event. This is
        // cheap (no disk I/O) and happens on every event. The periodic save
        // thread in main.cpp calls saveBookmarks() every ~30s to persist the
        // updated positions to disk.
        if (ctx->bookmarks) {
            ctx->bookmarks->update(ctx->channel, hEvent);
        }
    } catch (const std::exception& e) {
        logError(std::string("[EventCollector] exception in delivery callback: ") + e.what());
    } catch (...) {
        logError("[EventCollector] non-std exception in delivery callback");
    }
    return ERROR_SUCCESS;
}

// Build an XPath query that selects only events whose EventID is in the
// given set. Empty set → L"*" (all events). The query is used as the
// `Query` parameter to EvtSubscribe so Windows only delivers matching
// events, cutting rendering/buffering/evaluation load dramatically on a
// busy host (e.g. a DC generating thousands of events/sec across hundreds
// of channels when the ruleset only references a few dozen EventIDs).
//
// Format: *[System[EventID=4624 or EventID=4625 or ...]]
// Windows Event Log XPath supports the `or` operator inside a predicate, so
// a single query can whitelist many EventIDs on one channel. Duplicate IDs
// are deduplicated so the query stays compact when multiple rules reference
// the same EventID.
static std::vector<int> dedupSorted(const std::vector<int>& eventIds) {
    std::vector<int> ids = eventIds;
    std::sort(ids.begin(), ids.end());
    ids.erase(std::unique(ids.begin(), ids.end()), ids.end());
    return ids;
}

static std::wstring flatPredicate(const std::vector<int>& ids, size_t from, size_t to) {
    std::wostringstream wss;
    wss << L"*[System[";
    for (size_t i = from; i < to; ++i) {
        if (i > from) wss << L" or ";
        wss << L"EventID=" << ids[i];
    }
    wss << L"]]";
    return wss.str();
}

std::wstring buildEventIdXPath(const std::vector<int>& eventIds) {
    if (eventIds.empty()) return L"*";
    std::vector<int> ids = dedupSorted(eventIds);
    return flatPredicate(ids, 0, ids.size());
}

// Escape a channel path for use inside an XML attribute.
static std::wstring xmlAttrEscape(const std::wstring& s) {
    std::wstring out;
    out.reserve(s.size());
    for (wchar_t c : s) {
        switch (c) {
            case L'&':  out += L"&amp;"; break;
            case L'<':  out += L"&lt;"; break;
            case L'>':  out += L"&gt;"; break;
            case L'"':  out += L"&quot;"; break;
            case L'\'': out += L"&apos;"; break;
            default:    out += c;
        }
    }
    return out;
}

std::wstring buildEventIdXPath(const std::wstring& channel,
                               const std::vector<int>& eventIds) {
    if (eventIds.empty()) return L"*";
    std::vector<int> ids = dedupSorted(eventIds);
    if (ids.size() <= MAX_XPATH_EVENTID_TERMS) {
        return flatPredicate(ids, 0, ids.size());
    }
    // Structured form: one <Select> per chunk of MAX_XPATH_EVENTID_TERMS.
    // Windows unions the selects, so this is equivalent to one big "or".
    std::wstring ch = xmlAttrEscape(channel);
    std::wostringstream wss;
    wss << L"<QueryList><Query Id=\"0\" Path=\"" << ch << L"\">";
    for (size_t from = 0; from < ids.size(); from += MAX_XPATH_EVENTID_TERMS) {
        size_t to = (std::min)(ids.size(), from + MAX_XPATH_EVENTID_TERMS);
        wss << L"<Select Path=\"" << ch << L"\">" << flatPredicate(ids, from, to)
            << L"</Select>";
    }
    wss << L"</Query></QueryList>";
    return wss.str();
}

int EventCollector::subscribeAll() {
    std::lock_guard<std::mutex> resubLock(m_resubMutex);
    m_running = true;
    m_lastMode = SubMode::All;
    m_lastQueries.clear();
    m_generation.fetch_add(1);
    logInfo("[EventCollector] Opening channel enum...");
    EVT_HANDLE hChannels = EvtOpenChannelEnum(nullptr, 0);
    if (!hChannels) {
        logError("[EventCollector] EvtOpenChannelEnum failed: " +
                 std::to_string(GetLastError()));
        return 0;
    }
    logInfo("[EventCollector] Enumerating channels...");

    int count = 0;
    int skipped = 0;
    LPWSTR path = nullptr;
    DWORD bufSize = 0, bufUsed = 0;

    // Standard EvtNextChannelPath pattern: call once; if the buffer is too
    // small it returns FALSE with ERROR_INSUFFICIENT_BUFFER and reports the
    // required size in bufUsed. Reallocate and retry the SAME call (it does
    // not advance on failure). On success the path is filled; subscribe and
    // free for the next iteration. ERROR_NO_MORE_ITEMS ends the loop.
    while (true) {
        if (!EvtNextChannelPath(hChannels, bufSize, path, &bufUsed)) {
            DWORD err = GetLastError();
            if (err == ERROR_INSUFFICIENT_BUFFER) {
                bufSize = bufUsed;
                free(path);
                // bufUsed is in CHARACTERS (WCHARs); allocate bytes accordingly.
                path = (LPWSTR)malloc(bufSize * sizeof(WCHAR));
                if (!path) break;
                continue; // retry with the larger buffer (same channel)
            }
            // ERROR_NO_MORE_ITEMS or other -> done.
            break;
        }

        std::wstring wpath(path);
        std::string npath(wpath.begin(), wpath.end());
        // Build the per-channel context (heap-allocated, freed in stop()).
        auto* ctx = new SubscribeContext{&m_buffer, npath, m_bookmarks, this};
        EVT_HANDLE hBookmark = nullptr;      // passed to EvtSubscribe
        EVT_HANDLE hStoreBookmark = nullptr; // kept in the store for update()
        DWORD flags = EvtSubscribeToFutureEvents;
        if (m_bookmarks) {
            // Try to load a saved bookmark for this channel. If one exists
            // AND has a real position, switch to EvtSubscribeStartAfterBookmark
            // so we resume from the last-processed event (no events lost
            // across restarts). If no saved bookmark exists (first run), or
            // the bookmark is empty (never advanced), create an empty one so
            // we can track position for future saves, and stay on
            // EvtSubscribeToFutureEvents. Using StartAfterBookmark with an
            // empty bookmark causes Windows to deliver historical events
            // from the beginning of the channel (a bulk backlog on a fresh
            // install).
            //
            // When using FutureEvents we must pass NULL to EvtSubscribe's
            // Bookmark parameter: a non-NULL bookmark with FutureEvents is
            // invalid and returns ERROR_INVALID_PARAMETER (87). The empty
            // bookmark is still created in the store so update() can advance
            // it; the next resubscribe will then use StartAfterBookmark.
            hStoreBookmark = m_bookmarks->load(npath);
            if (hStoreBookmark && m_bookmarks->isUpdated(npath)) {
                flags = EvtSubscribeStartAfterBookmark;
                hBookmark = hStoreBookmark;  // real position → pass to EvtSubscribe
            } else if (!hStoreBookmark) {
                m_bookmarks->createForChannel(npath);
            }
            // else: bookmark exists but was never advanced; pass NULL +
            // FutureEvents (hBookmark stays nullptr).
        }
        EVT_HANDLE hSub = EvtSubscribe(nullptr, nullptr, path, L"*", hBookmark,
                                       reinterpret_cast<PVOID>(ctx),
                                       notifyCallback, flags);
        if (hSub) {
            std::lock_guard<std::mutex> lock(m_subMutex);
            m_subscriptions.push_back(hSub);
            m_contexts.push_back(ctx);
            ++count;
            if (count % 50 == 0) {
                logInfo("[EventCollector] ...subscribed " +
                        std::to_string(count) + " channels so far");
            }
        } else {
            // Some channels reject subscriptions (e.g. analytic/debug channels
            // that must be enabled first); this is expected.
            ++skipped;
            delete ctx;
        }
        free(path);
        path = nullptr;
        bufSize = 0;
    }
    if (path) free(path);
    EvtClose(hChannels);
    logInfo("[EventCollector] Subscribed to " + std::to_string(count) +
            " channel(s)" +
            (skipped ? (" (" + std::to_string(skipped) + " skipped)") : "") +
            ".");
    return count;
}

int EventCollector::subscribeChannels(const std::vector<std::wstring>& channels) {
    m_running = true;
    int count = 0;
    for (const auto& ch : channels) {
        EVT_HANDLE hSub = subscribeOne(ch, L"*");
        if (hSub) {
            std::lock_guard<std::mutex> lock(m_subMutex);
            m_subscriptions.push_back(hSub);
            ++count;
        } else {
            logError("[EventCollector] Failed to subscribe to channel " +
                     wideToUtf8(ch) + " (err " +
                     std::to_string(GetLastError()) + ")");
        }
    }
    logInfo("[EventCollector] Subscribed to " + std::to_string(count) + "/" +
            std::to_string(channels.size()) + " channels.");
    return count;
}

// Subscribe to a single channel with a query. Shared by the query-based
// subscription paths. Returns the handle or nullptr on failure. The handle
// is NOT added to m_subscriptions here; the caller owns that bookkeeping
// (under m_subMutex) so the lock is held exactly once per subscription.
//
// When a BookmarkStore is attached, loads the saved bookmark for the
// channel and uses EvtSubscribeStartAfterBookmark so the subscription
// resumes from the last-processed event (no events lost across restarts).
// If no saved bookmark exists, creates an empty one for future tracking
// and stays on EvtSubscribeToFutureEvents.
EVT_HANDLE EventCollector::subscribeOne(const std::wstring& channel,
                                        const std::wstring& query) {
    const wchar_t* q = query.empty() ? L"*" : query.c_str();
    // A structured <QueryList> query names the channel inside the XML and
    // EvtSubscribe requires a NULL ChannelPath for it.
    bool structured = query.rfind(L"<QueryList", 0) == 0;
    std::string nchannel(channel.begin(), channel.end());
    auto* ctx = new SubscribeContext{&m_buffer, nchannel, m_bookmarks, this};
    EVT_HANDLE hBookmark = nullptr;      // passed to EvtSubscribe
    EVT_HANDLE hStoreBookmark = nullptr; // kept in the store for update()
    DWORD flags = EvtSubscribeToFutureEvents;
    if (m_bookmarks) {
        hStoreBookmark = m_bookmarks->load(nchannel);
        // Only use EvtSubscribeStartAfterBookmark if the bookmark has a REAL
        // position (advanced by update() or loaded from a persisted XML).
        // An empty bookmark (created by createForChannel, never updated)
        // must NOT be used with EvtSubscribeStartAfterBookmark: per the
        // Windows docs, an empty bookmark with StartAfterBookmark causes
        // the subscription to deliver historical events from the beginning
        // of the channel, a bulk backlog on a fresh install.
        //
        // When falling back to EvtSubscribeToFutureEvents we must pass NULL
        // to EvtSubscribe's Bookmark parameter: a non-NULL bookmark with
        // FutureEvents is invalid and returns ERROR_INVALID_PARAMETER (87).
        // We still ensure an empty bookmark exists in the store (via
        // createForChannel) so the delivery callback's update() can advance
        // it; the next resubscribe will then see isUpdated()==true and use
        // StartAfterBookmark correctly.
        if (hStoreBookmark && m_bookmarks->isUpdated(nchannel)) {
            flags = EvtSubscribeStartAfterBookmark;
            hBookmark = hStoreBookmark;  // real position → pass to EvtSubscribe
        } else if (!hStoreBookmark) {
            // First run: create an empty bookmark in the store so update()
            // can advance it, but do NOT pass it to EvtSubscribe (NULL +
            // FutureEvents is the only valid combination for a fresh start).
            m_bookmarks->createForChannel(nchannel);
        }
        // else: bookmark exists but was never advanced, so treat as empty:
        // pass NULL + FutureEvents (hBookmark stays nullptr).
    }
    EVT_HANDLE hSub = EvtSubscribe(nullptr, nullptr,
                                   structured ? nullptr : channel.c_str(), q,
                                   hBookmark, reinterpret_cast<PVOID>(ctx),
                                   notifyCallback, flags);
    if (!hSub && std::wstring(q) != L"*") {
        // Windows rejected the filtered query (e.g. ERROR_EVT_INVALID_QUERY
        // 15001 for a predicate it considers too complex). Dropping the
        // channel would silently blind every rule on it; on a DC that is
        // the Security log. Fall back to all events on this channel; the
        // rule engine still filters, Windows just delivers more.
        DWORD err = GetLastError();
        logError("[EventCollector] Filtered subscription rejected for channel " +
                 wideToUtf8(channel) + " (err " + std::to_string(err) +
                 ", query length " + std::to_string(query.size()) +
                 "); falling back to all events on this channel.");
        hSub = EvtSubscribe(nullptr, nullptr, channel.c_str(), L"*",
                            hBookmark, reinterpret_cast<PVOID>(ctx),
                            notifyCallback, flags);
    }
    if (!hSub) {
        logError("[EventCollector] Failed to subscribe to channel " +
                 wideToUtf8(channel) + " (query=" +
                 wideToUtf8(structured ? L"<structured>" : q) +
                 ", err " + std::to_string(GetLastError()) + ")");
        delete ctx;
    } else {
        std::lock_guard<std::mutex> lock(m_subMutex);
        m_contexts.push_back(ctx);
    }
    return hSub;
}

int EventCollector::subscribeWithQueries(const std::vector<ChannelQuery>& queries) {
    std::lock_guard<std::mutex> resubLock(m_resubMutex);
    m_running = true;
    m_lastMode = SubMode::Queries;
    m_lastQueries = queries;
    m_generation.fetch_add(1);
    int count = 0;
    int skipped = 0;
    for (const auto& cq : queries) {
        EVT_HANDLE hSub = subscribeOne(cq.channel, cq.query);
        if (hSub) {
            std::lock_guard<std::mutex> lock(m_subMutex);
            m_subscriptions.push_back(hSub);
            ++count;
        } else {
            ++skipped;
        }
    }
    logInfo("[EventCollector] Subscribed to " + std::to_string(count) + "/" +
            std::to_string(queries.size()) + " channel(s) with XPath filtering" +
            (skipped ? (" (" + std::to_string(skipped) + " skipped)") : "") +
            ".");
    return count;
}

int EventCollector::resubscribe(const std::vector<ChannelQuery>& queries) {
    // Serialize whole calls: the poll thread and the 60 s reload thread can
    // both get here, and interleaving two close/reopen sequences leaves a
    // mix of old and new subscriptions.
    std::lock_guard<std::mutex> resubLock(m_resubMutex);
    // Same set as already active → nothing to do. Every real resubscribe
    // closes and reopens every channel (a gap where events on channels
    // without an advanced bookmark are missed), so the periodic reload
    // paths must not pay that for an unchanged ruleset.
    if (m_lastMode == SubMode::Queries && m_lastQueries == queries) {
        logInfo("[EventCollector] Subscription set unchanged (" +
                std::to_string(queries.size()) + " channel(s)); skipping resubscribe.");
        std::lock_guard<std::mutex> lock(m_subMutex);
        return static_cast<int>(m_subscriptions.size());
    }
    if (queries.empty() && m_lastMode == SubMode::None) {
        return 0;  // already subscribed to nothing
    }
    m_lastMode = queries.empty() ? SubMode::None : SubMode::Queries;
    m_lastQueries = queries;
    m_generation.fetch_add(1);
    // Stop all current subscriptions so the new XPath filters take effect.
    // There is a brief gap (milliseconds) between stop and re-subscribe
    // where events may be missed; this is acceptable for a ruleset change
    // (rare). We do NOT clear m_running here; the collector stays "running"
    // across a resubscribe so the destructor's stop() still tears down.
    {
        std::lock_guard<std::mutex> lock(m_subMutex);
        for (auto h : m_subscriptions) {
            if (h) EvtClose(h);
        }
        m_subscriptions.clear();
        for (auto* ctx : m_contexts) {
            delete ctx;
        }
        m_contexts.clear();
    }
    int count = 0;
    int skipped = 0;
    for (const auto& cq : queries) {
        EVT_HANDLE hSub = subscribeOne(cq.channel, cq.query);
        if (hSub) {
            std::lock_guard<std::mutex> lock(m_subMutex);
            m_subscriptions.push_back(hSub);
            ++count;
        } else {
            ++skipped;
        }
    }
    logInfo("[EventCollector] Re-subscribed to " + std::to_string(count) + "/" +
            std::to_string(queries.size()) + " channel(s) with XPath filtering" +
            (skipped ? (" (" + std::to_string(skipped) + " skipped)") : "") +
            ".");
    return count;
}

void EventCollector::saveBookmarks() {
    if (m_bookmarks) {
        m_bookmarks->saveAll();
    }
}

std::vector<std::wstring> EventCollector::subscribedChannels() const {
    std::lock_guard<std::mutex> lock(m_subMutex);
    std::vector<std::wstring> out;
    out.reserve(m_contexts.size());
    // SubscribeContext::channel is UTF-8; Windows channel paths are
    // ASCII, so the simple widening is lossless here.
    for (const auto* ctx : m_contexts) {
        out.emplace_back(ctx->channel.begin(), ctx->channel.end());
    }
    return out;
}

void EventCollector::stop() {
    if (!m_running.exchange(false)) return;
    std::lock_guard<std::mutex> lock(m_subMutex);
    for (auto h : m_subscriptions) {
        if (h) EvtClose(h);
    }
    m_subscriptions.clear();
    for (auto* ctx : m_contexts) {
        delete ctx;
    }
    m_contexts.clear();
}

} // namespace elf
