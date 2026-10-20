#pragma once

#include <string>
#include <mutex>
#include <unordered_map>
#include <unordered_set>
#include <windows.h>
#include <winevt.h>

namespace elf {

// Persists per-channel Windows Event Log bookmarks to disk so the agent
// can resume after a restart or network outage without losing events.
//
// A "bookmark" is a Windows Event Log opaque token (created with
// EvtCreateBookmark) that records the position of the last-processed event
// on a channel. When the agent restarts, it passes the saved bookmark to
// EvtSubscribe with the EvtSubscribeStartAfterBookmark flag, and Windows
// resumes delivering events from exactly that position; no events are
// lost and none are re-delivered.
//
// Storage layout:
//   %ProgramData%\ELFAgent\state\bookmarks\<channel>.xml
// Each file holds the bookmark XML string for one channel. The channel
// name is sanitized (backslashes -> underscores) so "Microsoft-Windows-
// Sysmon/Operational" becomes a flat filename.
//
// Thread safety: all public methods take an internal mutex, so the
// delivery callback (which calls update()) and the periodic-save thread
// (which calls saveAll()) can run concurrently. The in-memory bookmark
// HANDLE is NOT shared; each channel's bookmark is owned by the
// BookmarkStore and only mutated under the mutex.
//
// Lifecycle:
//   1. load(channel) at startup: reads the saved XML, creates an
//      EVT_HANDLE bookmark via EvtCreateBookmark. Returns nullptr if no
//      saved bookmark exists (first run) or on error (caller falls back to
//      EvtSubscribeToFutureEvents).
//   2. update(channel, hEvent) in the delivery callback: calls
//      EvtUpdateBookmark so the bookmark tracks the just-delivered event.
//      Cheap (no disk I/O).
//   3. saveAll() periodically (every ~30s or every ~100 events) and on
//      shutdown: serializes each channel's bookmark to XML via
//      EvtRender and writes it to the channel's file. Best-effort: a
//      write failure is logged but doesn't stop the agent.
class BookmarkStore {
public:
    BookmarkStore() = default;
    ~BookmarkStore();

    // Set the directory where bookmark files live. Call once at startup
    // before load()/saveAll(). Creates the directory if it doesn't exist.
    void setDirectory(const std::string& dir);

    // Load the saved bookmark for a channel. Returns an EVT_HANDLE (to be
    // passed to EvtSubscribe with EvtSubscribeStartAfterBookmark) or nullptr
    // if no saved bookmark exists or on error. The caller MUST NOT close
    // the returned handle; BookmarkStore owns it and will close it in its
    // destructor or saveAll(). Actually, to keep the subscription model
    // simple, the caller takes ownership of the handle for the lifetime of
    // the subscription; BookmarkStore keeps a copy of the XML so it can
    // re-create the handle if needed. See loadXml() for the XML-only path.
    EVT_HANDLE load(const std::string& channel);

    // Load only the saved bookmark XML for a channel (no handle creation).
    // Returns empty string if no saved bookmark. Used by EventCollector to
    // decide whether to use EvtSubscribeStartAfterBookmark or
    // EvtSubscribeToFutureEvents.
    std::string loadXml(const std::string& channel);

    // Update the in-memory bookmark for a channel to point at the given
    // event. Called from the delivery callback after each event is
    // processed. Cheap (no disk I/O). The bookmark handle must have been
    // created by load() or createForChannel() first.
    void update(const std::string& channel, EVT_HANDLE hEvent);

    // Returns true if the channel's bookmark has been advanced to a real
    // event by update() (or loaded from disk with a real position). Returns
    // false for a freshly-created empty bookmark (createForChannel) that has
    // never been updated. The caller uses this to decide between
    // EvtSubscribeStartAfterBookmark (only safe with a real position) and
    // EvtSubscribeToFutureEvents (correct for an empty bookmark). Using
    // StartAfterBookmark with an empty bookmark causes Windows to deliver
    // historical events from the beginning of the channel, a bulk backlog
    // that must be avoided on a fresh install.
    bool isUpdated(const std::string& channel);

    // Create a fresh (empty) bookmark for a channel. Used when a channel
    // has no saved bookmark but we still want to track its position for
    // future saves. Returns the handle; BookmarkStore also stores it.
    EVT_HANDLE createForChannel(const std::string& channel);

    // Persist all in-memory bookmarks to disk. Called periodically and on
    // shutdown. Best-effort: logs errors but doesn't throw. Returns the
    // number of channels successfully saved.
    int saveAll();

    // Persist a single channel's bookmark to disk. Best-effort.
    bool save(const std::string& channel);

private:
    // Sanitize a channel name into a safe filename (replace path
    // separators with underscores).
    static std::string sanitizeChannel(const std::string& channel);

    // Render the bookmark handle to its XML string. Returns empty on error.
    std::string renderBookmarkXml(EVT_HANDLE hBookmark);

    std::mutex m_mutex;
    std::string m_dir;
    // channel -> bookmark handle (owned by BookmarkStore)
    std::unordered_map<std::string, EVT_HANDLE> m_bookmarks;
    // Channels whose bookmark has been advanced to a real event (by update()
    // or by load() from a persisted XML that contains a real position). A
    // bookmark created by createForChannel() is NOT in this set until
    // update() is called. Used by isUpdated() so the subscriber knows whether
    // EvtSubscribeStartAfterBookmark is safe (real position) or whether it
    // must fall back to EvtSubscribeToFutureEvents (empty bookmark).
    std::unordered_set<std::string> m_updated;
};

} // namespace elf
