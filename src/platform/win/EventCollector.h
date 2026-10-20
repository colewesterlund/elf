#pragma once

#include "EventBuffer.h"
#include "BookmarkStore.h"
#include <windows.h>
#include <winevt.h>
#include <atomic>
#include <thread>
#include <functional>
#include <string>
#include <mutex>

namespace elf {

// A channel subscription spec: the Windows channel path + the XPath query
// that filters which events on that channel are delivered. An empty query
// means "all events" (L"*"). Used by subscribeWithQueries() and resubscribe()
// to drive XPath-based subscription filtering so Windows only delivers events
// the loaded rules actually reference (a major load reduction on a busy DC).
struct ChannelQuery {
    std::wstring channel;
    std::wstring query;   // XPath, e.g. L"*[System[EventID=4624 or EventID=4625]]"
    bool operator==(const ChannelQuery& o) const {
        return channel == o.channel && query == o.query;
    }
};

// Windows rejects an XPath predicate with more than 23 comparison terms
// (ERROR_EVT_INVALID_QUERY, 15001; measured on Server 2022, not documented).
// Flat queries stay under this; above it the channel-aware builder emits a
// structured <QueryList> with one <Select> per chunk, which has no such
// limit (tested with hundreds of <Select> elements).
constexpr size_t MAX_XPATH_EVENTID_TERMS = 20;

// Build an XPath query string that selects only events whose EventID is in
// the given set. Returns L"*" (all events) when the set is empty, since an
// empty set means "we can't pre-filter this channel" (e.g. a catch-all rule
// or a rule with no explicit EventID). The query format is:
//   *[System[EventID=4624 or EventID=4625 or ...]]
// FLAT form only, valid for at most MAX_XPATH_EVENTID_TERMS ids. Callers
// that may have more must use the channel-aware overload below.
std::wstring buildEventIdXPath(const std::vector<int>& eventIds);

// Channel-aware builder. Up to MAX_XPATH_EVENTID_TERMS ids → the flat form
// above. More → a structured query:
//   <QueryList><Query Id="0" Path="CH">
//     <Select Path="CH">*[System[(EventID=a or ...)]]</Select>  (×N chunks)
//   </Query></QueryList>
// which EvtSubscribe accepts with a NULL ChannelPath (the channel is inside
// the XML). subscribeOne() detects the structured form by its "<QueryList"
// prefix.
std::wstring buildEventIdXPath(const std::wstring& channel,
                               const std::vector<int>& eventIds);

class EventCollector;

// Context passed to EvtSubscribe's notify callback. The callback is a
// static C function with a fixed signature (DWORD WINAPI (*)(...)), so it
// can only receive a single PVOID context. This struct bundles everything
// the callback needs: the EventBuffer to push to, the channel name (for
// bookmark updates), the BookmarkStore (to update the bookmark position on
// each delivered event), and the owning collector (for the drop counters).
// The pointer is owned by EventCollector and lives for the duration of the
// subscription.
struct SubscribeContext {
    EventBuffer* buffer;
    std::string  channel;     // UTF-8 channel name (for bookmark keying)
    BookmarkStore* bookmarks; // may be null if bookmarking disabled
    EventCollector* owner;    // for renderFailures/subscribeErrors counters
};

// Subscribes to Windows Event Log channels and pushes rendered events into
// the EventBuffer. By default subscribes to all channels (matching the
// prototype); can be restricted to a list of channels for efficiency.
//
// Uses wevtapi push subscriptions (EvtSubscribe with a callback). Each
// channel gets its own subscription handle; the callback renders the event
// XML and appends to the buffer.
//
// Bookmark-based resume: when a BookmarkStore is attached (setBookmarkStore),
// the collector loads any saved bookmark for each channel at subscribe time
// and uses EvtSubscribeStartAfterBookmark so the subscription resumes from
// the last-processed event; no events are lost across restarts or network
// outages. The callback updates the bookmark on each delivered event, and
// a periodic save (every ~100 events or ~30s) persists the bookmark to disk.
//
// XPath subscription filtering: subscribeWithQueries() takes a per-channel
// XPath query (built from the loaded rules' EventIDs) so Windows only
// delivers events the rules reference. resubscribe() swaps the active
// subscriptions when the ruleset changes (hot reload), and is a no-op when
// the requested set equals what is already active, so the periodic reload
// paths don't churn every subscription for nothing. Both are thread-safe
// via m_subMutex; the delivery callback only touches m_buffer (not
// m_subscriptions), so there is no contention with the eval thread.
class EventCollector {
public:
    // Callback signature for channel enumeration progress.
    using ChannelEnumCallback = std::function<void(const std::wstring& channel, bool subscribed)>;

    explicit EventCollector(EventBuffer& buffer);
    ~EventCollector();

    // Attach a BookmarkStore for bookmark-based resume. Call once at
    // startup, before subscribeAll/subscribeWithQueries. The collector does
    // NOT own the BookmarkStore (main.cpp owns it); it just holds a pointer.
    void setBookmarkStore(BookmarkStore* store) { m_bookmarks = store; }

    // Subscribe to all channels (default). Returns the number of channels
    // successfully subscribed.
    int subscribeAll();

    // Subscribe to a specific list of channels (e.g. ["Security",
    // "Microsoft-Windows-Sysmon/Operational"]). Returns count subscribed.
    int subscribeChannels(const std::vector<std::wstring>& channels);

    // Subscribe to channels with per-channel XPath queries (XPath
    // subscription filtering). Each entry carries a channel path and an
    // XPath query; Windows only delivers events matching the query. An
    // empty query means "all events" on that channel. Used at startup when
    // the ruleset is known. Returns count subscribed.
    int subscribeWithQueries(const std::vector<ChannelQuery>& queries);

    // Stop all current subscriptions and re-subscribe with the given
    // channel→query pairs. Used when the ruleset changes (hot reload) so the
    // XPath filters track the new rules' EventIDs. Thread-safe (serialized
    // against concurrent callers). If `queries` equals the set already
    // active, returns immediately without touching any subscription.
    // Otherwise there is a brief gap (milliseconds) during the stop→
    // re-subscribe where events may be missed on channels without an
    // advanced bookmark. Returns count subscribed.
    int resubscribe(const std::vector<ChannelQuery>& queries);

    // Persist all bookmarks to disk now. Called by main.cpp on shutdown
    // and periodically. No-op if no BookmarkStore is attached.
    void saveBookmarks();

    // Channel paths (canonical case) of the currently-active subscriptions.
    // Used by main.cpp to keep the LogGrowthMonitor's measured channel set
    // in sync with what the collector actually watches (failed channels are
    // excluded; they generate nothing we could forward). Thread-safe.
    std::vector<std::wstring> subscribedChannels() const;

    // Stop all subscriptions and close handles.
    void stop();

    // What the active subscription set was built from, so resubscribe()
    // can recognize an identical request.
    enum class SubMode { None, Queries, All };

    // Incremented on every real (re)subscription of the channel set. Lets
    // tests verify that an identical resubscribe request was skipped.
    uint64_t resubscribeGeneration() const { return m_generation.load(); }

    // True when the active set came from subscribeAll(). Lets the reload
    // path skip tearing down ~400 channel subscriptions (30+ s to rebuild)
    // when the ruleset still needs "everything".
    bool isSubscribedToAll() const {
        std::lock_guard<std::mutex> lock(m_subMutex);
        return m_lastMode == SubMode::All;
    }

    // Silent-drop counters, reported by the status thread.
    //   renderFailures:   events Windows delivered that EvtRender could not
    //                     render (the event is lost; the bookmark advances).
    //   subscribeErrors:  EvtSubscribeActionError callbacks (Windows telling
    //                     us the subscription hit an error, e.g. a cleared
    //                     log underneath a bookmark).
    uint64_t renderFailures() const { return m_renderFailures.load(); }
    uint64_t subscribeErrors() const { return m_subscribeErrors.load(); }

private:
    friend struct SubscribeContext;
    static DWORD WINAPI notifyCallback(EVT_SUBSCRIBE_NOTIFY_ACTION action,
                                      PVOID pContext, EVT_HANDLE hEvent);

    // Subscribe to a single channel with a query. Returns the handle or
    // nullptr on failure. Shared by subscribeWithQueries/resubscribe. When
    // a BookmarkStore is attached, loads the saved bookmark for the channel
    // and uses EvtSubscribeStartAfterBookmark; otherwise uses
    // EvtSubscribeToFutureEvents. The SubscribeContext is heap-allocated
    // and stored in m_contexts (freed in stop()/destructor). If Windows
    // rejects a filtered query, retries once with "*" so a rule-referenced
    // channel is never left unsubscribed.
    EVT_HANDLE subscribeOne(const std::wstring& channel, const std::wstring& query);

    EventBuffer& m_buffer;
    std::vector<EVT_HANDLE> m_subscriptions;
    std::vector<SubscribeContext*> m_contexts;  // freed in stop()/dtor
    // mutable: subscribedChannels() is a const observer that needs to lock.
    mutable std::mutex m_subMutex;   // guards m_subscriptions (stop/resubscribe vs. eval)
    std::mutex m_resubMutex;         // serializes whole resubscribe()/subscribeAll() calls
    std::vector<ChannelQuery> m_lastQueries;
    SubMode m_lastMode = SubMode::None;
    std::atomic<uint64_t> m_generation{0};
    std::atomic<uint64_t> m_renderFailures{0};
    std::atomic<uint64_t> m_subscribeErrors{0};
    std::atomic<bool> m_running{false};
    BookmarkStore* m_bookmarks = nullptr;
};

} // namespace elf
