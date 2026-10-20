#pragma once

#include <windows.h>
#include <winevt.h>
#include <string>
#include <functional>

namespace elf {

// EventQueryCollector: on-demand HISTORICAL event pull.
//
// Unlike EventCollector (a long-lived push subscription started once at
// boot), EventQueryCollector is a short-lived, one-shot pull: given a start
// time (UTC ISO-8601), it opens an EvtQuery against every Windows Event Log
// channel with a time-bounded XPath query and pages through all matching
// events with EvtNext, rendering each to XML and handing it to a callback.
//
// This is the "collect logs" mechanism: an analyst requests all events from a
// host since a date, the server queues a collect_logs command, the agent
// receives it on poll, and EventQueryCollector pulls the historical events
// for streaming back to the server.
//
// Channels that reject the query (analytic/debug, access denied) are skipped
// silently, mirroring EventCollector's behavior. The collector is stateless
// and safe to call from a dedicated worker thread.
class EventQueryCollector {
public:
    // Called for each rendered event XML (UTF-16). The callback may batch
    // and ship events to the server.
    using EventCallback = std::function<void(const std::wstring& xml)>;

    // Pull all events from all channels with TimeCreated >= startTimeIsoUtc.
    // startTimeIsoUtc must be UTC ISO-8601 in the form the Windows Event Log
    // XPath expects, e.g. "2026-10-01T00:00:00.000Z".
    // Returns the total number of events pulled (0 if none or on error).
    static size_t collect(const std::string& startTimeIsoUtc, EventCallback cb);

private:
    // Pull events from a single channel. Returns the count pulled from it.
    static size_t collectChannel(const std::wstring& channelPath,
                                 const std::wstring& xpathQuery,
                                 EventCallback& cb);
};

} // namespace elf
