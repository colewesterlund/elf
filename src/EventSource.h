#pragma once

// The host's event source, behind an interface the agent runtime drives the
// same way on every platform: subscribe to what the rules can match, keep
// the position across restarts, report what was generated for the savings
// metric. Windows implements it over the Event Log (src/platform/win),
// Linux over the systemd journal (src/platform/linux).

#include "EventBuffer.h"
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace elf {

// What the rules can match on one channel (a Windows event-log channel or a
// Linux journal source): the channel name in its canonical spelling and
// the event ids referenced by the loaded rules. An empty id list means
// "every event on this channel".
struct SourceFilter {
    std::string channel;
    std::vector<int> eventIds;
    bool operator==(const SourceFilter& o) const {
        return channel == o.channel && eventIds == o.eventIds;
    }
};

class EventSource {
public:
    virtual ~EventSource() = default;

    // Subscribe to everything the host logs (catch-all rules present).
    // Returns the number of channels subscribed.
    virtual int subscribeAll() = 0;

    // Subscribe to the given channels, pre-filtered to the listed event ids
    // where the platform supports it. Returns the number subscribed.
    virtual int subscribe(const std::vector<SourceFilter>& filters) = 0;

    // Replace the active subscriptions. An identical request is a no-op;
    // an empty one stops collection. Returns the number subscribed.
    virtual int resubscribe(const std::vector<SourceFilter>& filters) = 0;

    // True when the active set came from subscribeAll().
    virtual bool isSubscribedToAll() const = 0;

    // Channels currently delivering events (canonical spelling, UTF-8).
    virtual std::vector<std::string> subscribedChannels() const = 0;

    // Persist the read position so the next start resumes without loss.
    virtual void savePosition() = 0;

    // Stop delivering and release the platform handles.
    virtual void stop() = 0;

    // Silent-drop counters for the status line: events the host delivered
    // that could not be rendered, and subscription errors the host reported.
    virtual uint64_t renderFailures() const = 0;
    virtual uint64_t subscribeErrors() const = 0;
};

// How much the host generated on the watched channels, independent of the
// pre-filter, for the created-vs-forwarded savings metric.
class GrowthMonitor {
public:
    virtual ~GrowthMonitor() = default;
    virtual void setChannels(const std::vector<std::string>& channels) = 0;
    virtual void measure(uint64_t avgBytesPerEvent) = 0;
    virtual uint64_t totalEvents() const = 0;
    virtual uint64_t totalBytes() const = 0;
};

// Platform factories. `stateDir` is where the source keeps its position
// files (bookmarks on Windows, the journal cursor on Linux).
std::unique_ptr<EventSource> makeEventSource(EventBuffer& buffer, const std::string& stateDir);
std::unique_ptr<GrowthMonitor> makeGrowthMonitor();

} // namespace elf
