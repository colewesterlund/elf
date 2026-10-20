#pragma once

#include <windows.h>
#include <winevt.h>
#include <atomic>
#include <map>
#include <mutex>
#include <string>
#include <vector>

namespace elf {

// Measures how many events the host GENERATES on the channels the agent
// watches, independent of the XPath subscription pre-filter.
//
// Why: EventCollector subscriptions are pre-filtered to the EventIDs the
// loaded rules reference (a major load reduction), so the EventBuffer only
// counts the delivered SUBSET. The metrics page's "created" denominator
// must reflect everything the host generated (that is the savings story:
// "the host generated N events, we forwarded only M"), so at each poll we
// take a per-channel growth measurement instead of using the buffer count.
//
// How: for each watched channel, read the log's OldestRecordNumber and
// NumberOfLogRecords via EvtOpenLog/EvtGetLogInfo and compute
//     newest = oldest + count - 1
// i.e. the record number of the most recent event. This position is monotonic
// even when a circular log wraps (the record COUNT plateaus at the log
// capacity while OLDEST keeps advancing), which is why we track it rather
// than the raw count. The delta between successive readings is the number
// of events written since the last measurement. No subscriptions, no
// event rendering; two metadata queries per channel per poll.
//
// Bytes: there is no cheap way to know the rendered size of events we never
// received, so bytes are ESTIMATED as (event delta) x (average rendered
// bytes per delivered event, supplied by the caller from the EventBuffer).
// Event counts are exact; byte counts are an estimate.
//
// Threading: setChannels() is called after every (re)subscribe, from the
// poll thread (server-pushed ruleset) or the 60s reload thread (disk
// reload); measure() is called from the poll thread. An internal mutex
// guards the channel list and per-channel baselines. applyReading() is
// public as a test seam for the delta logic.
class LogGrowthMonitor {
public:
    // Replace the measured channel set (canonical Windows channel paths,
    // e.g. L"Security"). Baselines for channels that drop out of the set
    // are discarded so a later re-add re-baselines instead of counting the
    // gap while the channel was unwatched. Thread-safe.
    void setChannels(const std::vector<std::wstring>& channels);

    // Number of channels currently being measured. Thread-safe.
    size_t channelCount() const;

    // Read every watched channel's oldest/count via the Windows Event Log
    // API and accumulate growth into the totals. Channels that cannot be
    // opened (removed, access denied, analytic channel not enabled) are
    // silently skipped; the subscription failure logged by
    // EventCollector is the visible symptom in that case.
    // avgBytesPerEvent is used to estimate bytes for growth-measured events.
    void measure(uint64_t avgBytesPerEvent);

    // Core delta logic, exposed as a test seam (measure() feeds its API
    // readings through here). Computes newest = oldest + count - 1, compares
    // with the last reading for this channel, and accumulates the delta:
    //   - first reading for a channel  -> baseline only, delta 0
    //   - newest advanced              -> delta = difference
    //   - newest unchanged or lower (log cleared/reset) -> delta 0, and the
    //     baseline re-arms at the lower position so a refill counts from
    //     there instead of skipping the entire refilled log
    // Returns the event delta for this reading.
    uint64_t applyReading(const std::wstring& channel,
                          uint64_t oldestRecordNumber,
                          uint64_t recordCount,
                          uint64_t avgBytesPerEvent);

    // Cumulative events generated on watched channels since agent start.
    uint64_t totalEvents() const { return m_totalEvents.load(); }
    // Cumulative ESTIMATED bytes for those events.
    uint64_t totalBytes() const { return m_totalBytes.load(); }

private:
    mutable std::mutex m_mutex;                     // guards channels + baselines
    std::vector<std::wstring> m_channels;
    std::map<std::wstring, uint64_t> m_lastNewest; // per-channel baseline
    std::atomic<uint64_t> m_totalEvents{0};
    std::atomic<uint64_t> m_totalBytes{0};
};

} // namespace elf
