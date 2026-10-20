#include "LogGrowthMonitor.h"
#include <algorithm>

#pragma comment(lib, "wevtapi.lib")

namespace elf {

void LogGrowthMonitor::setChannels(const std::vector<std::wstring>& channels) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_channels = channels;
    // Drop baselines for channels we no longer watch, so a later re-add
    // re-baselines instead of counting events generated while the channel
    // was unwatched (those events were never candidates for forwarding).
    for (auto it = m_lastNewest.begin(); it != m_lastNewest.end();) {
        if (std::find(channels.begin(), channels.end(), it->first) ==
            channels.end()) {
            it = m_lastNewest.erase(it);
        } else {
            ++it;
        }
    }
}

size_t LogGrowthMonitor::channelCount() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_channels.size();
}

void LogGrowthMonitor::measure(uint64_t avgBytesPerEvent) {
    // Copy the channel list under the lock, then do the API calls without
    // holding it (EvtOpenLog/EvtGetLogInfo are fast metadata reads, but
    // there is no reason to block a concurrent setChannels on them).
    std::vector<std::wstring> channels;
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        channels = m_channels;
    }
    for (const auto& channel : channels) {
        EVT_HANDLE hLog = EvtOpenLog(nullptr, channel.c_str(),
                                      EvtOpenChannelPath);
        if (!hLog) {
            // Channel missing or unreadable (removed, access denied,
            // analytic/debug channel not enabled). Skip silently; the
            // subscription failure logged by EventCollector is the
            // visible symptom; logging here every poll would spam.
            continue;
        }
        uint64_t oldest = 0, count = 0;
        EVT_VARIANT v = {};
        DWORD used = 0;
        if (EvtGetLogInfo(hLog, EvtLogOldestRecordNumber, sizeof(v), &v,
                          &used) &&
            v.Type == EvtVarTypeUInt64) {
            oldest = v.UInt64Val;
        }
        v = EVT_VARIANT();
        used = 0;
        if (EvtGetLogInfo(hLog, EvtLogNumberOfLogRecords, sizeof(v), &v,
                          &used) &&
            v.Type == EvtVarTypeUInt64) {
            count = v.UInt64Val;
        }
        EvtClose(hLog);
        applyReading(channel, oldest, count, avgBytesPerEvent);
    }
}

uint64_t LogGrowthMonitor::applyReading(const std::wstring& channel,
                                       uint64_t oldestRecordNumber,
                                       uint64_t recordCount,
                                       uint64_t avgBytesPerEvent) {
    // newest = oldest + count - 1 is the record number of the most recent
    // event in the log. It is monotonic across circular-log wraps (where
    // the COUNT plateaus at capacity but OLDEST keeps advancing), which is
    // why we track it instead of the raw record count. An empty log
    // (count 0) has no newest event; use 0.
    uint64_t newest =
        recordCount > 0 ? oldestRecordNumber + recordCount - 1 : 0;
    std::lock_guard<std::mutex> lock(m_mutex);
    uint64_t delta = 0;
    auto it = m_lastNewest.find(channel);
    if (it != m_lastNewest.end() && newest > it->second) {
        delta = newest - it->second;
    }
    // Always re-arm the baseline. When the log is cleared/reset (newest
    // drops below the previous baseline) this accepts the lower position
    // so the next refill counts from there instead of skipping the whole
    // refilled log.
    m_lastNewest[channel] = newest;
    if (delta > 0) {
        m_totalEvents.fetch_add(delta, std::memory_order_relaxed);
        m_totalBytes.fetch_add(delta * avgBytesPerEvent,
                               std::memory_order_relaxed);
    }
    return delta;
}

} // namespace elf
