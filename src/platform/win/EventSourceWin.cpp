// Windows Event Log implementation of EventSource / GrowthMonitor: the
// EventCollector (EvtSubscribe with XPath pre-filters), the BookmarkStore
// (per-channel resume positions) and the LogGrowthMonitor (record-number
// growth for the savings metric), behind the platform-neutral interfaces
// the agent runtime drives.
#include "EventSource.h"
#include "BookmarkStore.h"
#include "EventCollector.h"
#include "LogGrowthMonitor.h"
#include "Platform.h"

namespace elf {

namespace {

// EventCollector works in wide channel names and XPath queries; the
// runtime hands over UTF-8 names and event-id lists.
std::vector<ChannelQuery> toQueries(const std::vector<SourceFilter>& filters) {
    std::vector<ChannelQuery> out;
    out.reserve(filters.size());
    for (const auto& f : filters) {
        // "*" is the Linux "whole journal" channel (Sigma `service:
        // syslog`); there is no Windows channel of that name.
        if (f.channel == "*") continue;
        ChannelQuery cq;
        // Canonical case is preserved: EvtSubscribe rejects lowercase paths.
        cq.channel = utf8ToWide(f.channel);
        // Beyond ~20 ids the flat predicate is rejected by Windows, so the
        // channel-aware builder switches to a structured <QueryList>.
        cq.query = f.eventIds.empty() ? std::wstring(L"*")
                                      : buildEventIdXPath(cq.channel, f.eventIds);
        out.push_back(std::move(cq));
    }
    return out;
}

std::vector<std::string> toUtf8(const std::vector<std::wstring>& in) {
    std::vector<std::string> out;
    out.reserve(in.size());
    for (const auto& w : in) out.push_back(wideToUtf8(w));
    return out;
}

std::vector<std::wstring> toWide(const std::vector<std::string>& in) {
    std::vector<std::wstring> out;
    out.reserve(in.size());
    for (const auto& s : in) out.push_back(utf8ToWide(s));
    return out;
}

class WinEventSource : public EventSource {
public:
    WinEventSource(EventBuffer& buffer, const std::string& stateDir)
        : m_collector(buffer) {
        m_bookmarks.setDirectory(stateDir);
        m_collector.setBookmarkStore(&m_bookmarks);
    }
    int subscribeAll() override { return m_collector.subscribeAll(); }
    int subscribe(const std::vector<SourceFilter>& f) override {
        return m_collector.subscribeWithQueries(toQueries(f));
    }
    int resubscribe(const std::vector<SourceFilter>& f) override {
        return m_collector.resubscribe(toQueries(f));
    }
    bool isSubscribedToAll() const override { return m_collector.isSubscribedToAll(); }
    std::vector<std::string> subscribedChannels() const override {
        return toUtf8(m_collector.subscribedChannels());
    }
    void savePosition() override { m_collector.saveBookmarks(); }
    void stop() override { m_collector.stop(); }
    uint64_t renderFailures() const override { return m_collector.renderFailures(); }
    uint64_t subscribeErrors() const override { return m_collector.subscribeErrors(); }
private:
    // Declaration order matters: the collector holds a pointer to the store.
    BookmarkStore m_bookmarks;
    EventCollector m_collector;
};

class WinGrowthMonitor : public GrowthMonitor {
public:
    void setChannels(const std::vector<std::string>& channels) override {
        m_monitor.setChannels(toWide(channels));
    }
    void measure(uint64_t avgBytesPerEvent) override { m_monitor.measure(avgBytesPerEvent); }
    uint64_t totalEvents() const override { return m_monitor.totalEvents(); }
    uint64_t totalBytes() const override { return m_monitor.totalBytes(); }
private:
    LogGrowthMonitor m_monitor;
};

} // namespace

std::unique_ptr<EventSource> makeEventSource(EventBuffer& buffer, const std::string& stateDir) {
    return std::make_unique<WinEventSource>(buffer, stateDir);
}

std::unique_ptr<GrowthMonitor> makeGrowthMonitor() {
    return std::make_unique<WinGrowthMonitor>();
}

} // namespace elf
