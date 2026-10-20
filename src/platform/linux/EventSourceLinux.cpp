// systemd journal implementation of EventSource / GrowthMonitor.
//
// One reader thread owns an sd_journal handle, applies the subscription as
// journal matches (SYSLOG_IDENTIFIER=<channel> per channel, _TRANSPORT=audit
// for the audit channel, no match at all for "*"), and pushes every entry
// through the AuditJoiner into the buffer. The audit channel is read
// unfiltered at the journal level so a multi-record audit event stays
// together; the requested record types are applied after the join.
//
// Position: the cursor of the last entry read, persisted to
// <stateDir>/journal.cursor by savePosition(). A start without a cursor
// begins at the tail (future entries only), like the Windows subscription
// without a bookmark.
#include "EventSource.h"
#include "Console.h"
#include "JournalEvent.h"
#include "Platform.h"

#include <systemd/sd-journal.h>

#include <algorithm>
#include <atomic>
#include <condition_variable>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <mutex>
#include <set>
#include <sstream>
#include <thread>

namespace elf {

namespace {

constexpr const char* kAuditChannel = "audit";
constexpr const char* kAllChannels = "*";
constexpr const char* kCursorFile = "journal.cursor";

std::string errnoText(int negErrno) { return std::strerror(-negErrno); }

struct Subscription {
    bool all = false;
    std::vector<SourceFilter> filters;
    bool empty() const { return !all && filters.empty(); }
    bool operator==(const Subscription& o) const { return all == o.all && filters == o.filters; }
};

// Normalize what the runtime asks for: a "*" channel anywhere means the
// whole journal.
Subscription makeSubscription(bool all, const std::vector<SourceFilter>& filters) {
    Subscription s;
    s.all = all;
    for (const auto& f : filters) {
        if (f.channel == kAllChannels) { s.all = true; s.filters.clear(); return s; }
        if (f.channel.empty()) continue;
        s.filters.push_back(f);
    }
    return s;
}

// Add one match term per channel, OR'ed together.
bool applyMatches(sd_journal* j, const Subscription& sub, std::string& err) {
    sd_journal_flush_matches(j);
    if (sub.all) return true;
    bool first = true;
    for (const auto& f : sub.filters) {
        if (!first) {
            int r = sd_journal_add_disjunction(j);
            if (r < 0) { err = "add_disjunction: " + errnoText(r); return false; }
        }
        first = false;
        std::string m = (f.channel == kAuditChannel)
            ? std::string("_TRANSPORT=audit")
            : "SYSLOG_IDENTIFIER=" + f.channel;
        int r = sd_journal_add_match(j, m.c_str(), 0);
        if (r < 0) { err = m + ": " + errnoText(r); return false; }
    }
    return true;
}

// Position the journal so the next sd_journal_next() yields the first
// entry not yet delivered. Returns true when the current entry itself is
// new and must be delivered before calling next() (the saved cursor's
// entry is gone or no longer matches, so next() landed on the entry after
// it).
bool seekStart(sd_journal* j, const std::string& cursor, std::string& how) {
    if (!cursor.empty() && sd_journal_seek_cursor(j, cursor.c_str()) >= 0) {
        int r = sd_journal_next(j);
        if (r > 0) {
            if (sd_journal_test_cursor(j, cursor.c_str()) > 0) {
                how = "saved cursor";
                return false;    // positioned on the already-delivered entry
            }
            how = "first entry after the saved cursor";
            return true;
        }
        how = "saved cursor (at the tail)";
        return false;
    }
    sd_journal_seek_tail(j);
    sd_journal_previous(j);
    how = "tail";
    return false;
}

std::string describe(const Subscription& sub) {
    if (sub.all) return "all journal entries";
    std::string s;
    for (const auto& f : sub.filters) {
        if (!s.empty()) s += ", ";
        s += f.channel;
        if (f.channel == kAuditChannel && !f.eventIds.empty()) {
            s += " (" + std::to_string(f.eventIds.size()) + " record type(s))";
        }
    }
    return s;
}

class JournalEventSource : public EventSource {
public:
    JournalEventSource(EventBuffer& buffer, std::string stateDir)
        : m_buffer(buffer), m_stateDir(std::move(stateDir)) {
        if (!m_stateDir.empty() && m_stateDir.back() != '/') m_stateDir += '/';
        std::error_code ec;
        std::filesystem::create_directories(m_stateDir, ec);
        if (ec) {
            logError("[EventSource] Could not create state directory '" + m_stateDir +
                     "': " + ec.message());
        }
        loadCursor();
    }
    ~JournalEventSource() override { stop(); }

    int subscribeAll() override { return apply(makeSubscription(true, {})); }
    int subscribe(const std::vector<SourceFilter>& f) override {
        return apply(makeSubscription(false, f));
    }
    int resubscribe(const std::vector<SourceFilter>& f) override {
        Subscription s = makeSubscription(false, f);
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            if (s == m_sub) {
                logInfo("[EventSource] Subscription set unchanged (" +
                        std::to_string(s.filters.size()) + " channel(s)); skipping resubscribe.");
                return channelCountLocked();
            }
            if (s.empty() && m_sub.empty()) return 0;
        }
        return apply(std::move(s));
    }
    bool isSubscribedToAll() const override {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_sub.all;
    }
    std::vector<std::string> subscribedChannels() const override {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (m_sub.all) return {kAllChannels};
        std::vector<std::string> out;
        for (const auto& f : m_sub.filters) out.push_back(f.channel);
        return out;
    }
    void savePosition() override {
        std::string cursor;
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            if (!m_cursorDirty) return;
            cursor = m_cursor;
            m_cursorDirty = false;
        }
        std::string path = m_stateDir + kCursorFile;
        std::string tmp = path + ".tmp";
        {
            std::ofstream f(tmp, std::ios::out | std::ios::trunc);
            if (!f.is_open()) {
                logError("[EventSource] Could not open '" + tmp + "' for writing.");
                return;
            }
            f << cursor << '\n';
        }
        std::error_code ec;
        std::filesystem::rename(tmp, path, ec);
        if (ec) logError("[EventSource] Could not save the journal cursor: " + ec.message());
    }
    void stop() override {
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            m_stop = true;
        }
        m_cv.notify_all();
        if (m_thread.joinable()) m_thread.join();
    }
    uint64_t renderFailures() const override { return m_renderFailures.load(); }
    uint64_t subscribeErrors() const override { return m_subscribeErrors.load(); }

private:
    int channelCountLocked() const {
        return m_sub.all ? 1 : static_cast<int>(m_sub.filters.size());
    }

    int apply(Subscription s) {
        int count;
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            m_sub = std::move(s);
            ++m_generation;
            count = channelCountLocked();
            if (!m_thread.joinable() && !m_stop) {
                m_thread = std::thread([this] {
                    runGuarded("journal-reader", [this] { readerLoop(); });
                });
            }
        }
        m_cv.notify_all();
        return count;
    }

    void loadCursor() {
        std::ifstream f(m_stateDir + kCursorFile);
        if (!f.is_open()) return;
        std::getline(f, m_cursor);
        while (!m_cursor.empty() && (m_cursor.back() == '\r' || m_cursor.back() == ' ')) m_cursor.pop_back();
    }

    // Wait up to `secs` seconds for a stop or a subscription change.
    void pause(int secs, uint64_t applied) {
        std::unique_lock<std::mutex> lock(m_mutex);
        m_cv.wait_for(lock, std::chrono::seconds(secs),
                      [&] { return m_stop || m_generation != applied; });
    }

    // Record types requested on the audit channel (empty = every type).
    static std::set<int> auditTypesOf(const Subscription& sub) {
        std::set<int> out;
        for (const auto& f : sub.filters) {
            if (f.channel == kAuditChannel) out.insert(f.eventIds.begin(), f.eventIds.end());
        }
        return out;
    }

    void deliver(const JournalEntry& e, const std::vector<const JournalEntry*>& siblings) {
        if (!m_activeAll && e.isAudit() && !m_activeAuditTypes.empty()) {
            if (!m_activeAuditTypes.count(journalEventId(e))) return;
        }
        std::wstring xml = journalEntryToXml(e, siblings);
        if (xml.empty()) {
            uint64_t n = m_renderFailures.fetch_add(1) + 1;
            if (n == 1 || n % 1000 == 0) {
                logError("[EventSource] Could not render a journal entry; " +
                         std::to_string(n) + " failure(s) so far");
            }
            return;
        }
        m_buffer.push(xml);
    }

    void readerLoop() {
        sd_journal* j = nullptr;
        uint64_t applied = 0;
        bool deliverCurrent = false;
        AuditJoiner joiner([this](const JournalEntry& e, const std::vector<const JournalEntry*>& s) {
            deliver(e, s);
        });
        auto closeJournal = [&] {
            if (j) { sd_journal_close(j); j = nullptr; }
        };

        while (true) {
            Subscription sub;
            uint64_t gen;
            {
                std::unique_lock<std::mutex> lock(m_mutex);
                m_cv.wait(lock, [&] { return m_stop || !m_sub.empty() || m_generation != applied; });
                if (m_stop) break;
                sub = m_sub;
                gen = m_generation;
            }
            if (gen != applied || !j) {
                joiner.flushAll();
                closeJournal();
                applied = gen;
                if (sub.empty()) {
                    logInfo("[EventSource] Journal subscriptions cleared.");
                    continue;
                }
                int r = sd_journal_open(&j, SD_JOURNAL_LOCAL_ONLY);
                if (r < 0) {
                    j = nullptr;
                    m_subscribeErrors.fetch_add(1);
                    logError("[EventSource] sd_journal_open failed: " + errnoText(r) +
                             " (is the service account in the systemd-journal group?)");
                    pause(5, applied);
                    continue;
                }
                std::string err;
                if (!applyMatches(j, sub, err)) {
                    m_subscribeErrors.fetch_add(1);
                    logError("[EventSource] Journal match rejected: " + err);
                    closeJournal();
                    pause(5, applied);
                    continue;
                }
                std::string cursor;
                {
                    std::lock_guard<std::mutex> lock(m_mutex);
                    cursor = m_cursor;
                }
                std::string how;
                deliverCurrent = seekStart(j, cursor, how);
                m_activeAll = sub.all;
                m_activeAuditTypes = auditTypesOf(sub);
                logInfo("[EventSource] Reading the journal: " + describe(sub) + "; starting at " + how + ".");
            }

            int r = deliverCurrent ? 1 : sd_journal_next(j);
            deliverCurrent = false;
            if (r < 0) {
                m_subscribeErrors.fetch_add(1);
                logError("[EventSource] sd_journal_next failed: " + errnoText(r) + "; reopening.");
                closeJournal();
                pause(1, applied);
                continue;
            }
            if (r == 0) {
                joiner.flushIfIdle(std::chrono::milliseconds(1000));
                r = sd_journal_wait(j, 500000);
                if (r < 0) {
                    m_subscribeErrors.fetch_add(1);
                    logError("[EventSource] sd_journal_wait failed: " + errnoText(r) + "; reopening.");
                    closeJournal();
                    pause(1, applied);
                }
                continue;
            }
            JournalEntry e;
            if (!readJournalEntry(j, e)) {
                m_renderFailures.fetch_add(1);
                continue;
            }
            {
                std::lock_guard<std::mutex> lock(m_mutex);
                m_cursor = e.cursor;
                m_cursorDirty = true;
            }
            joiner.push(std::move(e));
        }
        joiner.flushAll();
        closeJournal();
    }

    EventBuffer& m_buffer;
    std::string m_stateDir;

    mutable std::mutex m_mutex;
    std::condition_variable m_cv;
    Subscription m_sub;
    uint64_t m_generation = 0;
    bool m_stop = false;
    std::string m_cursor;
    bool m_cursorDirty = false;
    std::thread m_thread;

    // Reader-thread state (no lock: written and read on that thread only).
    bool m_activeAll = false;
    std::set<int> m_activeAuditTypes;

    std::atomic<uint64_t> m_renderFailures{0};
    std::atomic<uint64_t> m_subscribeErrors{0};
};

// Counts the entries the journal gained on the watched channels since the
// last measurement, regardless of the record-type filter, by walking a
// second handle from its baseline. Entries are counted, not read.
class JournalGrowthMonitor : public GrowthMonitor {
public:
    ~JournalGrowthMonitor() override {
        std::lock_guard<std::mutex> lock(m_mutex);
        closeLocked();
    }
    void setChannels(const std::vector<std::string>& channels) override {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (channels == m_channels && (m_j || channels.empty())) return;
        m_channels = channels;
        closeLocked();
        if (channels.empty()) return;
        int r = sd_journal_open(&m_j, SD_JOURNAL_LOCAL_ONLY);
        if (r < 0) {
            m_j = nullptr;
            logError("[GrowthMonitor] sd_journal_open failed: " + errnoText(r));
            return;
        }
        Subscription sub;
        for (const auto& ch : channels) sub.filters.push_back({ch, {}});
        sub = makeSubscription(false, sub.filters);
        std::string err;
        if (!applyMatches(m_j, sub, err)) {
            logError("[GrowthMonitor] Journal match rejected: " + err);
            closeLocked();
            return;
        }
        // Baseline at the tail: only entries written from now on count.
        sd_journal_seek_tail(m_j);
        sd_journal_previous(m_j);
    }
    void measure(uint64_t avgBytesPerEvent) override {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (!m_j) return;
        uint64_t delta = 0;
        // Bounded so one measurement never stalls the poll thread.
        constexpr uint64_t kMaxPerMeasure = 1000000;
        int r;
        while (delta < kMaxPerMeasure && (r = sd_journal_next(m_j)) > 0) ++delta;
        if (delta > 0) {
            m_totalEvents.fetch_add(delta, std::memory_order_relaxed);
            m_totalBytes.fetch_add(delta * avgBytesPerEvent, std::memory_order_relaxed);
        }
    }
    uint64_t totalEvents() const override { return m_totalEvents.load(); }
    uint64_t totalBytes() const override { return m_totalBytes.load(); }
private:
    void closeLocked() {
        if (m_j) { sd_journal_close(m_j); m_j = nullptr; }
    }
    std::mutex m_mutex;
    std::vector<std::string> m_channels;
    sd_journal* m_j = nullptr;
    std::atomic<uint64_t> m_totalEvents{0};
    std::atomic<uint64_t> m_totalBytes{0};
};

} // namespace

std::unique_ptr<EventSource> makeEventSource(EventBuffer& buffer, const std::string& stateDir) {
    return std::make_unique<JournalEventSource>(buffer, stateDir);
}

std::unique_ptr<GrowthMonitor> makeGrowthMonitor() {
    return std::make_unique<JournalGrowthMonitor>();
}

} // namespace elf
