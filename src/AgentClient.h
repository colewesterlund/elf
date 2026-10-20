#pragma once

#include <cstdint>

#include "Config.h"
#include "Rule.h"
#include "BufferedEvent.h"
#include "SpoolQueue.h"
#include <string>
#include <vector>
#include <functional>
#include <atomic>
#include <mutex>
#include <condition_variable>
#include <thread>
#include <deque>
#include <set>
#include <unordered_map>
#include <chrono>

namespace elf {

// The AgentClient is the agent's link to the management server. It:
//   - Detects the local hostname (so the server knows which device this is).
//   - Registers with the server on startup (auto-registered on first poll).
//   - Periodically polls GET /config/{agent_id} for the effective config +
//     ruleset, applies the config locally, and writes the ruleset to the
//     local rules/ directory so the RuleEngine hot-reloads them.
//   - Pushes alerts (POST /alerts) and forwarded log batches (POST /logs) to
//     the server when rules fire.
//
// The server is the source of truth for rules and per-group settings. The
// agent's local config.ini provides the bootstrap (server URL, agent_id,
// local file destinations); everything else is pulled from the server and
// applied at runtime.
//
// Threading: poll() runs on its own worker thread; reportAlert/reportLogs
// are called from the RuleEngine thread. Server-mirror POSTs are queued
// and sent on a dedicated background thread so a slow/downed server never
// blocks the rule engine (which would freeze the agent). An internal mutex
// guards the queue; a condition variable wakes the worker when work arrives.
class AgentClient {
public:
    // Callback used to apply a server-pushed config (update ConfigStore +
    // Forwarder, adjust retention, etc.). Wired by main.cpp.
    using ApplyConfigFn = std::function<void(const Config& cfg)>;

    // Callback used to trigger a rule reload after rules are written to disk.
    using ReloadRulesFn = std::function<void()>;

    // Callback used to re-derive the XPath subscription filter and
    // re-subscribe the EventCollector after a ruleset change. Wired by
    // main.cpp so the collector's XPath filters track the new rules'
    // EventIDs. Called after m_reloadRules() in applyServerConfig() when
    // the ruleset actually changed.
    using ResubscribeFn = std::function<void()>;

    AgentClient();
    ~AgentClient();

    // Initialize from the bootstrap config. Reads server URL, agent_id, and
    // the local rules directory. Detects the hostname. Does NOT contact the
    // server yet.
    void init(const Config& bootstrap);

    // Set up the disk-backed spool directory for pending POSTs and start the
    // background sender. Call once at startup, after init() (the sender
    // needs the enrollment token).
    //   dir:      e.g. %ProgramData%\ELFAgent\spool\
    //   maxBytes: max total spool size (oldest evicted when exceeded)
    // Loads any existing spool files from a previous run so pending POSTs
    // are re-sent after a restart. Until this is called, report* calls are
    // dropped (no server mirror); that is the unit-test configuration.
    void initSpool(const std::string& dir, size_t maxBytes);

    // Pending server-mirror POSTs (spooled, not yet acknowledged).
    size_t pendingPosts() const { return m_poster.pending(); }

    // Ship the accumulated forward_event batch now (see m_batchEvents).
    // Called on every poll and periodically from the status thread so a
    // crash loses at most a few seconds of forwarded events.
    void flushPendingLogs();

    // Upper bounds on what one POST carries. The server rejects /logs
    // batches above 10,000 events (LogReport.events max_length); a rejected
    // batch can never be delivered, so forward_buffer dumps are split into
    // chunks well under that. Alert evidence (window/sequence events) is
    // capped so a threshold window of thousands of events does not turn
    // every alert into a multi-MB payload: the last N are kept and the
    // count of omitted events is reported in the payload.
    static constexpr size_t MAX_LOGS_POST_EVENTS = 2000;
    static constexpr size_t MAX_LOGS_POST_BYTES  = 4 * 1024 * 1024;  // 4 MB
    static constexpr size_t MAX_ALERT_EVIDENCE_EVENTS = 500;

    // Set callbacks for applying server-pushed config and triggering reloads.
    void setApplyConfig(ApplyConfigFn fn) { m_applyConfig = std::move(fn); }
    void setReloadRules(ReloadRulesFn fn) { m_reloadRules = std::move(fn); }
    void setResubscribe(ResubscribeFn fn) { m_resubscribe = std::move(fn); }

    // One poll cycle: GET /config/{agent_id}, apply config, write rules,
    // trigger reload. Returns true on success. Safe to call from a worker
    // thread on a timer. The eventsCreated/bytesCreated parameters are the
    // cumulative host-generated event/byte counts (events generated on the
    // watched channels, measured by the LogGrowthMonitor; bytes estimated
    // from the average rendered size of delivered events), reported to the
    // server so it can compute the savings ratio.
    bool poll(uint64_t eventsCreated = 0, uint64_t bytesCreated = 0);

    // Report an alert to the server (POST /alerts). Called by the RuleEngine
    // when an alert action fires. `level` is the Sigma severity (critical,
    // high, medium, low, informational) so the server can sort/color alerts
    // by severity and the analyst sees the most severe alerts first.
    // `evidenceEvents` carries the correlation evidence so the alert payload
    // includes the full picture, not just the trigger: the events that
    // formed a sequence (attack chain) or the events that filled a threshold
    // window. `evidenceIsSequence` selects the payload key,
    // `sequence_events` (chain) vs `window_events` (threshold window), so
    // the server UI can label the items correctly (Stage N vs Event N).
    // `alsoMatched` lists the ids of lower-severity Simple rules that also
    // matched this event but were suppressed by severity selection, so
    // nothing a rule detected is invisible to the analyst.
    void reportAlert(const std::string& ruleId, const std::string& message,
                     const BufferedEvent& evt, const std::string& level = "",
                     const std::vector<BufferedEvent>& evidenceEvents = {},
                     bool evidenceIsSequence = false,
                     const std::vector<std::string>& alsoMatched = {},
                     const std::string& alertId = "");

    // Report a single forwarded event to the server (POST /logs). Called by
    // the Forwarder when a forward_event action fires. Sends a one-event log
    // batch so the event lands in the logs view as a normal forwarded log,
    // NOT as an alert. forward_event is continuous forwarding and must not
    // generate alerts. `ruleId` is the rule that matched, so every forwarded
    // log is associated with the rule that sent it.
    void reportEvent(const BufferedEvent& evt, const std::string& ruleId);

    // Report a forward_buffer fire to the server. Sends TWO requests:
    //   1. POST /alerts: a single alert with the trigger event and details
    //      (rule_id, message) so the forward_buffer shows up once in the
    //      alerts view. For sequence rules, `sequenceEvents` carries ALL the
    //      events that formed the sequence (not just the trigger) so the
    //      analyst can see the full attack chain in the alert payload.
    //   2. POST /logs:   a single batch containing every event in the buffer
    //      (event_count + events[]), so the buffer contents land in the logs
    //      view as normal forwarded logs, not as hundreds of individual
    //      alerts.
    // The forwarded counter is deduplicated by EventRecordID so an event
    // forwarded via forward_event AND forward_buffer is only counted once
    // (prevents the >100% forwarded metric).
    // `skipAlertNotification`: when true, the POST /alerts notification
    // (request 1) is skipped because the rule's own `alert` action already
    // sent an alert for this event. Only the POST /logs batch (request 2) is
    // sent. This prevents a duplicate alert (same EventRecordID, ~20ms apart)
    // on the server when a rule has BOTH `alert` AND `forward_buffer` actions.
    // `skipLogsBatch`: when true, the POST /logs batch (request 2) is
    // skipped because the group's mirror_logs toggle is OFF (the server
    // pushes it via GET /config). The alert notification (request 1) is
    // STILL sent; alerts are the detection record and always mirror.
    // `evidenceIsSequence`: when the evidence events are a sequence chain
    // (vs a threshold window), the alert payload uses the `sequence_events`
    // key so the UI labels items "Stage N"; otherwise `window_events`
    // (labeled "Event N").
    void reportLogs(const std::string& ruleId, const std::string& message,
                    const BufferedEvent& trigger,
                    const std::vector<BufferedEvent>& buffer,
                    const std::string& level = "",
                    const std::vector<BufferedEvent>& sequenceEvents = {},
                    bool skipAlertNotification = false,
                    bool skipLogsBatch = false,
                    bool evidenceIsSequence = false,
                    const std::vector<std::string>& alsoMatched = {},
                    const std::string& alertId = "");

    // --- On-demand log collection (collect logs command) ---
    // Ship one streamed batch of collected events to the server. Called from
    // the collect worker thread as it pages through the historical query.
    void reportCollectBatch(long commandId, int batchIndex,
                            const std::vector<std::string>& eventsUtf8);
    // Ship the final completion marker for a collect command (done or failed).
    void reportCollectDone(long commandId, const std::string& status,
                           size_t eventsCollected, int batches,
                           const std::string& error);

    // Accessors.
    const std::string& agentId() const { return m_agentId; }
    const std::string& hostname() const { return m_hostname; }
    const std::string& ipAddress() const { return m_ipAddress; }
    const std::string& osName() const { return m_osName; }
    const std::string& serverUrl() const { return m_serverUrl; }

    // Cumulative counters for events/bytes forwarded to the server since
    // agent start. Reported on each poll so the server can compute the
    // savings ratio (1 - forwarded / created).
    uint64_t eventsForwarded() const { return m_eventsForwarded.load(); }
    uint64_t bytesForwarded() const { return m_bytesForwarded.load(); }

    // Whether the server has seen this agent before (reboot/reinstall vs.
    // first install). Set from the `known_agent` flag in the /config
    // response: true when first_seen < last_seen in the server's agents
    // table. The agent uses this to distinguish a fresh install (no prior
    // subscription → wait for rules before collecting, no backlog to
    // forward) from a reboot/reinstall of an already-known device (resume
    // from saved bookmarks). False until the first successful poll.
    bool knownAgent() const { return m_knownAgent.load(); }

    // Parse the /config response JSON and apply it: update ConfigStore with
    // server-pushed retention/destinations/mirror_logs, and write rules to
    // disk. Public so the unit tests can feed a canned /config response
    // (e.g. {"mirror_logs": false, "rules": [], "lists": []}) and verify
    // the parsed result without a live server.
    //
    // Ruleset fingerprint protocol: the response carries `ruleset_hash`
    // (content hash of the group's enabled rules + lists). The agent sends
    // the hash it last applied as `?known_hash=` on the next poll; when the
    // server sees a match it omits `rules`/`lists` and sets
    // `ruleset_unchanged: true`, and the agent skips the disk compare,
    // reload and resubscribe entirely. An ABSENT `rules` key is therefore
    // "no change", never "delete every rule" (an empty ARRAY still means
    // "no rules"). A server that sends no hash gets a full sync every poll.
    bool applyServerConfig(const std::string& json);

    // Ruleset hash the agent last applied ("" until the first full sync).
    const std::string& appliedRulesetHash() const { return m_appliedRulesetHash; }

    // Force the next poll to request the full ruleset even if the server's
    // hash still matches; called when something other than the server
    // changed the on-disk rules (a hand edit picked up by the disk watcher)
    // so the server's copy wins again.
    void invalidateRulesetHash() { m_forceFullSync.store(true); }

private:

    // Write the ruleset received from the server to the local rules/
    // directory. Each rule's yaml_body is written to <rulesDir>/<rule_id>.yaml.
    // Existing files not in the server set are removed so the local dir stays
    // in sync with the server (server is source of truth).
    // `changed` is set to true if any file was written or removed (i.e. the
    // on-disk ruleset actually changed). Callers can use it to skip an
    // expensive reload when nothing changed.
    bool writeRulesToDisk(const std::vector<std::pair<std::string, std::string>>& rules,
                          bool& changed);

    // Write the reusable lists received from the server to the local lists/
    // directory. Each list's content is written to <listsDir>/<name>.txt.
    // Existing files not in the server set are removed so the local dir stays
    // in sync with the server (server is source of truth).
    // `changed` is set to true if any file was written or removed.
    bool writeListsToDisk(const std::vector<std::pair<std::string, std::string>>& lists,
                          bool& changed);

    // Handle on-demand commands received in the /config response. For each
    // collect_logs command, spawn a detached worker thread that runs
    // EventQueryCollector and streams the events back. Guards against
    // duplicate execution with m_inFlightCommands. `commandsJson` is the
    // serialized JSON array from the config response.
    void handleCommands(const std::string& commandsJson);
    // Run a single collect_logs command to completion on a detached thread.
    void runCollectCommand(long commandId, const std::string& startTimeIsoUtc);

    std::string m_serverUrl;       // e.g. http://elf-server:8000
    std::string m_agentId;          // from config.ini [server] agent_id
    std::string m_authToken;        // from config.ini [server] auth_token (enrollment token)
    std::string m_hostname;         // detected device name
    std::string m_ipAddress;       // detected primary IPv4 address
    std::string m_osName;           // detected OS product name + build
    std::string m_rulesDir;         // local rules directory
    std::string m_listsDir;         // local lists directory
    std::string m_appliedRulesetHash;  // poll thread only
    std::atomic<bool> m_forceFullSync{false};

    ApplyConfigFn   m_applyConfig;
    ReloadRulesFn   m_reloadRules;
    ResubscribeFn   m_resubscribe;

    // --- Async server-mirror queue (disk-backed) ---
    // The rule engine calls reportAlert/reportEvent/reportLogs synchronously,
    // but the actual HTTP POST is spooled to disk and sent by PostWorker's
    // background thread. This guarantees the rule engine never blocks on
    // network I/O (a slow/downed server would otherwise freeze the agent for
    // up to the POST timeout per request). The disk backing means pending
    // POSTs survive an agent restart or crash. PostWorker owns the retry
    // policy (drop permanent 4xx rejections, back off on transport errors).
    PostWorker       m_poster;

    void enqueuePost(std::string url, std::string body);

    // --- Pending log batch (forward_event batching) ---
    // forward_event actions can match thousands of events per pass. Sending
    // one POST /logs per event opens a new WinHTTP session (socket) each time
    // and floods the server. Instead, accumulate forwarded events here and
    // flush them as a single batch on each poll cycle (at the poll interval)
    // or when the batch reaches a size threshold. Each batch entry carries
    // the rule_id that forwarded it so every forwarded log is associated
    // with the rule that sent it.
    struct BatchEntry {
        std::string ruleId;
        std::string xmlUtf8;
    };
    std::mutex m_batchMutex;
    std::vector<BatchEntry> m_batchEvents;
    size_t m_batchBytes = 0;
    static constexpr size_t MAX_BATCH_EVENTS = 200;
    static constexpr size_t MAX_BATCH_BYTES  = 1024 * 1024;  // 1 MB

    // --- Forwarded-metric deduplication ---
    // An event forwarded via forward_event AND forward_buffer must only count
    // once in m_eventsForwarded/m_bytesForwarded. We track the EventRecordIDs
    // already counted so forward_buffer can skip events already counted by
    // forward_event. Bounded by a TTL (pruned in countForwarded) so a
    // long-running agent doesn't grow the set unbounded.
    std::mutex m_fwdDedupMutex;
    std::unordered_map<uint64_t, std::chrono::system_clock::time_point> m_forwardedRecordIds;
    // Count an event as forwarded if its EventRecordID hasn't been counted
    // yet. Returns the number of newly-counted events (0 if already counted).
    size_t countForwarded(const std::vector<BufferedEvent>& events);
    // Prune entries older than 1 hour to bound memory.
    void pruneForwardedDedup();

    std::atomic<bool> m_lastPollOk{false};

    // --- On-demand collect-logs commands ---
    // Tracks command IDs currently being executed by a worker thread so a
    // retry poll (before the server marks the command sent) does not start a
    // second pull for the same command.
    std::mutex m_cmdMutex;
    std::set<long> m_inFlightCommands;

    // Cumulative counters for events/bytes shipped to the server.
    std::atomic<uint64_t> m_eventsForwarded{0};
    std::atomic<uint64_t> m_bytesForwarded{0};

    // Server-reported "known agent" flag (reboot/reinstall vs first install).
    std::atomic<bool> m_knownAgent{false};
};

// Build the JSON body for POST /alerts. Shared by reportAlert and the
// forward_buffer notification in reportLogs so both produce the same shape:
//   rule_id, message, level, event_xml (the trigger),
//   sequence_events[] or window_events[] (correlation evidence, capped at
//   AgentClient::MAX_ALERT_EVIDENCE_EVENTS; the LAST N are kept, and
//   <key>_truncated carries the number omitted),
//   also_matched[] (ids of lower-severity Simple rules that matched the
//   same event but were suppressed by severity selection; omitted when
//   empty).
// A free function so unit tests can check the payload without a server.
std::string buildAlertPayload(const std::string& ruleId,
                              const std::string& message,
                              const BufferedEvent& trigger,
                              const std::string& level,
                              const std::vector<BufferedEvent>& evidenceEvents,
                              bool evidenceIsSequence,
                              const std::vector<std::string>& alsoMatched = {},
                              const std::string& alertId = "");

} // namespace elf
