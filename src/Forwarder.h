#pragma once

#include <cstdint>

#include "Config.h"
#include "BufferedEvent.h"
#include "OutputFormat.h"
#include "SpoolQueue.h"
#include <string>
#include <vector>
#include <mutex>
#include <functional>
#include <chrono>
#include <deque>
#include <unordered_map>
#include <unordered_set>

namespace elf {

class AgentClient;

// The Forwarder executes rule actions against named destinations resolved
// from config.ini [destinations] (or pushed by the server). Three action
// types:
//
//   forward_event  - forward a single event (continuous, on every match).
//   alert          - forward a single event annotated as an alert.
//   forward_buffer - forward the current buffer (what this rule has not
//                    sent before).
//
// Destination URL scheme determines transport, and its ?format= option the
// document shape (see OutputFormat.h): raw Windows XML (default), ELF JSON,
// ECS, Splunk HEC, Graylog GELF, Microsoft Sentinel rows.
//   file://  - append one payload per line
//   http://  - POST via the destination spool (PostWorker)
//
// In addition to writing to the named destination, the Forwarder can mirror
// alerts and forwarded buffers to the management server via an AgentClient
// (POST /alerts, POST /logs). This is set via setAgentClient().
//
// Destination resolution happens under an internal mutex; the I/O does not,
// so a slow write never blocks a config update.
class Forwarder {
public:
    Forwarder();

    // Bind a config snapshot (used to resolve destinations). Call whenever
    // config is reloaded.
    void setConfig(const Config& cfg);

    // Optional: mirror alerts and forward_buffer batches to the management
    // server. Set to nullptr to disable server mirroring.
    void setAgentClient(AgentClient* client);

    // Start the disk-backed sender for http(s):// destinations. Until this
    // is called (unit tests), an HTTP destination gets ONE synchronous
    // attempt with no retry sleeps. With it, the write is spooled and sent
    // by a background thread with backoff; a dead SIEM never stalls the
    // rule-engine thread (inline retries on that thread would hold it for
    // longer than the 30 s buffer retention, so events would be evicted
    // unevaluated while it waited). Separate from the
    // server-mirror spool on purpose: a dead SIEM must not block alerts to
    // the management server, or vice versa.
    void initDestinationSpool(const std::string& dir, size_t maxBytes);

    // Forward a single event (forward_event action). `rule` identifies the
    // rule that matched; its id is threaded to the server mirror so every
    // forwarded log is associated with the rule that sent it.
    void forwardEvent(const BufferedEvent& evt, const std::string& destination,
                      const RuleMeta& rule);

    // Forward a single event annotated as an alert (alert action).
    // `evidenceEvents` carries the correlation evidence so the alert
    // payload includes the full picture, not just the trigger: the events
    // that formed a sequence (attack chain) or the events that filled a
    // threshold window. `evidenceIsSequence` selects the payload key,
    // `sequence_events` (chain, labeled Stage N) vs `window_events`
    // (threshold window, labeled Event N), so the server UI can label the
    // items correctly. Empty for simple rules.
    // `alsoMatched` lists the ids of lower-severity Simple rules that also
    // matched this event but were suppressed by severity selection; written
    // as an `also_matched:` header line and sent to the server so no
    // detection is invisible.
    // `alertId` identifies this rule fire; it is written on the alert and on
    // the forward_buffer batch of the same fire so the two can be joined.
    void forwardAlert(const BufferedEvent& evt, const std::string& destination,
                      const RuleMeta& rule, const std::string& message,
                      const std::vector<BufferedEvent>& evidenceEvents = {},
                      bool evidenceIsSequence = false,
                      const std::vector<std::string>& alsoMatched = {},
                      const std::string& alertId = std::string());

    // Forward a buffer snapshot (forward_buffer action). The triggering
    // event and action message are included so the server mirror can
    // produce a single alert with details (not one alert per buffer event).
    // `sequenceEvents` carries the correlation evidence (see forwardAlert).
    // `skipAlertNotification`: when true, the server mirror skips the
    // POST /alerts "forward_buffer fired" notification because the rule's
    // own `alert` action already sent an alert for this event (prevents a
    // duplicate alert on the server). Only the POST /logs batch is sent.
    void forwardBuffer(const BufferedEvent& trigger, const std::string& message,
                       const std::vector<BufferedEvent>& buffer,
                       const std::string& destination,
                       const RuleMeta& rule,
                       const std::vector<BufferedEvent>& sequenceEvents = {},
                       bool skipAlertNotification = false,
                       bool evidenceIsSequence = false,
                       const std::vector<std::string>& alsoMatched = {},
                       const std::string& alertId = std::string());

private:
    // Resolve a destination name to a copy of the Destination struct.
    // Returns true on success. Caller must hold m_mutex (reads m_config).
    bool resolveDestination(const std::string& name, Destination& out);

    // Write one formatted payload to a resolved destination (file:// append
    // or http:// POST). Does NOT take m_mutex; the caller resolves the
    // destination under the lock, releases it, then calls this so a slow
    // I/O doesn't block setConfig.
    bool writeToDestination(const Destination& d, const FormattedPayload& payload);

    // Build the per-action formatting context (agent id, rule, action).
    FormatContext makeContext(const Destination& d, const RuleMeta& rule,
                              const char* action) const;

    // An event reaches a given destination (and the server mirror) at most
    // once, however many rules ask for it: several forward_buffer rules on
    // one destination snapshot the same buffer, and a forward_event rule
    // plus a forward_buffer rule both carry the trigger. Each scope (a
    // destination name, or the mirror) remembers the (channel, record id)
    // keys it has sent, bounded by a TTL that outlives the buffer retention.
    // Events with no record id (key 0) always pass.
    class SentOnce {
    public:
        // Drop the events already sent to `scope`; record the rest.
        std::vector<BufferedEvent> filter(const std::string& scope,
                                          const std::vector<BufferedEvent>& events);
        bool first(const std::string& scope, const BufferedEvent& evt);
        void setTtl(std::chrono::seconds ttl) { m_ttl = ttl; }
    private:
        struct Scope {
            std::unordered_set<uint64_t> seen;
            std::deque<std::pair<std::chrono::steady_clock::time_point, uint64_t>> order;
        };
        void prune(Scope& s, std::chrono::steady_clock::time_point now);
        std::mutex m_mutex;
        std::unordered_map<std::string, Scope> m_scopes;
        std::chrono::seconds m_ttl{600};
    };
    static constexpr const char* kMirrorScope = "\x01server";

    std::mutex m_mutex;
    Config m_config;
    AgentClient* m_agentClient = nullptr;
    PostWorker m_destWorker;   // http(s):// destinations; no enrollment token
    bool m_destSpoolStarted = false;
    SentOnce m_sent;
};

} // namespace elf
