#include "Forwarder.h"
#include "HttpClient.h"
#include "AgentClient.h"
#include "Console.h"
#include "FieldResolver.h"   // eventDedupKey
#include "Platform.h"        // platformGetEnv
#include <fstream>
#include <filesystem>

namespace elf {

// --- Destination resolution + transport ---

bool Forwarder::resolveDestination(const std::string& name, Destination& out) {
    const Destination* d = m_config.resolveDestination(name);
    if (!d) {
        logError("[Forwarder] Unknown destination: " + name);
        return false;
    }
    out = *d;
    return true;
}

FormatContext Forwarder::makeContext(const Destination& d, const RuleMeta& rule,
                                     const char* action) const {
    FormatContext ctx;
    ctx.dest = &d;
    ctx.rule = &rule;
    ctx.agentId = m_config.server.agent_id;
    ctx.action = action;
    return ctx;
}

bool Forwarder::writeToDestination(const Destination& d, const FormattedPayload& payload) {
    if (d.scheme == "file") {
        // Ensure the parent directory exists so the agent is self-sufficient.
        std::filesystem::path p(d.path);
        if (p.has_parent_path()) {
            std::error_code ec;
            std::filesystem::create_directories(p.parent_path(), ec);
        }
        // Append one line to the file.
        std::ofstream f(d.path, std::ios::app);
        if (!f.is_open()) {
            logError("[Forwarder] Cannot open file: " + d.path);
            return false;
        }
        f << payload.body << "\n";
        return true;
    }
    if (d.scheme == "http" || d.scheme == "https") {
        // Spooled when the destination spool is running: the POST goes to
        // disk and a background thread sends it with backoff, so the
        // rule-engine thread never waits on a SIEM. Without a spool (unit
        // tests / dev) make exactly one attempt and never sleep here; an
        // inline retry loop would hold the engine thread for longer than
        // the buffer retention.
        if (m_destSpoolStarted) {
            if (d.opts.format == "sentinel") {
                // OAuth2 client credentials, resolved by the worker at
                // send time (tokens expire; they never go into the spool).
                OAuthSpec spec;
                spec.tokenUrl = "https://login.microsoftonline.com/" + d.opts.tenant +
                                "/oauth2/v2.0/token";
                // Test hook: tools/siem-sink.py --mode sentinel serves a fake
                // token endpoint; ELF_OAUTH_TOKEN_URL points the agent at it.
                std::string override = platformGetEnv("ELF_OAUTH_TOKEN_URL");
                if (!override.empty()) spec.tokenUrl = override;
                spec.clientId = d.opts.client;
                spec.clientSecret = d.opts.secret;
                spec.scope = "https://monitor.azure.com/.default";
                std::string prefix = d.path.substr(0, d.path.find('?'));
                m_destWorker.registerOAuth(prefix, std::move(spec));
            }
            return m_destWorker.enqueue(
                d.path, payload.body,
                PostWorker::makeHeaderBlock(payload.contentType, payload.headers,
                                            d.opts.insecure));
        }
        HttpRequestOptions opts;
        opts.contentType = payload.contentType;
        opts.headers = payload.headers;
        opts.insecure = d.opts.insecure;
        std::string resp, err;
        if (HttpClient::post(d.path, payload.body, opts, resp, err,
                             PostWorker::POST_TIMEOUT_MS)) {
            return true;
        }
        logError("[Forwarder] HTTP POST to " + d.path + " failed: " + err +
                 " (no destination spool configured; event dropped)");
        return false;
    }
    logError("[Forwarder] Unsupported scheme: " + d.scheme);
    return false;
}

// --- Public API ---

Forwarder::Forwarder() {}

void Forwarder::setConfig(const Config& cfg) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_config = cfg;
    // An event can be re-requested for as long as it sits in the buffer;
    // remember it well past the retention window.
    m_sent.setTtl(std::chrono::seconds((std::max)(600, cfg.retention_seconds * 4)));
}

void Forwarder::setAgentClient(AgentClient* client) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_agentClient = client;
}

void Forwarder::initDestinationSpool(const std::string& dir, size_t maxBytes) {
    m_destWorker.start(dir, maxBytes);
    m_destSpoolStarted = true;
}

// --- SentOnce ---

void Forwarder::SentOnce::prune(Scope& s, std::chrono::steady_clock::time_point now) {
    while (!s.order.empty() && now - s.order.front().first > m_ttl) {
        s.seen.erase(s.order.front().second);
        s.order.pop_front();
    }
}

bool Forwarder::SentOnce::first(const std::string& scope, const BufferedEvent& evt) {
    uint64_t key = eventDedupKey(evt);
    if (key == 0) return true;
    std::lock_guard<std::mutex> lock(m_mutex);
    Scope& s = m_scopes[scope];
    auto now = std::chrono::steady_clock::now();
    prune(s, now);
    if (!s.seen.insert(key).second) return false;
    s.order.emplace_back(now, key);
    return true;
}

std::vector<BufferedEvent> Forwarder::SentOnce::filter(const std::string& scope,
                                                       const std::vector<BufferedEvent>& events) {
    std::vector<BufferedEvent> out;
    if (events.empty()) return out;
    std::lock_guard<std::mutex> lock(m_mutex);
    Scope& s = m_scopes[scope];
    auto now = std::chrono::steady_clock::now();
    prune(s, now);
    out.reserve(events.size());
    for (const auto& evt : events) {
        uint64_t key = eventDedupKey(evt);
        if (key != 0) {
            if (!s.seen.insert(key).second) continue;
            s.order.emplace_back(now, key);
        }
        out.push_back(evt);
    }
    return out;
}

void Forwarder::forwardEvent(const BufferedEvent& evt, const std::string& destination,
                             const RuleMeta& rule) {
    // Resolve the destination + read the mirror flag under the lock, then
    // release it before I/O so a slow file write or HTTP POST doesn't block
    // setConfig.
    Destination dest;
    bool ok = false;
    bool mirror = true;
    FormatContext ctx;
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        ok = resolveDestination(destination, dest);
        mirror = m_config.mirror_logs;
        ctx = makeContext(dest, rule, "forward_event");
    }
    // Once per destination: a second rule asking for the same event (or a
    // forward_buffer that already carried it) does not write it again.
    if (ok && m_sent.first(dest.name, evt)) {
        for (const auto& p : formatEvents({evt}, ctx)) writeToDestination(dest, p);
    }
    // Mirror the event to the management server as a normal forwarded log
    // (POST /logs), NOT as an alert. forward_event is continuous forwarding
    // and must not generate alerts. The rule_id is passed so every forwarded
    // log is associated with the rule that sent it.
    // Gated on the per-group mirror_logs toggle (pushed via GET /config):
    // when off, log batches stop but alerts (forwardAlert) still mirror.
    if (m_agentClient && mirror && m_sent.first(kMirrorScope, evt)) {
        m_agentClient->reportEvent(evt, rule.id);
    }
}

void Forwarder::forwardAlert(const BufferedEvent& evt, const std::string& destination,
                              const RuleMeta& rule, const std::string& message,
                              const std::vector<BufferedEvent>& evidenceEvents,
                              bool evidenceIsSequence,
                              const std::vector<std::string>& alsoMatched,
                              const std::string& alertId) {
    // Resolve the destination under the lock, then release it before I/O so
    // a slow write doesn't block setConfig. The server POST is also outside
    // the lock.
    Destination dest;
    bool ok = false;
    FormatContext ctx;
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        ok = resolveDestination(destination, dest);
        ctx = makeContext(dest, rule, "alert");
    }
    ctx.alertId = alertId;
    if (ok) {
        ctx.message = message;
        ctx.evidence = &evidenceEvents;
        ctx.evidenceIsSequence = evidenceIsSequence;
        ctx.alsoMatched = &alsoMatched;
        for (const auto& p : formatAlert(evt, ctx)) writeToDestination(dest, p);
    }
    // Mirror the alert to the management server (best-effort, outside the
    // Forwarder lock so other forwarding/config operations can proceed).
    if (m_agentClient) {
        m_agentClient->reportAlert(rule.id, message, evt, rule.level,
                                   evidenceEvents, evidenceIsSequence,
                                   alsoMatched, alertId);
    }
}

void Forwarder::forwardBuffer(const BufferedEvent& trigger, const std::string& message,
                              const std::vector<BufferedEvent>& buffer,
                              const std::string& destination,
                              const RuleMeta& rule,
                              const std::vector<BufferedEvent>& sequenceEvents,
                              bool skipAlertNotification,
                              bool evidenceIsSequence,
                              const std::vector<std::string>& alsoMatched,
                              const std::string& alertId) {
    // Resolve the destination under the lock, then release it before building
    // the payload + I/O so a large buffer write doesn't block setConfig.
    // Skip the write entirely when the buffer is empty; writing an empty
    // payload would just produce a blank line in the file with no event data.
    Destination dest;
    bool ok = false;
    bool mirror = true;
    FormatContext ctx;
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        ok = resolveDestination(destination, dest);
        mirror = m_config.mirror_logs;
        ctx = makeContext(dest, rule, "forward_buffer");
    }
    ctx.alertId = alertId;
    // Only the events this destination has not received yet: another rule's
    // forward_buffer or forward_event may already have carried some of them.
    if (ok && !buffer.empty()) {
        auto fresh = m_sent.filter(dest.name, buffer);
        if (!fresh.empty()) {
            for (const auto& p : formatEvents(fresh, ctx)) writeToDestination(dest, p);
        }
    }
    // Mirror to the management server outside the lock so the agent doesn't
    // freeze on a slow server POST. The server mirror sends ONE alert (the
    // forward_buffer notification, with the trigger event + evidence) plus
    // the buffer events via POST /logs (chunked). For sequence rules,
    // sequenceEvents carries all the events that formed the sequence so the
    // alert payload shows the full attack chain.
    // When `skipAlertNotification` is true (the rule's own `alert` action
    // already fired for this event), the mirror skips the POST /alerts
    // notification so the server doesn't record a duplicate alert for the
    // same EventRecordID. Only the POST /logs batch is sent.
    // The POST /logs batch is additionally gated on the per-group
    // mirror_logs toggle (skipLogsBatch = !mirror): when off, the alert
    // still mirrors (detection record) but the log batch does not.
    // The batch carries only events the server has not received from this
    // agent yet; the notification alert goes regardless of the batch size.
    if (m_agentClient) {
        std::vector<BufferedEvent> fresh;
        if (mirror) fresh = m_sent.filter(kMirrorScope, buffer);
        m_agentClient->reportLogs(rule.id, message, trigger, fresh, rule.level,
                                  sequenceEvents, skipAlertNotification,
                                  /*skipLogsBatch=*/!mirror,
                                  evidenceIsSequence, alsoMatched, alertId);
    }
}

} // namespace elf
