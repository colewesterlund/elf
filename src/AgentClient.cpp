#include "AgentClient.h"
#include "HttpClient.h"
#include "FieldResolver.h"
#include "Config.h"
#include "Console.h"
#include "Platform.h"
#include <nlohmann/json.hpp>
#include <iostream>
#include <fstream>
#include <filesystem>
#include <sstream>
#include <algorithm>
#include <thread>
#include <type_traits>
#include <unordered_set>

namespace elf {

using json = nlohmann::json;

// Type-checked JSON field read with a default. nlohmann's `j["k"].get<T>()`
// AND `j.value("k", def)` both throw type_error when the key exists with
// the wrong type (e.g. a null, or "30" instead of 30). The poll thread
// has no business dying because the server sent an odd value, so every
// field read from a server response goes through here and falls back to
// the default on any mismatch.
template <class T>
static T jsonGet(const json& j, const char* key, T def) {
    if (!j.is_object()) return def;
    auto it = j.find(key);
    if (it == j.end()) return def;
    if constexpr (std::is_same_v<T, bool>) {
        return it->is_boolean() ? it->get<bool>() : def;
    } else if constexpr (std::is_integral_v<T>) {
        return it->is_number_integer() ? it->get<T>() : def;
    } else if constexpr (std::is_same_v<T, std::string>) {
        return it->is_string() ? it->get<std::string>() : def;
    } else {
        return def;
    }
}

AgentClient::AgentClient() = default;

AgentClient::~AgentClient() {
    // Ship any pending forwarded-event batch before tearing down so events
    // accumulated since the last poll are not lost on shutdown. The spool
    // keeps whatever the worker could not send for the next start.
    flushPendingLogs();
    m_poster.stop();
}

void AgentClient::enqueuePost(std::string url, std::string body) {
    if (m_serverUrl.empty()) return;
    // The spool writes to disk immediately so the POST survives a crash.
    // It bounds the total spool size (evicting oldest-first) so a long
    // network outage can't fill the disk.
    m_poster.enqueue(std::move(url), std::move(body));
}




void AgentClient::init(const Config& bootstrap) {
    m_serverUrl = bootstrap.server.url;
    m_agentId = bootstrap.server.agent_id;
    m_authToken = bootstrap.server.auth_token;
    m_rulesDir = bootstrap.rules_directory;
    m_listsDir = bootstrap.lists_directory;
    m_hostname = platformHostname();
    m_ipAddress = platformIpAddress();
    m_osName = platformOsName();

    // If agent_id is empty, fall back to the hostname so every device has a
    // stable identity without manual config.
    if (m_agentId.empty()) {
        m_agentId = m_hostname;
    }

    logInfo("[AgentClient] agent_id=" + m_agentId +
            " hostname=" + m_hostname +
            " ip=" + m_ipAddress +
            " os=" + m_osName +
            " server=" + m_serverUrl +
            (m_authToken.empty() ? " (no auth token - legacy mode)" : " (auth token configured)"));
}

void AgentClient::initSpool(const std::string& dir, size_t maxBytes) {
    // The token is scoped to the server URL so it can never be sent
    // anywhere else, even if a future producer spools a foreign URL here.
    m_poster.start(dir, maxBytes, m_serverUrl, m_authToken);
}

bool AgentClient::poll(uint64_t eventsCreated, uint64_t bytesCreated) {
    if (m_serverUrl.empty()) {
        return false;
    }

    // Flush any pending forwarded-event batch so forward_event logs are
    // shipped at the poll interval (batched into a single POST /logs rather
    // than one POST per event).
    flushPendingLogs();

    // Send the detected hostname, IP, OS, and cumulative event/byte counters
    // as query params so the server can store them on the agent row. The
    // eventsCreated/bytesCreated come from the LogGrowthMonitor (events
    // generated on the watched channels, measured via event-log metadata;
    // bytes estimated); eventsForwarded/bytesForwarded are tracked locally
    // (shipped to the server). The server computes savings = 1 - forwarded /
    // created.
    auto urlEncode = [](const std::string& s) {
        static const char* hex = "0123456789ABCDEF";
        std::string out;
        out.reserve(s.size());
        for (unsigned char c : s) {
            if ((c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') ||
                (c >= 'a' && c <= 'z') || c == '-' || c == '_' ||
                c == '.' || c == '~') {
                out.push_back(c);
            } else {
                out.push_back('%');
                out.push_back(hex[c >> 4]);
                out.push_back(hex[c & 0xF]);
            }
        }
        return out;
    };
    std::string url = m_serverUrl + "/config/" + urlEncode(m_agentId)
        + "?hostname=" + urlEncode(m_hostname)
        + "&ip=" + urlEncode(m_ipAddress)
        + "&os=" + urlEncode(m_osName)
        + "&events_created=" + std::to_string(eventsCreated)
        + "&bytes_created=" + std::to_string(bytesCreated)
        + "&events_forwarded=" + std::to_string(m_eventsForwarded.load())
        + "&bytes_forwarded=" + std::to_string(m_bytesForwarded.load());
    // Tell the server which ruleset we already run so it can answer "no
    // change" without shipping every rule again (see applyServerConfig).
    if (!m_appliedRulesetHash.empty() && !m_forceFullSync.load()) {
        url += "&known_hash=" + urlEncode(m_appliedRulesetHash);
    }
    std::string body, err;
    // Use a bounded timeout so a slow/downed server doesn't stall the poll
    // thread indefinitely. The poll thread doesn't block the rule engine, but
    // a long stall delays config/rule updates. The /config response carries
    // the full ruleset (yaml_body per rule); with thousands of rules the
    // gzipped payload can still take a while to transfer, so allow up to 60s
    // for the config fetch. The server compresses large responses with gzip.
    bool ok = HttpClient::get(url, body, err, 60000, m_authToken);
    if (!ok) {
        if (m_lastPollOk.exchange(false)) {
            logError("[AgentClient] poll failed: " + err);
        }
        return false;
    }

    m_lastPollOk = true;
    return applyServerConfig(body);
}

bool AgentClient::applyServerConfig(const std::string& jsonStr) {
    json cfg;
    try {
        cfg = json::parse(jsonStr);
    } catch (const std::exception& e) {
        logError("[AgentClient] Failed to parse server config: " + std::string(e.what()));
        return false;
    }

    // Build a Config from the bootstrap (current ConfigStore) and overlay the
    // server-pushed values. The server is the source of truth for retention,
    // poll interval, and destinations.
    Config cfgOut = ConfigStore::instance().get();

    // Reboot/reinstall protection: the server tells us whether it has seen
    // this agent before. known_agent=true means this is a reboot/reinstall of
    // an already-subscribed device (resume from bookmarks); false means a
    // fresh first install (wait for rules before collecting so we don't
    // buffer+forward a backlog of historical events).
    m_knownAgent.store(jsonGet<bool>(cfg, "known_agent", m_knownAgent.load()));
    cfgOut.retention_seconds =
        jsonGet<int>(cfg, "retention_seconds", cfgOut.retention_seconds);
    cfgOut.server.poll_interval_seconds =
        jsonGet<int>(cfg, "poll_interval_seconds", cfgOut.server.poll_interval_seconds);
    // Per-group mirror toggle: when false the agent stops POSTing
    // forwarded-log batches (POST /logs) but still reports alerts, since alerts
    // are the detection record and always mirror. Forwarder reads this flag
    // from the config snapshot on every forward decision.
    cfgOut.mirror_logs = jsonGet<bool>(cfg, "mirror_logs", cfgOut.mirror_logs);

    // Overlay server-pushed destinations. These replace the [destinations]
    // from config.ini for the named keys the server provides. We keep any
    // local destinations the server didn't mention so file:// local sinks
    // still work.
    if (cfg.contains("destinations") && cfg["destinations"].is_object()) {
        for (auto it = cfg["destinations"].begin(); it != cfg["destinations"].end(); ++it) {
            if (!it.value().is_string()) continue;
            std::string name = it.key();
            std::string url = it.value().get<std::string>();
            // Same parser as config.ini so ?format=... options and secret
            // stripping apply identically to server-pushed destinations.
            Destination d = parseDestinationUrl(name, url);
            // Resolve relative file paths against the agent DATA directory
            // (%ProgramData%\ELFAgent), the only tree the service account
            // can write. Anchoring them to the exe dir (Program Files) made
            // every server-pushed `file://./output/x.jsonl` fail with
            // "Cannot open file" on installed hosts. Absolute paths pass
            // through. Same helper as config.ini destinations.
            if (d.scheme == "file") {
                d.path = resolveFileDestinationPath(d.path);
            }
            cfgOut.destinations[name] = d;
        }
    }

    // Apply the config locally (updates ConfigStore + Forwarder).
    ConfigStore::instance().set(cfgOut);
    if (m_applyConfig) m_applyConfig(cfgOut);

    // Write the ruleset to disk. writeRulesToDisk only touches files whose
    // content actually changed (to avoid triggering Defender real-time
    // scanning on every poll), and reports whether anything changed.
    //
    // Only when the server actually sent a ruleset. `ruleset_unchanged`
    // (our known_hash still matched) or a missing `rules` key (a server
    // that sends no hash, or a malformed response) means: leave the disk
    // alone. Treating it as an empty ruleset would make the stale-file
    // sweep delete every rule.
    const bool rulesetUnchanged = jsonGet<bool>(cfg, "ruleset_unchanged", false);
    const std::string rulesetHash = jsonGet<std::string>(cfg, "ruleset_hash", "");
    if (rulesetUnchanged) {
        logDebug("[AgentClient] Ruleset unchanged (hash " + rulesetHash.substr(0, 12) + ")");
    }
    if (!rulesetUnchanged && cfg.contains("rules") && cfg["rules"].is_array()) {
    std::vector<std::pair<std::string, std::string>> rules;
    {
        for (const auto& r : cfg["rules"]) {
            std::string id = jsonGet<std::string>(r, "rule_id", "");
            std::string yaml = jsonGet<std::string>(r, "yaml_body", "");
            // A rule toggled off in the UI must not run here. The loader
            // only knows the Sigma `status` field, so the server's enabled
            // flag has to be honored at this point: leave the rule out of
            // the set, and the stale-file sweep below deletes its file.
            if (!jsonGet<bool>(r, "enabled", true)) continue;
            if (!id.empty() && !yaml.empty()) {
                rules.emplace_back(id, yaml);
            }
        }
    }

    bool rulesChanged = false;
    if (writeRulesToDisk(rules, rulesChanged)) {
        // Write reusable lists to disk (so the rule loader can expand `@@`
        // references on the next reload). Lists are written BEFORE the
        // reload is triggered so the freshly-written list files are available
        // when the loader runs.
        std::vector<std::pair<std::string, std::string>> lists;
        if (cfg.contains("lists") && cfg["lists"].is_array()) {
            for (const auto& l : cfg["lists"]) {
                std::string name = jsonGet<std::string>(l, "name", "");
                std::string content = jsonGet<std::string>(l, "content", "");
                if (!name.empty()) {
                    lists.emplace_back(name, content);
                }
            }
        }
        bool listsChanged = false;
        writeListsToDisk(lists, listsChanged);

        // Only trigger a reload + log when the ruleset or lists actually
        // changed. Reloading 1000 rules on every 30s poll wastes CPU and
        // disk I/O (the loader re-parses every YAML file).
        if ((rulesChanged || listsChanged) && m_reloadRules) {
            m_reloadRules();
        }
        // After a ruleset change, re-derive the XPath subscription filter
        // and re-subscribe the EventCollector so Windows only delivers
        // events the new rules reference. This is the hot-reload half of
        // XPath subscription filtering; the startup half is in main.cpp.
        if ((rulesChanged || listsChanged) && m_resubscribe) {
            m_resubscribe();
        }
        if (rulesChanged || listsChanged) {
            logInfo("[AgentClient] Applied server config: " +
                    std::to_string(rules.size()) + " rule(s), " +
                    std::to_string(lists.size()) + " list(s), retention=" +
                    std::to_string(cfgOut.retention_seconds) + "s");
        }
        // Disk now reflects this hash; the next poll can ask for a short
        // "unchanged" answer. (Empty when the server predates the protocol,
        // which keeps the full-sync behavior.)
        m_appliedRulesetHash = rulesetHash;
        m_forceFullSync.store(false);
    }
    }  // rules present

    // Handle on-demand commands (e.g. collect_logs) received from the server.
    // These are delivered once (the server marks them sent when building the
    // response). Each spawns a detached worker thread so the poll loop is not
    // blocked by a potentially long historical pull.
    if (cfg.contains("commands") && cfg["commands"].is_array()) {
        handleCommands(cfg["commands"].dump());
    }
    return true;
}

// Write `content` to `filename` only if the file's current bytes differ.
// Returns true if the file was written, false if it was identical (or the
// write failed, which is logged). Both the read and the write are BINARY: a
// text-mode write turns "\n" into "\r\n" on Windows, so the comparison
// would never match, every rule file would be rewritten on every poll (a
// Defender scan storm with thousands of rules) and each poll would trigger
// a full reload + resubscribe. The write goes to a .tmp then an atomic rename, so
// the 60 s reload thread sees either the old or the new complete file,
// never a half-written one.
static bool writeFileIfChanged(const std::string& filename,
                               const std::string& content, const char* kind) {
    std::ifstream existing(filename, std::ios::binary);
    if (existing.is_open()) {
        std::string old((std::istreambuf_iterator<char>(existing)),
                        std::istreambuf_iterator<char>());
        existing.close();
        if (old == content) return false;
    }
    std::string tmp = filename + ".tmp";
    {
        std::ofstream f(tmp, std::ios::binary | std::ios::trunc);
        if (!f.is_open()) {
            logError("[AgentClient] Cannot write " + std::string(kind) +
                     " file: " + filename);
            return false;
        }
        f << content;
    }
    std::error_code ec;
    std::filesystem::rename(tmp, filename, ec);
    if (ec) {
        // rename can fail if the target is held open (e.g. by an AV scan);
        // fall back to copy + remove.
        std::filesystem::copy_file(tmp, filename,
            std::filesystem::copy_options::overwrite_existing, ec);
        std::error_code rmEc;
        std::filesystem::remove(tmp, rmEc);
        if (ec) {
            logError("[AgentClient] Cannot finalize " + std::string(kind) +
                     " file: " + filename + ": " + ec.message());
            return false;
        }
    }
    return true;
}

bool AgentClient::writeRulesToDisk(
        const std::vector<std::pair<std::string, std::string>>& rules,
        bool& changed) {
    changed = false;
    std::error_code ec;
    std::filesystem::create_directories(m_rulesDir, ec);

    // Track which rule ids we're writing so we can remove files for rules
    // the server no longer includes (server is source of truth).
    std::unordered_set<std::string> keep;

    // Only write files whose content actually changed. The server is the
    // source of truth and the agent polls every poll_interval_seconds (often
    // 30s); rewriting all 1000+ rule files on every poll triggers Windows
    // Defender real-time scanning on every file, causing 100% CPU spikes in
    // MsMpEng.exe. By skipping unchanged files we keep the disk (and thus
    // Defender) quiet on the common case where the ruleset hasn't changed.
    size_t written = 0, skipped = 0;
    for (const auto& [id, yaml] : rules) {
        std::string filename = m_rulesDir + "/" + id + ".yaml";
        keep.insert(id);

        // Read the existing file (if any) and compare. Only write when the
        // content differs or the file doesn't exist.
        if (!writeFileIfChanged(filename, yaml, "rule")) { ++skipped; continue; }
        ++written;
        changed = true;
    }

    // Remove local .yaml files whose rule_id isn't in the server set, and
    // any .tmp left by a crash mid-write (it was never a complete rule).
    size_t removed = 0;
    if (std::filesystem::is_directory(m_rulesDir, ec)) {
        for (auto& entry : std::filesystem::directory_iterator(m_rulesDir, ec)) {
            std::error_code feErr;
            if (!entry.is_regular_file(feErr)) continue;
            auto stem = entry.path().stem().string();
            auto ext = entry.path().extension().string();
            if (ext == ".tmp") {
                std::error_code rmErr;
                std::filesystem::remove(entry.path(), rmErr);
                continue;
            }
            if (ext != ".yaml" && ext != ".yml") continue;
            if (keep.count(stem) == 0) {
                std::error_code rmErr;
                std::filesystem::remove(entry.path(), rmErr);
                ++removed;
                changed = true;
            }
        }
    }
    // Log only when something actually changed, so the agent log isn't
    // noisy on every poll. A change log line is the operator's signal that
    // a ruleset update landed.
    if (written || removed) {
        logInfo("[AgentClient] Rules written: " + std::to_string(written) +
                " new/changed, " + std::to_string(skipped) + " unchanged, " +
                std::to_string(removed) + " removed");
    }
    return true;
}

bool AgentClient::writeListsToDisk(
        const std::vector<std::pair<std::string, std::string>>& lists,
        bool& changed) {
    changed = false;
    std::error_code ec;
    std::filesystem::create_directories(m_listsDir, ec);

    // Track which list names we're writing so we can remove files for lists
    // the server no longer includes (server is source of truth).
    std::unordered_set<std::string> keep;

    // Same content-based skip as writeRulesToDisk: only write changed files
    // to avoid triggering Defender real-time scanning on every poll.
    size_t written = 0, skipped = 0;
    for (const auto& [name, content] : lists) {
        std::string filename = m_listsDir + "/" + name + ".txt";
        keep.insert(name);
        if (!writeFileIfChanged(filename, content, "list")) { ++skipped; continue; }
        ++written;
        changed = true;
    }

    // Remove local .txt files whose list name isn't in the server set.
    size_t removed = 0;
    if (std::filesystem::is_directory(m_listsDir, ec)) {
        for (auto& entry : std::filesystem::directory_iterator(m_listsDir, ec)) {
            if (!entry.is_regular_file()) continue;
            auto stem = entry.path().stem().string();
            auto ext = entry.path().extension().string();
            if (ext != ".txt" && ext != ".list") continue;
            if (std::find(keep.begin(), keep.end(), stem) == keep.end()) {
                std::error_code rmErr;
                std::filesystem::remove(entry.path(), rmErr);
                ++removed;
                changed = true;
            }
        }
    }
    if (written || removed) {
        logInfo("[AgentClient] Lists written: " + std::to_string(written) +
                " new/changed, " + std::to_string(skipped) + " unchanged, " +
                std::to_string(removed) + " removed");
    }
    return true;
}

std::string buildAlertPayload(const std::string& ruleId,
                              const std::string& message,
                              const BufferedEvent& trigger,
                              const std::string& level,
                              const std::vector<BufferedEvent>& evidenceEvents,
                              bool evidenceIsSequence,
                              const std::vector<std::string>& alsoMatched,
                              const std::string& alertId) {
    // Convert the event XML (UTF-16 wstring) to UTF-8 for JSON. Use
    // wideToUtf8 (WideCharToMultiByte); the naive std::string(w.begin(),
    // w.end()) truncates each wchar_t to a single char and corrupts
    // non-ASCII content (rendered as '�' by consumers).
    json payload;
    payload["rule_id"] = ruleId;
    payload["message"] = message;
    payload["level"] = level;
    if (!alertId.empty()) payload["alert_id"] = alertId;
    payload["event_xml"] = wideToUtf8(trigger.xml);
    // Correlation evidence: the events that formed the sequence (attack
    // chain) or the events that filled the threshold window, so the alert
    // payload shows the full picture, not just the trigger. The key
    // distinguishes the two so the UI can label items correctly (Stage N
    // for sequences, Event N for threshold windows). Capped: keep the LAST
    // N (the most recent; they led directly to the fire) and say how many
    // older ones were left out, so a huge window never becomes a huge POST.
    if (!evidenceEvents.empty()) {
        const size_t cap = AgentClient::MAX_ALERT_EVIDENCE_EVENTS;
        size_t start = evidenceEvents.size() > cap ? evidenceEvents.size() - cap : 0;
        json evArr = json::array();
        for (size_t i = start; i < evidenceEvents.size(); ++i) {
            evArr.push_back(wideToUtf8(evidenceEvents[i].xml));
        }
        const char* key = evidenceIsSequence ? "sequence_events" : "window_events";
        payload[key] = evArr;
        if (start > 0) {
            payload[std::string(key) + "_truncated"] = start;
        }
    }
    if (!alsoMatched.empty()) {
        payload["also_matched"] = alsoMatched;
    }
    return payload.dump();
}

void AgentClient::reportAlert(const std::string& ruleId, const std::string& message,
                              const BufferedEvent& evt, const std::string& level,
                              const std::vector<BufferedEvent>& evidenceEvents,
                              bool evidenceIsSequence,
                              const std::vector<std::string>& alsoMatched,
                              const std::string& alertId) {
    if (m_serverUrl.empty()) return;
    std::string url = m_serverUrl + "/alerts?agent_id=" + m_agentId;
    enqueuePost(std::move(url), buildAlertPayload(ruleId, message, evt, level,
                                                  evidenceEvents, evidenceIsSequence,
                                                  alsoMatched, alertId));
}

void AgentClient::reportEvent(const BufferedEvent& evt, const std::string& ruleId) {
    if (m_serverUrl.empty()) return;

    std::string xmlUtf8 = wideToUtf8(evt.xml);
    // Track forwarded metrics: 1 event, bytes = UTF-8 XML length. Dedup by
    // EventRecordID so an event forwarded via forward_event AND forward_buffer
    // is only counted once (prevents the >100% forwarded metric).
    countForwarded({evt});

    // Accumulate into the pending batch instead of sending immediately.
    // The batch is flushed on each poll cycle (at the poll interval) or
    // when it reaches the size threshold, so thousands of forward_event
    // matches produce a small number of batched POSTs rather than one
    // POST (and one new socket) per event. Each entry carries the rule_id
    // so every forwarded log is associated with the rule that sent it.
    bool shouldFlush = false;
    {
        std::lock_guard<std::mutex> lock(m_batchMutex);
        m_batchEvents.push_back({ruleId, std::move(xmlUtf8)});
        m_batchBytes += m_batchEvents.back().xmlUtf8.size();
        if (m_batchEvents.size() >= MAX_BATCH_EVENTS ||
            m_batchBytes >= MAX_BATCH_BYTES) {
            shouldFlush = true;
        }
    }
    if (shouldFlush) flushPendingLogs();
}

void AgentClient::flushPendingLogs() {
    std::vector<BatchEntry> events;
    {
        std::lock_guard<std::mutex> lock(m_batchMutex);
        if (m_batchEvents.empty()) return;
        events.swap(m_batchEvents);
        m_batchBytes = 0;
    }
    // Build the batch payload. Each entry carries the rule_id that forwarded
    // it so every forwarded log is associated with the rule that sent it.
    // The LogReport model accepts a single rule_id; when
    // a batch spans multiple rules we send the first event's rule_id as the
    // primary and include a per-event rule_ids array for full attribution.
    json payload;
    payload["rule_id"] = events.empty() ? "" : events[0].ruleId;
    payload["event_count"] = events.size();
    json arr = json::array();
    json ruleIds = json::array();
    for (auto& e : events) {
        arr.push_back(std::move(e.xmlUtf8));
        ruleIds.push_back(e.ruleId);
    }
    payload["events"] = arr;
    payload["rule_ids"] = ruleIds;
    std::string url = m_serverUrl + "/logs?agent_id=" + m_agentId;
    enqueuePost(std::move(url), payload.dump());
}

void AgentClient::reportLogs(const std::string& ruleId, const std::string& message,
                             const BufferedEvent& trigger,
                             const std::vector<BufferedEvent>& buffer,
                             const std::string& level,
                             const std::vector<BufferedEvent>& sequenceEvents,
                             bool skipAlertNotification,
                             bool skipLogsBatch,
                             bool evidenceIsSequence,
                             const std::vector<std::string>& alsoMatched,
                             const std::string& alertId) {
    if (m_serverUrl.empty()) return;

    // 1. Send a SINGLE alert notifying that forward_buffer fired. The alert
    //    carries the rule's description as the message AND the trigger
    //    event XML so the Alerts page dropdown can show what triggered the
    //    buffer forward. For sequence rules, the alert also includes ALL
    //    the events that formed the sequence (sequenceEvents) so the analyst
    //    can see the full attack chain, not just the final trigger. The full
    //    buffer is shipped separately as a log batch below; the alert only
    //    carries the trigger + sequence events (not the whole buffer) to
    //    avoid duplicating large payloads.
    //    SKIPPED when `skipAlertNotification` is true: the rule's own
    //    `alert` action already sent a POST /alerts for this event, so
    //    sending another here would produce a duplicate alert (same
    //    EventRecordID, ~20ms apart) on the server. Only the POST /logs
    //    batch below is sent in that case.
    if (!skipAlertNotification) {
        std::string url = m_serverUrl + "/alerts?agent_id=" + m_agentId;
        enqueuePost(std::move(url),
                    buildAlertPayload(ruleId,
                                      message.empty() ? "forward_buffer" : message,
                                      trigger, level, sequenceEvents,
                                      evidenceIsSequence, alsoMatched, alertId));
    }

    // 2. Ship the buffer contents as log batches (POST /logs) so the events
    //    land in the logs view as normal forwarded logs, not as individual
    //    alerts. The server's LogReport model accepts {rule_id, event_count,
    //    events[]} with at most 10,000 events; a bigger batch is rejected
    //    with 422 and can never be delivered, so the buffer is split into
    //    chunks of MAX_LOGS_POST_EVENTS /
    //    MAX_LOGS_POST_BYTES.
    //    SKIPPED when `skipLogsBatch` is true: the group's mirror_logs
    //    toggle is OFF (Forwarder passes !mirror). The alert above is
    //    STILL sent: alerts are the detection record and always mirror.
    if (!skipLogsBatch && !buffer.empty()) {
        json events = json::array();
        size_t chunkBytes = 0;
        auto flushChunk = [&]() {
            if (events.empty()) return;
            json logsPayload;
            logsPayload["rule_id"] = ruleId;
            if (!alertId.empty()) logsPayload["alert_id"] = alertId;
            logsPayload["event_count"] = events.size();
            logsPayload["events"] = std::move(events);
            events = json::array();
            chunkBytes = 0;
            std::string url = m_serverUrl + "/logs?agent_id=" + m_agentId;
            enqueuePost(std::move(url), logsPayload.dump());
        };
        for (const auto& e : buffer) {
            std::string xmlUtf8 = wideToUtf8(e.xml);
            if (!events.empty() &&
                (events.size() >= MAX_LOGS_POST_EVENTS ||
                 chunkBytes + xmlUtf8.size() > MAX_LOGS_POST_BYTES)) {
                flushChunk();
            }
            chunkBytes += xmlUtf8.size();
            events.push_back(std::move(xmlUtf8));
        }
        flushChunk();
        // Track forwarded metrics with dedup: only count events whose
        // EventRecordID hasn't already been counted (e.g. by forward_event).
        // This prevents the >100% forwarded metric where forward_buffer
        // re-counts events already forwarded via forward_event.
        size_t newlyCounted = countForwarded(buffer);
        if (newlyCounted < buffer.size()) {
            logInfo("[AgentClient] forward_buffer: " +
                    std::to_string(buffer.size() - newlyCounted) +
                    " events already counted (dedup), " +
                    std::to_string(newlyCounted) + " new");
        }
    }
}

// Count events as forwarded, deduplicating by EventRecordID. Returns the
// number of newly-counted events (events whose EventRecordID was not already
// in m_forwardedRecordIds). This prevents the >100% forwarded metric where
// an event forwarded via forward_event AND forward_buffer is counted twice.
size_t AgentClient::countForwarded(const std::vector<BufferedEvent>& events) {
    if (events.empty()) return 0;
    size_t newlyCounted = 0;
    uint64_t newBytes = 0;
    auto now = std::chrono::system_clock::now();
    {
        std::lock_guard<std::mutex> lock(m_fwdDedupMutex);
        for (const auto& evt : events) {
            uint64_t key = eventDedupKey(evt);
            if (key != 0) {
                if (m_forwardedRecordIds.count(key)) continue;
                m_forwardedRecordIds[key] = now;
            }
            ++newlyCounted;
            newBytes += wideToUtf8(evt.xml).size();
        }
    }
    m_eventsForwarded.fetch_add(newlyCounted, std::memory_order_relaxed);
    m_bytesForwarded.fetch_add(newBytes, std::memory_order_relaxed);
    // Prune periodically to bound memory (every call is cheap enough; the
    // set is bounded by the number of unique events in ~1 hour).
    pruneForwardedDedup();
    return newlyCounted;
}

void AgentClient::pruneForwardedDedup() {
    auto cutoff = std::chrono::system_clock::now() - std::chrono::hours(1);
    std::lock_guard<std::mutex> lock(m_fwdDedupMutex);
    for (auto it = m_forwardedRecordIds.begin(); it != m_forwardedRecordIds.end();) {
        if (it->second < cutoff) {
            it = m_forwardedRecordIds.erase(it);
        } else {
            ++it;
        }
    }
}

// --- On-demand log collection (collect logs command) ----------------------

void AgentClient::handleCommands(const std::string& commandsJson) {
    json commands;
    try {
        commands = json::parse(commandsJson);
    } catch (const std::exception& e) {
        logError("[AgentClient] Failed to parse commands array: " + std::string(e.what()));
        return;
    }
    if (!commands.is_array()) return;
    for (const auto& cmd : commands) {
        if (!cmd.is_object()) continue;
        long id = static_cast<long>(jsonGet<long long>(cmd, "id", 0));
        std::string type = jsonGet<std::string>(cmd, "type", "");
        if (type != "collect_logs" || id == 0) continue;

        // Guard against duplicate execution: if a command ID is already being
        // processed (e.g. the server didn't yet mark it sent and we polled
        // again), skip it.
        {
            std::lock_guard<std::mutex> lock(m_cmdMutex);
            if (m_inFlightCommands.count(id)) continue;
            m_inFlightCommands.insert(id);
        }

        std::string startTime;
        if (cmd.contains("params") && cmd["params"].is_object()) {
            startTime = jsonGet<std::string>(cmd["params"], "start_time", "");
        }
        if (startTime.empty()) {
            logError("[AgentClient] collect_logs command " + std::to_string(id) +
                     " missing start_time; skipping.");
            std::lock_guard<std::mutex> lock(m_cmdMutex);
            m_inFlightCommands.erase(id);
            continue;
        }

        logInfo("[AgentClient] Received collect_logs command " + std::to_string(id) +
                " (start=" + startTime + "); spawning collector thread.");
        // Detached thread: fire-and-forget. The pull may take a while for a
        // large date range; we must not block the poll loop.
        std::thread([this, id, startTime]() {
            runGuarded("collect-logs", [&] { runCollectCommand(id, startTime); });
        }).detach();
    }
}

void AgentClient::runCollectCommand(long commandId,
                                    const std::string& startTimeIsoUtc) {
    size_t total = 0;
    int batches = 0;
    std::string error;
    try {
        // Batch the rendered events and ship via POST /collect/{id}. Use a
        // local accumulator so the collector callback stays cheap.
        std::vector<std::string> batch;
        batch.reserve(200);
        size_t* pTotal = &total;
        int* pBatches = &batches;
        long cmdId = commandId;
        AgentClient* self = this;
        auto cb = [&batch, pTotal, pBatches, cmdId, self](const std::wstring& xml) {
            std::string utf8 = wideToUtf8(xml);
            batch.push_back(std::move(utf8));
            if (batch.size() >= 200) {
                self->reportCollectBatch(cmdId, *pBatches, batch);
                ++(*pBatches);
                (*pTotal) += batch.size();
                batch.clear();
                batch.reserve(200);
            }
        };
        platformCollectHistory(startTimeIsoUtc, cb);
        // Flush any remaining events in the final partial batch.
        if (!batch.empty()) {
            reportCollectBatch(commandId, batches, batch);
            total += batch.size();
            ++batches;
            batch.clear();
        }
    } catch (const std::exception& e) {
        error = e.what();
        logError("[AgentClient] collect_logs command " + std::to_string(commandId) +
                 " failed: " + error);
    }

    std::string status = error.empty() ? "done" : "failed";
    reportCollectDone(commandId, status, total, batches, error);

    // Remove from the in-flight set so a future command with the same ID
    // (shouldn't happen, but defensive) can run.
    std::lock_guard<std::mutex> lock(m_cmdMutex);
    m_inFlightCommands.erase(commandId);
}

void AgentClient::reportCollectBatch(long commandId, int batchIndex,
                                      const std::vector<std::string>& eventsUtf8) {
    if (m_serverUrl.empty()) return;
    json payload;
    payload["agent_id"] = m_agentId;
    payload["batch_index"] = batchIndex;
    payload["event_count"] = eventsUtf8.size();
    json arr = json::array();
    for (const auto& e : eventsUtf8) arr.push_back(e);
    payload["events"] = arr;
    std::string url = m_serverUrl + "/collect/" + std::to_string(commandId);
    enqueuePost(std::move(url), payload.dump());
}

void AgentClient::reportCollectDone(long commandId, const std::string& status,
                                     size_t eventsCollected, int batches,
                                     const std::string& error) {
    if (m_serverUrl.empty()) return;
    json payload;
    payload["agent_id"] = m_agentId;
    payload["status"] = status;
    payload["events_collected"] = eventsCollected;
    payload["batches"] = batches;
    if (!error.empty()) payload["error"] = error;
    std::string url = m_serverUrl + "/collect/" + std::to_string(commandId) + "/done";
    enqueuePost(std::move(url), payload.dump());
}

} // namespace elf
