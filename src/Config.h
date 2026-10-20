#pragma once

#include <string>
#include <unordered_map>
#include <vector>
#include <mutex>
#include <chrono>

namespace elf {

// The agent's writable data root, with a trailing backslash. Relative
// `file://` destination paths (from config.ini or pushed by the server)
// resolve against it. Resolution order:
//   1. setDataRootDir() override: main.cpp sets it to %ProgramData%\ELFAgent
//      at startup; config.ini `[paths] data_directory` also sets it.
//   2. %ProgramData%\ELFAgent\ if that directory exists (installed agent).
//   3. The exe directory (dev/test runs).
// The exe directory is deliberately NOT the default for an installed agent:
// it is Program Files, read-only for the service account, and anchoring
// relative output paths there produced "Cannot open file" on every alert.
std::string dataRootDir();
void setDataRootDir(const std::string& dir);

// Resolve a `file://` destination path: http(s):// URLs and absolute paths
// pass through; `file:///C:/x` (which parses to "/C:/x") loses its leading
// slash; a relative path (optionally starting with "./") is anchored to
// dataRootDir().
std::string resolveFileDestinationPath(const std::string& path);

// Per-destination output options, carried as query-string keys on the
// destination URL so the existing {name: url} wire format (config.ini, the
// server database, GET /config, the Groups tab) needs no schema change:
//
//   file://output/alerts.jsonl?format=ecs
//   https://splunk:8088/services/collector/event?format=hec&token=...&index=win
//   http://graylog:12201/gelf?format=gelf
//   https://<dce>.ingest.monitor.azure.com/dataCollectionRules/<dcr>/streams/Custom-ELF_CL?api-version=2023-01-01&format=sentinel&tenant=...&client=...&secret=...
//
// Known keys are consumed here and STRIPPED from the request URL (so a
// token never reaches a log line that prints the URL); unknown keys pass
// through to the endpoint. `token=env:NAME` / `secret=env:NAME` read the
// value from the service environment instead of the URL.
struct DestinationOptions {
    std::string format = "raw";   // raw | json | ecs | hec | gelf | sentinel
    std::string event;            // hec inner document: json (default) | ecs
    std::string token;            // hec: "Authorization: Splunk"; json/ecs/gelf over http: Bearer
    std::string index;            // hec: envelope index
    std::string sourcetype;       // hec: override elf:event / elf:alert
    std::string tenant;           // sentinel: Entra tenant id
    std::string client;           // sentinel: app (client) id
    std::string secret;           // sentinel: client secret
    bool        insecure = false; // https: ignore certificate errors; http: allow a secret over cleartext
};

// A named forwarding destination resolved from config.ini [destinations].
// The URL scheme determines the type: "file://" -> line append,
// "http(s)://" -> POST via the destination spool.
struct Destination {
    std::string name;
    std::string url;          // as configured (may carry ?format=... options)
    std::string scheme;       // "file", "http" or "https"
    std::string path;         // file path (file://) or the STRIPPED request URL (http)
    DestinationOptions opts;  // parsed from the URL query string
};

// Parse a destination URL into scheme + path + options (see
// DestinationOptions). Shared by config.ini parsing and the server-pushed
// destination overlay in AgentClient so both apply identical rules.
Destination parseDestinationUrl(const std::string& name, const std::string& url);

// The URL with every secret-bearing query value (token, secret, apikey)
// replaced by "***". Use this in any log line that prints a destination URL.
std::string redactedUrl(const std::string& url);

// Agent <-> management server settings.
struct ServerConfig {
    std::string url;                 // base URL of management server
    int         poll_interval_seconds = 30;
    std::string agent_id;             // unique agent identity
    // Enrollment token for machine auth . Minted
    // by the install script, sent as `Authorization: Bearer <token>` on every
    // request to the server. Empty for agents that haven't been re-enrolled
    // (backward-compat: the server allows legacy agents during the grace
    // period). Stored in config.ini under [server] auth_token.
    std::string auth_token;
};

// [collect] settings. Optional operator override for XPath subscription
// filtering. By default the agent auto-derives its channel subscriptions from
// the loaded rules (only subscribing to channels + EventIDs the rules
// reference). `channels` lets an operator force-subscribe to additional
// channels (with all events, i.e. "*") that no rule references, useful for
// a compliance channel the operator wants forwarded via a catch-all rule, or
// for debugging. Empty by default (pure auto-derivation).
struct CollectConfig {
    std::vector<std::string> channels;  // extra channels to always subscribe
};

// [logging] settings. Controls log verbosity, rotation, and (optionally)
// the log directory. The agent writes two files: elf_agent.log (everything
// at or above `level`) and error.log (ERROR only). When max_file_size_mb > 0
// the agent log is size-rotated, keeping `max_files` rotated copies. This
// keeps the log directory bounded for unattended service operation.
struct LoggingConfig {
    // Minimum severity to emit: "error", "notice", "info", or "debug".
    // Default "notice": startup banner, alerts, shutdown only.
    std::string level = "notice";
    // Rotate the agent log when it exceeds this many MB. 0 = no rotation.
    int max_file_size_mb = 1;
    // Number of rotated .1/.2/.N copies to keep (excluding the active file).
    // 0 = keep none. Default 3 (active + .1 + .2 + .3 = ~4MB max).
    int max_files = 3;
    // Optional override for the log directory. Empty = default
    // (%ProgramData%\ELFAgent\logs\).
    std::string directory;
};

// [spool] settings. The agent persists pending HTTP POSTs (alerts + forwarded
// logs) to a disk-backed spool so they survive a restart or network outage.
// When the server is unreachable, the spool grows up to max_spool_mb; beyond
// that, the OLDEST entries are evicted (dropped); the oldest events are the
// least valuable to an analyst. The worker retries with exponential backoff
// (1s→60s) so a transient outage recovers quickly without hammering the
// server.
struct SpoolConfig {
    // Max total spool size in MB. 0 = unbounded (not recommended for a
    // long-running service). Default 100MB.
    int max_spool_mb = 100;
    // Optional override for the spool directory. Empty = default
    // (%ProgramData%\ELFAgent\spool\).
    std::string directory;
};

// Global agent configuration parsed from config.ini.
struct Config {
    // [buffer]
    int retention_seconds = 30;
    // Hard cap on the number of events held in the in-memory buffer, even
    // when they're within the retention window. This bounds RAM on very
    // busy hosts (e.g. a DC generating thousands of Security events/sec).
    // 0 = unlimited (retention-only). Default 50000 (~150MB at ~3KB/event).
    size_t max_events = 50000;

    // [rules]
    std::string rules_directory = "rules";

    // [lists]
    std::string lists_directory = "lists";

    // [server]
    ServerConfig server;

    // [collect] (optional)
    CollectConfig collect;

    // [logging] (optional)
    LoggingConfig logging;

    // [spool] (optional)
    SpoolConfig spool;

    // Mirror forwarded logs to the management server (per-group toggle
    // pushed by the server via GET /config; alerts always mirror
    // regardless). Default: on. When false, the agent skips the POST
    // /logs batch for forwarded events but still reports alerts.
    bool mirror_logs = true;

    // [destinations] name -> Destination
    std::unordered_map<std::string, Destination> destinations;

    // Resolve a named destination; returns nullptr if not found.
    const Destination* resolveDestination(const std::string& name) const;
};

// Thread-safe config holder. Allows hot reload of settings pulled from the
// management server without restarting the agent.
class ConfigStore {
public:
    static ConfigStore& instance();

    // Load (or reload) config from a given INI file path. Returns true on success.
    bool load(const std::string& path);

    // Get a snapshot of the current config. Thread-safe.
    Config get() const;

    // Replace the current config atomically (used by AgentClient).
    void set(const Config& cfg);

private:
    ConfigStore() = default;
    mutable std::mutex m_mutex;
    Config m_config;
};

} // namespace elf
