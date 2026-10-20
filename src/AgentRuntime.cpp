#include "AgentRuntime.h"
#include "AgentClient.h"
#include "Config.h"
#include "Console.h"
#include "EventBuffer.h"
#include "EventSource.h"
#include "Forwarder.h"
#include "Platform.h"
#include "RuleEngine.h"
#include "YamlRuleLoader.h"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <filesystem>
#include <thread>

namespace elf {

// --- StopSignal ---

void StopSignal::request() {
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_requested = true;
    }
    m_cv.notify_all();
}

void StopSignal::wait() {
    std::unique_lock<std::mutex> lock(m_mutex);
    while (!m_requested && !m_fromSignal.load(std::memory_order_relaxed)) {
        m_cv.wait_for(lock, std::chrono::milliseconds(250));
    }
}

bool StopSignal::requested() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_requested || m_fromSignal.load(std::memory_order_relaxed);
}

// Worker threads poll this once a second; the stop handler clears it.
static std::atomic<bool> g_running{true};

bool agentRunning() { return g_running.load(); }

// --- Subscription filters ---

// The filters the collector should apply, from the engine's analysis of the
// loaded rules plus any operator-configured extra channels ([collect]
// channels, always unfiltered). Empty when a catch-all rule is present: the
// caller subscribes to everything instead.
static std::vector<SourceFilter> buildFilters(const RuleEngine& engine, const Config& cfg) {
    auto derived = engine.deriveChannelQueries();
    if (derived.empty()) return {};
    std::vector<SourceFilter> filters;
    for (const auto& [channel, ids] : derived) {
        filters.push_back({channel, ids});
    }
    for (const auto& ch : cfg.collect.channels) {
        filters.push_back({ch, {}});
    }
    return filters;
}

// Re-derive the subscription filters and re-subscribe the source after a
// ruleset change. With zero rules loaded the source is stopped: there is
// nothing to evaluate or forward, so buffering events would only use RAM,
// and a fresh install would otherwise accumulate a backlog to dump when the
// first forward_buffer rule arrives.
static void resubscribeSource(RuleEngine& engine, EventSource& source,
                              GrowthMonitor& growth, const Config& cfg) {
    if (engine.ruleCount() == 0) {
        logInfo("[Reload] No rules loaded; stopping event subscriptions.");
        source.resubscribe({});
        growth.setChannels({});
        return;
    }
    auto filters = buildFilters(engine, cfg);
    if (filters.empty()) {
        if (source.isSubscribedToAll()) {
            logInfo("[Reload] Catch-all rules present; already subscribed to all channels.");
        } else {
            logInfo("[Reload] Catch-all rules present; subscribing to all channels.");
            source.resubscribe({});
            source.subscribeAll();
        }
    } else {
        source.resubscribe(filters);
    }
    // The growth monitor measures the same channels the source watches, so
    // "generated on watched channels" and "forwarded" describe one set.
    growth.setChannels(source.subscribedChannels());
}

// --- Worker threads ---

// Drop events older than retention_seconds and enforce the max_events cap.
static void bufferCleanupThread(EventBuffer& buffer) {
    while (g_running) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
        if (!g_running) break;
        auto cfg = ConfigStore::instance().get();
        buffer.cleanup(cfg.retention_seconds);
        buffer.trimTo(cfg.max_events);
    }
}

// Buffer depth to the agent log every 5 s, plus a NOTICE whenever a silent
// loss counter moved (events evicted before evaluation, render failures,
// subscription errors). Also flushes the forward_event batch so a crash
// loses at most 5 s of forwarded events.
static void statusThread(EventBuffer& buffer, EventSource& source, AgentClient& agentClient) {
    size_t last = 0;
    uint64_t lastEvicted = 0, lastRender = 0, lastSubErr = 0;
    while (g_running) {
        for (int i = 0; i < 5 && g_running; ++i) {
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
        if (!g_running) break;
        agentClient.flushPendingLogs();
        size_t cur = buffer.size();
        logInfo("[STATUS] Buffered events: " + std::to_string(cur) +
                (cur > last ? " (+new)" : ""));
        last = cur;
        uint64_t evicted = buffer.evictedUnevaluated();
        uint64_t render = source.renderFailures();
        uint64_t subErr = source.subscribeErrors();
        if (evicted > lastEvicted || render > lastRender || subErr > lastSubErr) {
            logNotice("[STATUS] WARNING: events evicted before evaluation +" +
                      std::to_string(evicted - lastEvicted) +
                      ", render failures +" + std::to_string(render - lastRender) +
                      ", subscription errors +" + std::to_string(subErr - lastSubErr) +
                      " (totals " + std::to_string(evicted) + "/" +
                      std::to_string(render) + "/" + std::to_string(subErr) + ")");
            lastEvicted = evicted;
            lastRender = render;
            lastSubErr = subErr;
        }
    }
}

// Persist the read position every 30 s (the final flush happens on
// shutdown). A crash between saves re-delivers at most 30 s of events on
// the next start; the server deduplicates them.
static void positionSaveThread(EventSource& source) {
    while (g_running) {
        for (int i = 0; i < 30 && g_running; ++i) {
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
        if (!g_running) break;
        source.savePosition();
    }
}

static void ruleEngineThread(RuleEngine& engine) {
    while (g_running) {
        for (int i = 0; i < 2 && g_running; ++i) {
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
        if (!g_running) break;
        engine.evaluateOnce();
    }
}

// FNV-1a over the sorted (name, size, mtime) of every rule and list file. A
// reload is only worth doing when this changes.
static uint64_t dirFingerprint(const std::string& rulesDir, const std::string& listsDir) {
    std::vector<std::string> entries;
    for (const std::string& dir : {rulesDir, listsDir}) {
        if (dir.empty()) continue;
        std::error_code ec;
        for (auto& e : std::filesystem::directory_iterator(dir, ec)) {
            std::error_code fe;
            if (!e.is_regular_file(fe)) continue;
            auto mtime = e.last_write_time(fe).time_since_epoch().count();
            auto size = e.file_size(fe);
            entries.push_back(e.path().filename().string() + "|" +
                              std::to_string(size) + "|" + std::to_string(mtime));
        }
    }
    std::sort(entries.begin(), entries.end());
    uint64_t h = 1469598103934665603ULL;
    for (const auto& s : entries) {
        for (unsigned char c : s) { h ^= c; h *= 1099511628211ULL; }
        h ^= '\n'; h *= 1099511628211ULL;
    }
    return h;
}

// Fingerprint of the on-disk ruleset the engine currently runs, set by
// whichever path last loaded it so the disk watcher can tell "unchanged"
// from "edited by hand".
static std::atomic<uint64_t> g_rulesFingerprint{0};

// Swap a LoadSummary into the engine unless nothing could be read.
static bool applyLoadedRules(RuleEngine& engine, const LoadSummary& s, const char* who) {
    if (!s.applicable()) {
        logError(std::string("[") + who + "] Ruleset not applied: " +
                 (s.dirMissing ? "rules directory missing"
                               : "no rule parsed and " + std::to_string(s.failed) +
                                 " failed") + "; keeping current rules.");
        return false;
    }
    engine.reload(s.rules);
    logInfo(std::string("[") + who + "] Ruleset refreshed: " +
            std::to_string(s.rules.size()) + " rule(s) active" +
            (s.failed ? " (" + std::to_string(s.failed) + " file(s) skipped)" : "") + ".");
    return true;
}

// Reload rules from disk when a file changed (hand edits); the server poll
// records its own loads so it does not repeat them.
static void ruleReloadThread(RuleEngine& engine, EventSource& source, GrowthMonitor& growth,
                             const std::string& rulesDir, const std::string& listsDir) {
    while (g_running) {
        for (int i = 0; i < 60 && g_running; ++i) {
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
        if (!g_running) break;
        uint64_t fp = dirFingerprint(rulesDir, listsDir);
        if (fp == g_rulesFingerprint.load()) continue;
        LoadSummary s = loadRules(rulesDir, listsDir);
        if (!applyLoadedRules(engine, s, "Reload")) continue;
        g_rulesFingerprint.store(fp);
        resubscribeSource(engine, source, growth, ConfigStore::instance().get());
    }
}

// Average rendered bytes per delivered event, for estimating the byte cost
// of generated events the pre-filter never delivered.
static uint64_t defaultAvgBytesPerEvent(EventBuffer& buffer) {
    if (buffer.eventsCreated() > 0) {
        uint64_t avg = buffer.bytesCreated() / buffer.eventsCreated();
        return avg == 0 ? 1 : avg;
    }
    return 1500;
}

// Poll the server for config and rules, reporting the growth counters.
// The first measurement only baselines each channel, so the counters are
// consistent from the first poll on.
static void agentPollThread(AgentClient& client, EventBuffer& buffer, GrowthMonitor& growth) {
    {
        growth.measure(defaultAvgBytesPerEvent(buffer));
        client.poll(growth.totalEvents(), growth.totalBytes());
    }
    while (g_running) {
        int interval = ConfigStore::instance().get().server.poll_interval_seconds;
        if (interval < 5) interval = 5;
        for (int i = 0; i < interval && g_running; ++i) {
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
        if (!g_running) break;
        growth.measure(defaultAvgBytesPerEvent(buffer));
        client.poll(growth.totalEvents(), growth.totalBytes());
    }
}

// --- runAgent ---

int runAgent(StopSignal& stop, const std::function<void()>& reportRunning) {
    g_running = true;
    installCrashHandlers();
    disableConsoleQuickEdit();

    // Logs open with defaults first so a bad config.ini still produces a
    // line about it, then re-open with the configured level/rotation.
    const char* sep = platformPathSep();
    std::string dataDir = platformDefaultDataDir();
    setDataRootDir(dataDir);
    std::string defaultLogDir = dataDir + "logs" + sep;
    std::error_code ec;
    std::filesystem::create_directories(defaultLogDir, ec);
    std::string logPath = defaultLogDir + "elf_agent.log";
    std::string errLogPath = defaultLogDir + "error.log";
    bool logOk = openLogFiles(logPath, errLogPath, 0, 0);
    logNotice("=== Efficient Log Forwarder starting ===");
    logNotice("  Log file: " + logPath + (logOk ? " (active)" : " (FAILED to open; console only)"));
    logNotice("  Error log: " + errLogPath);
    logInfo("  Build: " + std::string(__DATE__) + " " + __TIME__);
    logInfo("  Working dir: " + std::filesystem::current_path().string());
    logInfo("  Exe dir: " + platformExeDir());
    logInfo("  Data dir: " + dataDir);

    // config.ini is the read-only bootstrap (next to the executable, or
    // /etc/elf on Linux); server-pushed rules and lists go to the writable
    // data dir.
    std::string configPath = platformConfigPath();
    if (!ConfigStore::instance().load(configPath)) {
        logError("Failed to load config.ini from " + configPath);
        return 1;
    }
    Config cfg = ConfigStore::instance().get();

    {
        const std::string& lvl = cfg.logging.level;
        if (lvl == "error")       setLogLevel(LogLevel::Error);
        else if (lvl == "notice") setLogLevel(LogLevel::Notice);
        else if (lvl == "info")   setLogLevel(LogLevel::Info);
        else if (lvl == "debug")  setLogLevel(LogLevel::Debug);
        else if (!lvl.empty()) {
            logError("[Config] Unknown logging.level '" + lvl + "'; defaulting to notice.");
            setLogLevel(LogLevel::Notice);
        }
    }
    if (!cfg.logging.directory.empty() && cfg.logging.directory != defaultLogDir) {
        std::string newLogDir = cfg.logging.directory;
        if (newLogDir.back() != '\\' && newLogDir.back() != '/') newLogDir += sep;
        std::filesystem::create_directories(newLogDir, ec);
        logPath = newLogDir + "elf_agent.log";
        errLogPath = newLogDir + "error.log";
        size_t maxBytes = cfg.logging.max_file_size_mb > 0
            ? static_cast<size_t>(cfg.logging.max_file_size_mb) * 1024 * 1024 : 0;
        logOk = openLogFiles(logPath, errLogPath, maxBytes,
                             static_cast<size_t>(cfg.logging.max_files));
        logNotice("[Config] Log directory override: " + newLogDir);
        logNotice("  Log file: " + logPath + (logOk ? " (active)" : " (FAILED to open; console only)"));
        logNotice("  Error log: " + errLogPath);
    } else if (cfg.logging.max_file_size_mb > 0) {
        size_t maxBytes = static_cast<size_t>(cfg.logging.max_file_size_mb) * 1024 * 1024;
        logOk = openLogFiles(logPath, errLogPath, maxBytes,
                             static_cast<size_t>(cfg.logging.max_files));
    }
    logInfo("[Config] Logging level: " + cfg.logging.level +
            ", max_file_size_mb: " + std::to_string(cfg.logging.max_file_size_mb) +
            ", max_files: " + std::to_string(cfg.logging.max_files));
    logInfo("Efficient Log Forwarder config:");
    logInfo("  Retention: " + std::to_string(cfg.retention_seconds) + "s");
    logInfo("  Rules dir: " + cfg.rules_directory);
    logInfo("  Lists dir: " + cfg.lists_directory);
    logInfo("  Destinations: " + std::to_string(cfg.destinations.size()));
    for (const auto& [name, dest] : cfg.destinations) {
        logInfo("    " + name + " -> " + redactedUrl(dest.url));
    }
    logInfo("  Server: " + cfg.server.url);
    logInfo("  Agent ID: " + cfg.server.agent_id);
    logInfo("  Poll interval: " + std::to_string(cfg.server.poll_interval_seconds) + "s");

    // Mark the service started before the slow subscription phase (several
    // hundred channels can take longer than a service manager's timeout).
    if (reportRunning) reportRunning();

    EventBuffer buffer;
    Forwarder forwarder;
    forwarder.setConfig(cfg);
    RuleEngine engine(buffer, forwarder);

    AgentClient agentClient;
    agentClient.init(cfg);
    {
        std::string spoolDir = cfg.spool.directory.empty()
                ? (dataDir + "spool" + sep) : cfg.spool.directory;
        std::error_code spoolEc;
        std::filesystem::create_directories(spoolDir, spoolEc);
        size_t maxBytes = (cfg.spool.max_spool_mb > 0)
                ? (static_cast<size_t>(cfg.spool.max_spool_mb) * 1024 * 1024)
                : (100ull * 1024 * 1024);
        agentClient.initSpool(spoolDir, maxBytes);
        // SIEM destinations get their own spool and sender so a dead SIEM
        // never blocks server alerts, or the reverse.
        forwarder.initDestinationSpool(spoolDir + "destinations" + sep, maxBytes);
        logInfo("[Startup] Spool dir: " + spoolDir +
                "  cap=" + std::to_string(cfg.spool.max_spool_mb) + "MB");
    }
    agentClient.setApplyConfig([&forwarder](const Config& newCfg) {
        forwarder.setConfig(newCfg);
    });
    // The server path reloads the engine here and resubscribes through the
    // separate callback below, so each ruleset change rebuilds the
    // subscriptions exactly once.
    agentClient.setReloadRules([&engine, &cfg]() {
        LoadSummary s = loadRules(cfg.rules_directory, cfg.lists_directory);
        if (applyLoadedRules(engine, s, "AgentClient")) {
            g_rulesFingerprint.store(dirFingerprint(cfg.rules_directory, cfg.lists_directory));
        }
    });
    forwarder.setAgentClient(&agentClient);

    logInfo("[Startup] Loading rules from " + cfg.rules_directory +
            " (lists: " + cfg.lists_directory + ")...");
    auto rules = loadRulesFromDirectory(cfg.rules_directory, cfg.lists_directory);
    logNotice("[Startup] Active rules: " + std::to_string(rules.size()));
    engine.reload(rules);
    g_rulesFingerprint.store(dirFingerprint(cfg.rules_directory, cfg.lists_directory));

    // Collection. With no rules loaded (first install before the first
    // poll) nothing is subscribed; the poll's resubscribe starts it.
    auto source = makeEventSource(buffer, dataDir + "state" + sep + "bookmarks" + sep);
    auto growth = makeGrowthMonitor();
    {
        auto filters = buildFilters(engine, cfg);
        if (engine.ruleCount() == 0) {
            logNotice("[Startup] No rules loaded; deferring event subscription "
                      "until the server delivers a ruleset.");
        } else if (filters.empty()) {
            logInfo("[Startup] Subscribing to all channels (catch-all rules present).");
            source->subscribeAll();
        } else {
            logInfo("[Startup] Subscribing with filtering to " +
                    std::to_string(filters.size()) + " channel(s).");
            source->subscribe(filters);
        }
        growth->setChannels(source->subscribedChannels());
    }
    EventSource& src = *source;
    GrowthMonitor& grw = *growth;
    agentClient.setResubscribe([&engine, &src, &grw]() {
        resubscribeSource(engine, src, grw, ConfigStore::instance().get());
    });

    // Every thread runs under runGuarded so an escaping exception becomes a
    // crash report naming the thread, then a process exit the service
    // manager restarts.
    std::thread cleanup([&] { runGuarded("buffer-cleanup", [&] { bufferCleanupThread(buffer); }); });
    std::thread status([&] { runGuarded("status", [&] { statusThread(buffer, src, agentClient); }); });
    std::thread engineThread([&] { runGuarded("rule-engine", [&] { ruleEngineThread(engine); }); });
    std::thread reloadThread([&] {
        runGuarded("rule-reload", [&] {
            ruleReloadThread(engine, src, grw, cfg.rules_directory, cfg.lists_directory);
        });
    });
    std::thread pollThread([&] { runGuarded("server-poll", [&] { agentPollThread(agentClient, buffer, grw); }); });
    std::thread positionThread([&] { runGuarded("position-save", [&] { positionSaveThread(src); }); });

    logNotice("Agent running.");
    stop.wait();
    g_running = false;

    logNotice("Shutting down...");
    src.stop();
    src.savePosition();
    cleanup.join();
    status.join();
    engineThread.join();
    reloadThread.join();
    pollThread.join();
    positionThread.join();
    logNotice("Agent stopped cleanly.");
    return 0;
}

} // namespace elf
