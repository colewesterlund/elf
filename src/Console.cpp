#include "Console.h"
#include <iostream>
#include <fstream>
#include <sstream>
#include <chrono>
#include <iomanip>
#include <atomic>
#include "Platform.h"
#include <csignal>
#include <cstdlib>
#include <filesystem>


namespace elf {

// Process-wide mutex serializing console output across all worker threads.
std::mutex g_consoleMutex;

// --- Level threshold + console suppression ---
//
// g_logLevel is the minimum severity to emit. Lines whose tier is below
// (numerically greater than) the threshold are dropped before any sink
// write. Default is Notice, the right default for an unattended service
// (startup banner, alerts, shutdown only). Operators who need more detail
// set level=info or level=debug in config.ini [logging].
//
// g_consoleSuppressed is set by the service entry point (svcMain) because
// services have no interactive console. When true, logNotice/logError skip
// std::cout/std::cerr entirely (they still go to the log files). This
// avoids wasted writes to a phantom console handle and prevents any chance
// of a stall if the service gets a console handle that blocks.
static std::atomic<LogLevel> g_logLevel{LogLevel::Notice};
static std::atomic<bool> g_consoleSuppressed{false};

void setLogLevel(LogLevel level) { g_logLevel.store(level); }
LogLevel getLogLevel() { return g_logLevel.load(); }
void suppressConsole() { g_consoleSuppressed.store(true); }


// --- Centralized logging ---
//
// Three sinks, each an ofstream kept alive for the whole process:
//   - g_agentLog, elf_agent.log: everything (DEBUG + INFO + NOTICE + ERROR).
//   - g_errorLog, error.log:     errors only (ERROR).
// The console is the third destination, gated by verbosity tier and the
// console-suppressed flag.
//
// Every line is prefixed with a timestamp "[YYYY-MM-DD HH:MM:SS] " so the
// log file and error.log are self-describing and sortable. The console
// gets the same prefix for consistency.
//
// We deliberately do NOT replace std::cout/std::cerr streambufs. A tee
// streambuf would capture everything but make it impossible to route
// per-line by verbosity; every std::cout line would hit the console.
// Instead the call sites use logDebug/logInfo/logNotice/logError, which
// write a complete line under the mutex and pick the sinks. The handful of
// raw std::cout/std::cerr sites (crash report, the pre-log startup banner)
// go to the console only, which is the right behavior for a crash that may
// have happened before the logs opened.
//
// --- Rotation ---
//
// When maxFileBytes > 0, the agent log is size-rotated: when a write would
// push the active file past the limit, the active file is closed, the
// existing .N files are shifted (.N -> .N+1, oldest dropped at maxFiles),
// the active file is renamed to .1, and a new active file is opened. This
// keeps the log directory bounded, critical for an unattended service on
// a long-running host where an unbounded log would eventually fill the
// disk. The error log is NOT rotated (it's expected to stay small; only
// errors land there). Rotation happens under the console mutex so two
// threads can't rotate simultaneously.

static std::ofstream* g_agentLog = nullptr;
static std::ofstream* g_errorLog = nullptr;
static std::string    g_agentLogPath;
static size_t          g_maxFileBytes = 0;   // 0 = no rotation
static size_t          g_maxFiles = 0;       // rotated files to keep
static size_t          g_agentLogSize = 0;  // current bytes written

// Build a "[YYYY-MM-DD HH:MM:SS] " prefix from the system clock. Kept
// simple and allocation-light since it runs on every log line.
static std::string timestampPrefix() {
    using namespace std::chrono;
    auto now = system_clock::now();
    auto t = system_clock::to_time_t(now);
    std::tm tm{};
    platformLocalTime(t, tm);
    std::ostringstream oss;
    oss << '[' << std::put_time(&tm, "%Y-%m-%d %H:%M:%S") << "] ";
    return oss.str();
}

// Rotate the agent log: shift .N -> .N+1 (dropping the oldest at maxFiles),
// rename the active file to .1, open a fresh active file. Called under
// g_consoleMutex. On any filesystem error we log to the console and keep
// going with the existing file (rotation is best-effort; losing the log
// would be worse than a slightly-too-big file).
static void rotateAgentLog() {
    if (!g_agentLog || g_agentLogPath.empty()) return;
    g_agentLog->close();
    // Shift .N -> .N+1 from oldest down so we don't clobber.
    for (size_t n = g_maxFiles; n >= 1; --n) {
        std::string src = g_agentLogPath + "." + std::to_string(n);
        std::string dst = g_agentLogPath + "." + std::to_string(n + 1);
        std::error_code ec;
        if (n + 1 > g_maxFiles) {
            std::filesystem::remove(dst, ec);   // drop the oldest
        }
        if (std::filesystem::exists(src, ec)) {
            std::filesystem::rename(src, dst, ec);
        }
    }
    // Active -> .1
    {
        std::error_code ec;
        std::filesystem::rename(g_agentLogPath, g_agentLogPath + ".1", ec);
    }
    // Open a fresh active file (append mode so a concurrent reader sees it).
    g_agentLog->open(g_agentLogPath, std::ios::out | std::ios::app);
    g_agentLogSize = 0;
    if (!g_agentLog->is_open()) {
        std::cerr << "[Console] Rotation failed to reopen agent log '"
                  << g_agentLogPath << "'." << std::endl;
    }
}

// Write one complete line (msg + '\n') to the chosen sinks, all under the
// console mutex so lines never interleave. `toConsole` gates the console
// (NOTICE/ERROR yes, INFO/DEBUG no) but is overridden if the console is
// suppressed (service mode). `toErrorLog` gates error.log (ERROR only).
// `level` is the line's severity; lines below the global threshold are
// dropped before any sink write.
static void writeLine(const std::string& msg, LogLevel level,
                      bool toConsole, bool toErrorLog) {
    if (static_cast<int>(level) > static_cast<int>(g_logLevel.load())) {
        return;  // below threshold: drop entirely
    }
    std::lock_guard<std::mutex> lock(g_consoleMutex);
    std::string line = timestampPrefix() + msg + "\n";
    if (toConsole && !g_consoleSuppressed.load()) {
        std::cout << line;
        std::cout.flush();
    }
    if (g_agentLog && g_agentLog->is_open()) {
        // Rotate before writing if this line would exceed the limit.
        if (g_maxFileBytes > 0 &&
            g_agentLogSize + line.size() > g_maxFileBytes) {
            rotateAgentLog();
        }
        (*g_agentLog) << line;
        g_agentLog->flush();
        g_agentLogSize += line.size();
    }
    if (toErrorLog && g_errorLog && g_errorLog->is_open()) {
        (*g_errorLog) << line;
        g_errorLog->flush();
    }
}

void logDebug(const std::string& msg) {
    // DEBUG: agent log only, only if threshold is Debug. Verbose diagnostics.
    writeLine(msg, LogLevel::Debug, /*toConsole*/ false, /*toErrorLog*/ false);
}

void logInfo(const std::string& msg) {
    // INFO: agent log only. NOT the console. This is the tier for routine
    // per-rule load messages, status ticks, reload notices, etc., the
    // stuff that flooded the console before.
    writeLine(msg, LogLevel::Info, /*toConsole*/ false, /*toErrorLog*/ false);
}

void logNotice(const std::string& msg) {
    // NOTICE: agent log + console. Reserved for the few lines the operator
    // should see live: startup banner, active rule count, alerts.
    writeLine(msg, LogLevel::Notice, /*toConsole*/ true, /*toErrorLog*/ false);
}

void logError(const std::string& msg) {
    // ERROR: agent log + error.log + console. Failures the operator needs
    // to see: rule load exceptions, unknown modifiers, POST failures,
    // crashes.
    writeLine(msg, LogLevel::Error, /*toConsole*/ true, /*toErrorLog*/ true);
}

bool openLogFiles(const std::string& agentLogPath,
                  const std::string& errorLogPath,
                  size_t maxFileBytes,
                  size_t maxFiles) {
    // Close and delete any previously-opened log streams. This is
    // essential when openLogFiles is called more than once (e.g., in
    // tests, or if the config is reloaded): without this, the old
    // ofstream pointers are leaked and their file handles stay open
    // even after the underlying files/directories are deleted, which
    // can cause filesystem-level errors on subsequent rotations.
    if (g_agentLog) {
        g_agentLog->close();
        delete g_agentLog;
        g_agentLog = nullptr;
    }
    if (g_errorLog) {
        g_errorLog->close();
        delete g_errorLog;
        g_errorLog = nullptr;
    }

    g_agentLogPath = agentLogPath;
    g_maxFileBytes = maxFileBytes;
    g_maxFiles = maxFiles;
    g_agentLogSize = 0;

    // Append mode so a restart continues the same log (rotation handles
    // size bounds). Legacy behavior (maxFileBytes==0) used trunc mode; we
    // keep append for rotation and also for the no-rotation case so a
    // service restart doesn't wipe the history.
    auto* agent = new std::ofstream(agentLogPath, std::ios::out | std::ios::app);
    auto* err = new std::ofstream(errorLogPath, std::ios::out | std::ios::app);
    if (!agent->is_open()) {
        std::cerr << "[Console] Could not open agent log '" << agentLogPath
                  << "' for writing." << std::endl;
        delete agent;
        agent = nullptr;
    } else {
        // Seed the size counter from the existing file so rotation is
        // accurate across restarts.
        std::error_code ec;
        auto sz = std::filesystem::file_size(agentLogPath, ec);
        if (!ec) g_agentLogSize = static_cast<size_t>(sz);
    }
    if (!err->is_open()) {
        std::cerr << "[Console] Could not open error log '" << errorLogPath
                  << "' for writing." << std::endl;
        delete err;
        err = nullptr;
    }
    g_agentLog = agent;
    g_errorLog = err;
    return g_agentLog != nullptr;
}

// --- Crash handlers ---
//
// Two failure modes need to be caught so the cause lands in the log before
// the process disappears:
//   1. An uncaught C++ exception -> std::terminate -> set_terminate handler.
//   2. A fault the runtime cannot catch (access violation, SIGSEGV)
//      -> the platform's handler in installCrashHandlers (Platform.h).
// Both write a report under the console mutex and flush the log, then let
// the process die.


void writeCrashReport(const std::string& kind, const std::string& detail) {
    // A crash is the most severe error: route to all sinks (console +
    // agent log + error log) with a timestamp, under the mutex.
    std::ostringstream oss;
    oss << "\n========== AGENT CRASH ==========\n"
        << "Kind:   " << kind << "\n"
        << "Detail: " << detail << "\n"
        << "=================================";
    logError(oss.str());
}


static void terminateHandler() {
    std::string detail = "unknown";
    try {
        if (std::current_exception()) {
            std::rethrow_exception(std::current_exception());
        }
    } catch (const std::exception& e) {
        detail = std::string(typeid(e).name()) + ": " + e.what();
    } catch (...) {
        detail = "non-std exception";
    }
    writeCrashReport("std::terminate (uncaught exception)", detail);
}



void installThreadCrashHandlers() {
    std::set_terminate(terminateHandler);
}

void runGuarded(const char* threadName, const std::function<void()>& body) {
    installThreadCrashHandlers();
    try {
        body();
    } catch (const std::exception& e) {
        writeCrashReport(std::string("Uncaught exception on thread '") +
                         threadName + "'",
                         std::string(typeid(e).name()) + ": " + e.what());
        std::_Exit(3);
    } catch (...) {
        writeCrashReport(std::string("Uncaught exception on thread '") +
                         threadName + "'", "non-std exception");
        std::_Exit(3);
    }
}

} // namespace elf
