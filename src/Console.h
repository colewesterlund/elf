#pragma once

#include <functional>
#include <mutex>
#include <string>

namespace elf {

// A process-wide mutex serializing writes to std::cout/std::cerr so the
// agent's many worker threads (rule engine, reload, poll, status, async
// POST worker) don't interleave their log lines. Without this, two threads
// writing at the same time produce garbled output like:
//   [FORWARD][YamlRuleLoader] Loaded rule: ...
//    Rule fired: ...
// which is confusing and can hide real errors.
//
// Usage: acquire the lock, write the whole line, then flush. The Console::log
// helpers do this in one call.
extern std::mutex g_consoleMutex;

// Log severity tiers. The threshold is set once at startup via
// setLogLevel(); lines below the threshold are dropped before they reach
// any sink. Default is Notice so a freshly installed service logs only
// the startup banner, active rule count, alerts, and shutdown, keeping
// the log file small for unattended operation. Operators who need more
// detail set level=info (or debug) in config.ini [logging].
enum class LogLevel {
    Error   = 0,   // always logged
    Notice  = 1,   // default threshold
    Info    = 2,   // routine per-rule load, status ticks, reloads
    Debug   = 3,   // verbose diagnostics (HTTP bodies, XPath, etc.)
};

// Set the process-wide minimum severity to emit. Call once at startup,
// before any worker threads begin. Thread-safe.
void setLogLevel(LogLevel level);

// Get the current threshold.
LogLevel getLogLevel();

// Suppress console output entirely. Called by the service entry point
// (svcMain) because services have no interactive console; writing to the
// (non-existent) console is harmless but wasteful, and on some Windows
// builds the service gets a phantom console handle that can stall writes.
// After this call, logNotice/logError still go to the log files but skip
// std::cout/std::cerr. Thread-safe.
void suppressConsole();

// Thread-safe line writers. Each writes the message + a newline under the
// console mutex so lines from different threads never interleave. These
// route through the logging system (timestamps + file sinks + level
// filtering); prefer them over raw std::cout/std::cerr in new code.
//
// Verbosity tiers control where a line goes AND whether it's emitted at
// all (relative to the global threshold):
//   - DEBUG:   elf_agent.log only. Verbose diagnostics. Off by default.
//   - INFO:    elf_agent.log only (NOT the console). Use for routine
//              per-rule load messages, status, etc.
//   - NOTICE:  elf_agent.log + console. Use for the handful of lines the
//              operator should see live (startup banner, active rule
//              count, alerts).
//   - ERROR:   elf_agent.log + error.log + console. Use for failures the
//              operator needs to see (rule load exceptions, unknown
//              modifiers, POST failures, crashes).
void logDebug(const std::string& msg);    // DEBUG: log only (if enabled)
void logInfo(const std::string& msg);     // INFO: log only
void logNotice(const std::string& msg);  // NOTICE: log + console
void logError(const std::string& msg);   // ERROR: log + error.log + console

// Open the log sinks. Call once at startup, before any worker threads begin.
//   agentLogPath: full path to elf_agent.log (everything, timestamped).
//   errorLogPath: full path to error.log (errors only, timestamped).
//   maxFileBytes: rotate the agent log when it exceeds this size; 0 = no
//                  rotation (truncate on open).
//   maxFiles:     number of rotated .1/.2/.N files to keep (excluding the
//                  active file). 0 = keep none (just the active file).
// Returns true if at least the agent log opened; false (with a console
// message) if neither file could be created, in which case output still
// goes to the console only.
bool openLogFiles(const std::string& agentLogPath,
                  const std::string& errorLogPath,
                  size_t maxFileBytes = 0,
                  size_t maxFiles = 0);

// Install the per-thread half of the crash handlers on the CALLING thread.
// MSVC keeps the std::terminate handler per thread, so installCrashHandlers
// (called on the main thread) does not cover worker threads: an uncaught
// exception on a worker fell through to the CRT's default abort() and the
// log showed "SIGABRT, Detail: (empty)" with no exception type or message.
// The SEH filter is process-wide and needs no per-thread install.
void installThreadCrashHandlers();

// Write a crash report through every sink. Used by the platform crash
// handlers (Platform.h) and by runGuarded.
void writeCrashReport(const std::string& kind, const std::string& detail);

// Run `body` as the whole of a worker thread: installs the per-thread
// crash handlers, then catches anything the body throws, writes a crash
// report naming the thread and the exception (type + what()), and exits
// the process with code 3. Exiting is deliberate: a worker that silently
// died (e.g. the rule engine thread) would leave the service "running"
// but detecting nothing forever, whereas a process exit triggers the SCM
// recovery restart and the agent resumes from its saved bookmarks.
void runGuarded(const char* threadName, const std::function<void()>& body);

} // namespace elf
