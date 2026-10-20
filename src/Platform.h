#pragma once

// Operating-system services the agent needs, declared once and implemented
// per platform (src/platform/win, src/platform/linux). Everything above this
// layer (rule engine, buffer, forwarder, formats, server client) is plain
// C++17 and builds on both.

#include <ctime>
#include <functional>
#include <string>

namespace elf {

// --- Paths and environment ---

// Directory containing the running executable, with a trailing separator.
std::string platformExeDir();

// Writable state root for logs, spool, bookmarks and server-pushed rules
// (%ProgramData%\ELFAgent\ on Windows, /var/lib/elf/ on Linux). Created on
// first use. Trailing separator.
std::string platformDefaultDataDir();

// Value of an environment variable, or "" when unset.
std::string platformGetEnv(const std::string& name);

// Where config.ini is read from: next to the executable on Windows; on
// Linux $ELF_CONFIG, else config.ini next to the executable when present,
// else /etc/elf/config.ini.
std::string platformConfigPath();

// True for an absolute path on this platform (drive letter or UNC on
// Windows; a leading '/' everywhere).
bool platformIsAbsolutePath(const std::string& path);

// The path separator this platform writes ("\\" or "/"). Both accept '/',
// but generated paths shown to operators use the native form.
const char* platformPathSep();

// --- Host identity (reported to the console at registration) ---
std::string platformHostname();
std::string platformIpAddress();
std::string platformOsName();

// The Sigma logsource.product this agent evaluates: "windows" or "linux".
const char* platformSigmaProduct();

// --- Text and time ---

// UTF-16/32 (std::wstring) <-> UTF-8.
std::string wideToUtf8(const std::wstring& s);
std::wstring utf8ToWide(const std::string& s);

// Thread-safe gmtime/localtime, and the inverse of gmtime.
bool platformGmTime(std::time_t t, std::tm& out);
bool platformLocalTime(std::time_t t, std::tm& out);
std::time_t platformTimeGm(std::tm& tm);

// --- Process hooks ---

// Catch what the C++ runtime cannot (access violations, stack overflow,
// SIGSEGV...) and write a crash report through the logger before the
// process dies. Called once on the main thread.
void installCrashHandlers();

// Keep a console click from pausing output (Windows QuickEdit). No-op
// elsewhere.
void disableConsoleQuickEdit();

// --- On-demand historical collection ---

// Pull every event with a timestamp >= startTimeIsoUtc from the host's logs
// and hand each one, rendered in the agent's event XML form, to `cb`.
// Returns the number delivered.
size_t platformCollectHistory(const std::string& startTimeIsoUtc,
                              const std::function<void(const std::wstring& xml)>& cb);

} // namespace elf
