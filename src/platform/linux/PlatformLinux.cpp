// Linux implementation of Platform.h.
#include "Platform.h"
#include "Console.h"
#include "JournalEvent.h"

#include <systemd/sd-journal.h>

#include <arpa/inet.h>
#include <csignal>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <netinet/in.h>
#include <sstream>
#include <sys/socket.h>
#include <sys/utsname.h>
#include <unistd.h>
#include <vector>

namespace elf {

// --- Paths and environment ---

std::string platformExeDir() {
    std::error_code ec;
    auto p = std::filesystem::read_symlink("/proc/self/exe", ec);
    if (ec) return "";
    return p.parent_path().string() + "/";
}

// $ELF_DATA_DIR, else /var/lib/elf/ when the account can write there (the
// systemd unit grants it), else ~/.elf/ for --debug runs as a normal user.
// The tree holds spool records with destination credentials, so it is
// private to the owner. Never a shared directory such as /tmp.
std::string platformDefaultDataDir() {
    std::string env = platformGetEnv("ELF_DATA_DIR");
    std::string p = env.empty() ? "/var/lib/elf/" : env;
    if (p.back() != '/') p += '/';
    std::error_code ec;
    std::filesystem::create_directories(p, ec);
    if (!ec && access(p.c_str(), W_OK) == 0) {
        std::filesystem::permissions(p, std::filesystem::perms::owner_all,
                                     std::filesystem::perm_options::replace, ec);
        return p;
    }
    std::string home = platformGetEnv("HOME");
    if (home.empty()) {
        logError("[Platform] Data directory " + p + " is not writable and HOME is unset; "
                 "state will fail to persist.");
        return p;
    }
    std::string fallback = home + "/.elf/";
    logNotice("[Platform] Data directory " + p + " is not writable; using " + fallback);
    std::filesystem::create_directories(fallback, ec);
    std::filesystem::permissions(fallback, std::filesystem::perms::owner_all,
                                 std::filesystem::perm_options::replace, ec);
    return fallback;
}

std::string platformGetEnv(const std::string& name) {
    const char* v = std::getenv(name.c_str());
    return v ? std::string(v) : std::string();
}

std::string platformConfigPath() {
    std::string env = platformGetEnv("ELF_CONFIG");
    if (!env.empty()) return env;
    std::string local = platformExeDir() + "config.ini";
    std::error_code ec;
    if (std::filesystem::is_regular_file(local, ec)) return local;
    return "/etc/elf/config.ini";
}

bool platformIsAbsolutePath(const std::string& path) {
    return !path.empty() && path[0] == '/';
}

const char* platformPathSep() { return "/"; }

// --- Host identity ---

std::string platformHostname() {
    char buf[256] = {0};
    if (gethostname(buf, sizeof(buf) - 1) == 0 && buf[0]) return buf;
    return "unknown-host";
}

// The address the host would use to reach a public destination: a UDP
// "connect" selects the outbound interface without sending a packet.
std::string platformIpAddress() {
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0) return "unknown";
    std::string result = "unknown";
    sockaddr_in target = {};
    target.sin_family = AF_INET;
    target.sin_port = htons(53);
    inet_pton(AF_INET, "8.8.8.8", &target.sin_addr);
    if (connect(s, reinterpret_cast<sockaddr*>(&target), sizeof(target)) == 0) {
        sockaddr_in local = {};
        socklen_t len = sizeof(local);
        if (getsockname(s, reinterpret_cast<sockaddr*>(&local), &len) == 0) {
            char ip[INET_ADDRSTRLEN] = {0};
            if (inet_ntop(AF_INET, &local.sin_addr, ip, sizeof(ip))) result = ip;
        }
    }
    close(s);
    return result;
}

// "PRETTY_NAME" from os-release plus the kernel release.
std::string platformOsName() {
    std::string name;
    std::ifstream f("/etc/os-release");
    std::string line;
    while (std::getline(f, line)) {
        if (line.rfind("PRETTY_NAME=", 0) == 0) {
            name = line.substr(12);
            if (name.size() >= 2 && name.front() == '"' && name.back() == '"')
                name = name.substr(1, name.size() - 2);
            break;
        }
    }
    utsname u = {};
    if (uname(&u) == 0) {
        if (name.empty()) name = u.sysname;
        name += std::string(" (kernel ") + u.release + ")";
    }
    return name.empty() ? "Linux" : name;
}

const char* platformSigmaProduct() { return "linux"; }

// --- Text and time ---
// wchar_t is UTF-32 on Linux.

// Both directions substitute U+FFFD for anything that is not a scalar
// value (surrogates, code points past U+10FFFF, overlong or truncated
// sequences), as WideCharToMultiByte does on Windows, so the core never
// sees invalid UTF-8.
std::string wideToUtf8(const std::wstring& s) {
    std::string out;
    out.reserve(s.size());
    for (wchar_t wc : s) {
        uint32_t c = static_cast<uint32_t>(wc);
        if (c > 0x10FFFF || (c >= 0xD800 && c <= 0xDFFF)) c = 0xFFFD;
        if (c < 0x80) out += static_cast<char>(c);
        else if (c < 0x800) {
            out += static_cast<char>(0xC0 | (c >> 6));
            out += static_cast<char>(0x80 | (c & 0x3F));
        } else if (c < 0x10000) {
            out += static_cast<char>(0xE0 | (c >> 12));
            out += static_cast<char>(0x80 | ((c >> 6) & 0x3F));
            out += static_cast<char>(0x80 | (c & 0x3F));
        } else {
            out += static_cast<char>(0xF0 | (c >> 18));
            out += static_cast<char>(0x80 | ((c >> 12) & 0x3F));
            out += static_cast<char>(0x80 | ((c >> 6) & 0x3F));
            out += static_cast<char>(0x80 | (c & 0x3F));
        }
    }
    return out;
}

std::wstring utf8ToWide(const std::string& s) {
    std::wstring out;
    out.reserve(s.size());
    size_t i = 0;
    while (i < s.size()) {
        unsigned char b = static_cast<unsigned char>(s[i]);
        uint32_t c; size_t n; uint32_t minimum;
        if (b < 0x80) { c = b; n = 1; minimum = 0; }
        else if (b >= 0xC2 && b <= 0xDF) { c = b & 0x1F; n = 2; minimum = 0x80; }
        else if ((b & 0xF0) == 0xE0) { c = b & 0x0F; n = 3; minimum = 0x800; }
        else if (b >= 0xF0 && b <= 0xF4) { c = b & 0x07; n = 4; minimum = 0x10000; }
        else { out += static_cast<wchar_t>(0xFFFD); ++i; continue; }   // C0, C1, F5..FF
        if (i + n > s.size()) { out += static_cast<wchar_t>(0xFFFD); break; }   // truncated at the end
        bool ok = true;
        for (size_t k = 1; k < n; ++k) {
            unsigned char cb = static_cast<unsigned char>(s[i + k]);
            if ((cb & 0xC0) != 0x80) { ok = false; n = k; break; }
            c = (c << 6) | (cb & 0x3F);
        }
        if (!ok || c < minimum || c > 0x10FFFF || (c >= 0xD800 && c <= 0xDFFF)) c = 0xFFFD;
        out += static_cast<wchar_t>(c);
        i += n;
    }
    return out;
}

bool platformGmTime(std::time_t t, std::tm& out) { return gmtime_r(&t, &out) != nullptr; }
bool platformLocalTime(std::time_t t, std::tm& out) { return localtime_r(&t, &out) != nullptr; }
std::time_t platformTimeGm(std::tm& tm) { return timegm(&tm); }

// --- Process hooks ---

// The report goes through the normal logger, which locks and allocates:
// not signal-safe, but the only way to get the crash into the agent log.
// Three guards keep a bad case from hanging the process instead of
// ending it: the default disposition is restored first (a second fault
// kills the process), a re-entered handler exits at once, and alarm()
// ends the process if the report blocks on a lock the faulting thread
// already holds. Either way the service manager sees an exit and
// restarts the agent.
static volatile std::sig_atomic_t g_inCrashHandler = 0;

static void fatalSignalHandler(int sig) {
    for (int s : {SIGSEGV, SIGBUS, SIGFPE, SIGILL, SIGABRT}) std::signal(s, SIG_DFL);
    if (g_inCrashHandler) std::_Exit(3);
    g_inCrashHandler = 1;
    alarm(5);
    const char* name = sig == SIGSEGV ? "SIGSEGV" : sig == SIGBUS ? "SIGBUS"
                     : sig == SIGFPE ? "SIGFPE" : sig == SIGILL ? "SIGILL"
                     : sig == SIGABRT ? "SIGABRT" : "signal";
    writeCrashReport(std::string("Fatal ") + name, "");
    std::_Exit(3);
}

void installCrashHandlers() {
    installThreadCrashHandlers();
    // An alternate stack so a stack overflow still reaches the handler.
    static std::vector<char> altStack(1 << 16);
    stack_t ss = {};
    ss.ss_sp = altStack.data();
    ss.ss_size = altStack.size();
    ss.ss_flags = 0;
    sigaltstack(&ss, nullptr);
    struct sigaction sa = {};
    sa.sa_handler = fatalSignalHandler;
    sa.sa_flags = SA_ONSTACK;
    sigemptyset(&sa.sa_mask);
    for (int sig : {SIGSEGV, SIGBUS, SIGFPE, SIGILL, SIGABRT}) sigaction(sig, &sa, nullptr);
    std::signal(SIGPIPE, SIG_IGN);   // a closed socket must not kill the agent
}

void disableConsoleQuickEdit() {}

// --- On-demand historical collection ---

// Every journal entry from the start time on, rendered through the same
// join and envelope as the live reader.
size_t platformCollectHistory(const std::string& startTimeIsoUtc,
                              const std::function<void(const std::wstring&)>& cb) {
    uint64_t start = 0;
    if (!parseIsoUtcUsec(startTimeIsoUtc, start)) {
        logError("[Collect] Unparsable start time '" + startTimeIsoUtc + "'.");
        return 0;
    }
    sd_journal* j = nullptr;
    int r = sd_journal_open(&j, SD_JOURNAL_LOCAL_ONLY);
    if (r < 0) {
        logError(std::string("[Collect] sd_journal_open failed: ") + std::strerror(-r));
        return 0;
    }
    size_t count = 0;
    AuditJoiner joiner([&](const JournalEntry& e, const std::vector<const JournalEntry*>& siblings) {
        std::wstring xml = journalEntryToXml(e, siblings);
        if (!xml.empty()) {
            cb(xml);
            ++count;
        }
    });
    r = sd_journal_seek_realtime_usec(j, start);
    if (r < 0) {
        logError(std::string("[Collect] sd_journal_seek_realtime_usec failed: ") + std::strerror(-r));
    } else {
        while ((r = sd_journal_next(j)) > 0) {
            JournalEntry e;
            if (readJournalEntry(j, e)) joiner.push(std::move(e));
        }
        if (r < 0) {
            logError(std::string("[Collect] sd_journal_next failed: ") + std::strerror(-r));
        }
    }
    joiner.flushAll();
    sd_journal_close(j);
    return count;
}

} // namespace elf
