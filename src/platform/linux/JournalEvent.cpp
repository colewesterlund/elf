#include "JournalEvent.h"
#include "Platform.h"

#include <systemd/sd-journal.h>

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <map>
#include <set>

namespace elf {

// --- JournalEntry ---

const std::string* JournalEntry::get(const std::string& key) const {
    for (const auto& kv : fields) {
        if (kv.first == key) return &kv.second;
    }
    return nullptr;
}

bool JournalEntry::isAudit() const {
    const std::string* t = get("_TRANSPORT");
    return t && *t == "audit";
}

std::string JournalEntry::auditId() const {
    const std::string* id = get("_AUDIT_ID");
    return id ? *id : std::string();
}

int JournalEntry::auditType() const {
    const std::string* t = get("_AUDIT_TYPE");
    if (!t || t->empty() || t->size() > 9) return -1;
    for (char c : *t) {
        if (!std::isdigit(static_cast<unsigned char>(c))) return -1;
    }
    return std::atoi(t->c_str());
}

namespace {

// Field values beyond this are cut; a rule never needs more and a runaway
// MESSAGE must not inflate the buffer.
constexpr size_t kMaxValueBytes = 64 * 1024;

// Audit record types (linux/audit.h).
constexpr int kAuditSyscall   = 1300;
constexpr int kAuditPath      = 1302;
constexpr int kAuditCwd       = 1307;
constexpr int kAuditExecve    = 1309;
constexpr int kAuditEoe       = 1320;
constexpr int kAuditProctitle = 1327;

// journald stores the audit record's own fields as _AUDIT_FIELD_<NAME>
// (process identity fields like pid/uid/exe/comm get their trusted
// names: _PID, _UID, _EXE, _COMM, _PPID, ...).
constexpr const char* kAuditFieldPrefix = "_AUDIT_FIELD_";
constexpr size_t kAuditFieldPrefixLen = 13;

bool isAuditField(const std::string& key) {
    return key.compare(0, kAuditFieldPrefixLen, kAuditFieldPrefix) == 0;
}

// _AUDIT_FIELD_A0 .. _AUDIT_FIELD_A99: argv in an EXECVE record, syscall
// arguments (pointers) in a SYSCALL record.
bool isAuditArgField(const std::string& key, int* index) {
    if (!isAuditField(key) || key.size() < kAuditFieldPrefixLen + 2) return false;
    if (key[kAuditFieldPrefixLen] != 'A') return false;
    int n = 0;
    for (size_t i = kAuditFieldPrefixLen + 1; i < key.size(); ++i) {
        if (!std::isdigit(static_cast<unsigned char>(key[i]))) return false;
        n = n * 10 + (key[i] - '0');
        if (n > 999) return false;
    }
    if (index) *index = n;
    return true;
}

std::string toLower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return s;
}

// Text content needs only the three markup characters escaped; quotes
// stay literal there, as the Windows renderer leaves them. Attribute
// values (`attr` = true) escape the quotes too.
std::string xmlEscape(const std::string& s, bool attr = false) {
    std::string out;
    out.reserve(s.size() + 8);
    for (char c : s) {
        switch (c) {
            case '&':  out += "&amp;"; break;
            case '<':  out += "&lt;"; break;
            case '>':  out += "&gt;"; break;
            case '"':  out += attr ? "&quot;" : "\""; break;
            case '\'': out += attr ? "&apos;" : "'"; break;
            default:
                // Control characters are not valid XML text.
                if (static_cast<unsigned char>(c) < 0x20 && c != '\t' && c != '\n' && c != '\r') {
                    out += ' ';
                } else {
                    out += c;
                }
        }
    }
    return out;
}

// Journal keys that describe the entry's storage rather than the event,
// or are rendered into <System> instead of <EventData>.
bool skippedKey(const std::string& key) {
    static const std::set<std::string> skip = {
        "_AUDIT_TYPE", "_HOSTNAME", "_MACHINE_ID", "_BOOT_ID",
        "_SOURCE_MONOTONIC_TIMESTAMP", "_CAP_EFFECTIVE", "_SYSTEMD_CGROUP",
        "_SYSTEMD_SLICE", "_SYSTEMD_INVOCATION_ID", "_STREAM_ID",
        "_RUNTIME_SCOPE", "_SELINUX_CONTEXT",
    };
    if (key.rfind("__", 0) == 0) return true;   // __CURSOR, __REALTIME_TIMESTAMP, ...
    return skip.count(key) > 0;
}

// The <Data Name> a journal key is rendered under. Audit fields keep the
// names the audit log uses (exe, comm, a0, key, ...), which are also the
// names Sigma's auditd rules use. Everything else keeps the journal name
// without the leading underscore.
std::string dataName(const std::string& key) {
    static const std::map<std::string, std::string> fixed = {
        {"MESSAGE",          "Message"},
        {"_AUDIT_TYPE_NAME", "type"},
        {"_AUDIT_ID",        "AuditId"},
        {"_AUDIT_LOGINUID",  "auid"},
        {"_AUDIT_SESSION",   "ses"},
        {"_EXE",             "exe"},
        {"_COMM",            "comm"},
        {"_PID",             "pid"},
        {"_PPID",            "ppid"},
        {"_UID",             "uid"},
        {"_GID",             "gid"},
        {"_EUID",            "euid"},
        {"_EGID",            "egid"},
        {"_FSUID",           "fsuid"},
        {"_FSGID",           "fsgid"},
        {"_TTY",             "tty"},
        {"_CMDLINE",         "cmdline"},
    };
    auto it = fixed.find(key);
    if (it != fixed.end()) return it->second;
    if (isAuditField(key)) return toLower(key.substr(kAuditFieldPrefixLen));
    size_t i = 0;
    while (i < key.size() && key[i] == '_') ++i;
    return key.substr(i);
}

// Fields of a sibling audit record worth merging into another record of
// the same event: the process identity from SYSCALL, argv from EXECVE,
// the working directory from CWD, the decoded title (_CMDLINE) from
// PROCTITLE. Not the message, the type, or the SYSCALL's pointer-valued
// a0..a3, which would masquerade as argv.
bool mergeableKey(const std::string& key, int recordType) {
    if (isAuditArgField(key, nullptr) || key == "_AUDIT_FIELD_ARGC") {
        return recordType == kAuditExecve;
    }
    if (isAuditField(key)) return true;
    static const std::set<std::string> process = {
        "_EXE", "_COMM", "_PID", "_PPID", "_UID", "_GID", "_EUID", "_EGID",
        "_FSUID", "_FSGID", "_TTY", "_CMDLINE", "_AUDIT_LOGINUID", "_AUDIT_SESSION",
    };
    return process.count(key) > 0;
}

// The audit subsystem hex-encodes a string field that contains a space,
// a quote or a control character; journald keeps such values as they
// came. Only the fields that are strings by definition are decoded (a
// SYSCALL's a0..a3 are pointers and stay hex).
bool hexEncodedStringField(const std::string& key, int recordType) {
    switch (recordType) {
        case kAuditExecve:    return isAuditArgField(key, nullptr);
        case kAuditPath:      return key == "_AUDIT_FIELD_NAME";
        case kAuditCwd:       return key == "_AUDIT_FIELD_CWD";
        case kAuditProctitle: return key == "_AUDIT_FIELD_PROCTITLE";
        default:              return false;
    }
}

bool isHexString(const std::string& s) {
    if (s.size() < 4 || (s.size() % 2) != 0) return false;
    for (char c : s) {
        if (!std::isxdigit(static_cast<unsigned char>(c))) return false;
    }
    return true;
}

// The audit subsystem hex-encodes a string field that contains a space,
// a quote or a control character. Decode when the result is plain text.
std::string unhexIfEncoded(const std::string& s) {
    if (!isHexString(s)) return s;
    std::string out;
    out.reserve(s.size() / 2);
    for (size_t i = 0; i + 1 < s.size(); i += 2) {
        int v = std::stoi(s.substr(i, 2), nullptr, 16);
        if (v < 0x20 && v != '\t' && v != '\n' && v != 0) return s;
        out += v == 0 ? ' ' : static_cast<char>(v);   // argv separators in proctitle
    }
    return out;
}

std::string stripQuotes(const std::string& s) {
    if (s.size() >= 2 && s.front() == '"' && s.back() == '"') return s.substr(1, s.size() - 2);
    return s;
}

std::string formatUsecIso(uint64_t usec) {
    std::time_t secs = static_cast<std::time_t>(usec / 1000000);
    std::tm tm{};
    if (!platformGmTime(secs, tm)) return "1970-01-01T00:00:00.000000Z";
    char buf[48];
    std::snprintf(buf, sizeof(buf), "%04d-%02d-%02dT%02d:%02d:%02d.%06lluZ",
                  tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
                  tm.tm_hour, tm.tm_min, tm.tm_sec,
                  static_cast<unsigned long long>(usec % 1000000));
    return buf;
}

// Windows event level from the syslog priority: 2 error, 3 warning, 4
// informational. Audit records carry no priority and count as
// informational.
int levelOf(const JournalEntry& e) {
    const std::string* p = e.get("PRIORITY");
    if (!p || p->empty() || !std::isdigit(static_cast<unsigned char>((*p)[0]))) return 4;
    int prio = (*p)[0] - '0';
    if (prio <= 3) return 2;
    if (prio == 4) return 3;
    return 4;
}

} // namespace

// --- Reading ---

bool readJournalEntry(sd_journal* j, JournalEntry& out) {
    out.fields.clear();
    out.cursor.clear();
    out.realtimeUsec = 0;
    const void* data = nullptr;
    size_t len = 0;
    sd_journal_restart_data(j);
    int r;
    while ((r = sd_journal_enumerate_available_data(j, &data, &len)) > 0) {
        const char* p = static_cast<const char*>(data);
        const char* eq = static_cast<const char*>(std::memchr(p, '=', len));
        if (!eq) continue;
        std::string key(p, static_cast<size_t>(eq - p));
        size_t vlen = len - static_cast<size_t>(eq + 1 - p);
        if (vlen > kMaxValueBytes) vlen = kMaxValueBytes;
        out.fields.emplace_back(std::move(key), std::string(eq + 1, vlen));
    }
    if (r < 0) return false;
    if (sd_journal_get_realtime_usec(j, &out.realtimeUsec) < 0) out.realtimeUsec = 0;
    char* c = nullptr;
    if (sd_journal_get_cursor(j, &c) >= 0 && c) {
        out.cursor = c;
        std::free(c);
    }
    return true;
}

std::string journalChannel(const JournalEntry& e) {
    if (e.isAudit()) return "audit";
    if (const std::string* id = e.get("SYSLOG_IDENTIFIER")) {
        if (!id->empty()) return *id;
    }
    if (const std::string* comm = e.get("_COMM")) {
        if (!comm->empty()) return *comm;
    }
    if (const std::string* t = e.get("_TRANSPORT")) {
        if (!t->empty()) return *t;
    }
    return "journal";
}

int journalEventId(const JournalEntry& e) {
    int t = e.auditType();
    return t < 0 ? 0 : t;
}

// --- Rendering ---

std::wstring journalEntryToXml(const JournalEntry& e,
                               const std::vector<const JournalEntry*>& siblings) {
    const bool audit = e.isAudit();
    const std::string channel = journalChannel(e);
    const std::string* host = e.get("_HOSTNAME");
    std::string provider = audit ? "audit" : channel;

    // EventData: own fields first, then siblings' process fields, then the
    // derived names the Windows-shaped rules use. First writer of a name
    // wins, compared case-insensitively like the field cache.
    std::vector<std::pair<std::string, std::string>> data;
    std::set<std::string> seen;
    auto add = [&](const std::string& name, const std::string& value) {
        if (name.empty()) return;
        if (!seen.insert(toLower(name)).second) return;
        data.emplace_back(name, value);
    };
    auto cleanAudit = [&](const std::string& key, const std::string& value, int recordType) {
        if (!audit || !isAuditField(key)) return value;
        if (value.size() >= 2 && value.front() == '"') return stripQuotes(value);
        if (hexEncodedStringField(key, recordType)) return unhexIfEncoded(value);
        return value;
    };
    const int ownType = e.auditType();
    for (const auto& kv : e.fields) {
        if (skippedKey(kv.first)) continue;
        add(dataName(kv.first), cleanAudit(kv.first, kv.second, ownType));
    }
    for (const JournalEntry* s : siblings) {
        if (!s) continue;
        const int sibType = s->auditType();
        for (const auto& kv : s->fields) {
            if (!mergeableKey(kv.first, sibType)) continue;
            add(dataName(kv.first), cleanAudit(kv.first, kv.second, sibType));
        }
    }

    // Derived fields. `value` reads what has been collected so far.
    auto value = [&](const char* name) -> const std::string* {
        std::string lower = toLower(name);
        for (const auto& kv : data) {
            if (toLower(kv.first) == lower) return &kv.second;
        }
        return nullptr;
    };
    if (const std::string* exe = value("exe")) add("NewProcessName", *exe);
    if (const std::string* pid = value("pid")) add("ProcessId", *pid);
    if (const std::string* ppid = value("ppid")) add("ParentProcessId", *ppid);
    if (const std::string* cwd = value("cwd")) add("CurrentDirectory", *cwd);
    if (audit) {
        // argv from the EXECVE record of this audit event (the entry itself
        // or a sibling): a0, a1, ... in order. Otherwise the decoded
        // process title journald attaches to the PROCTITLE record.
        const JournalEntry* execve = ownType == kAuditExecve ? &e : nullptr;
        for (const JournalEntry* s : siblings) {
            if (!execve && s && s->auditType() == kAuditExecve) execve = s;
        }
        std::map<int, std::string> argv;
        if (execve) {
            for (const auto& kv : execve->fields) {
                int idx = 0;
                if (isAuditArgField(kv.first, &idx)) {
                    argv[idx] = cleanAudit(kv.first, kv.second, kAuditExecve);
                }
            }
        }
        if (!argv.empty()) {
            std::string cmd;
            for (const auto& [idx, arg] : argv) {
                if (!cmd.empty()) cmd += ' ';
                cmd += arg;
            }
            add("CommandLine", cmd);
        } else if (const std::string* cmdline = value("cmdline")) {
            add("CommandLine", *cmdline);
        }
    } else if (const std::string* cmdline = value("cmdline")) {
        add("CommandLine", *cmdline);
    }

    std::string xml;
    xml.reserve(512 + data.size() * 64);
    xml += "<Event xmlns=\"http://schemas.microsoft.com/win/2004/08/events/event\">";
    xml += "<System>";
    xml += "<Provider Name=\"" + xmlEscape(provider, true) + "\"/>";
    xml += "<EventID>" + std::to_string(journalEventId(e)) + "</EventID>";
    xml += "<Level>" + std::to_string(levelOf(e)) + "</Level>";
    xml += "<TimeCreated SystemTime=\"" + formatUsecIso(e.realtimeUsec) + "\"/>";
    xml += "<EventRecordID>" + std::to_string(e.realtimeUsec) + "</EventRecordID>";
    xml += "<Channel>" + xmlEscape(channel) + "</Channel>";
    xml += "<Computer>" + xmlEscape(host ? *host : platformHostname()) + "</Computer>";
    xml += "</System>";
    xml += "<EventData>";
    for (const auto& kv : data) {
        xml += "<Data Name=\"" + xmlEscape(kv.first, true) + "\">" + xmlEscape(kv.second) + "</Data>";
    }
    xml += "</EventData>";
    xml += "</Event>";
    return utf8ToWide(xml);
}

// --- AuditJoiner ---

void AuditJoiner::push(JournalEntry e) {
    if (!e.isAudit()) {
        // Syslog lines interleave with audit records; they do not end a
        // group (its records keep arriving behind them).
        m_emit(e, {});
        return;
    }
    std::string id = e.auditId();
    if (id.empty()) {
        m_emit(e, {});
        return;
    }
    if (!m_group.empty() && id != m_groupId) flushGroup();
    if (m_group.empty()) {
        m_groupId = id;
        m_groupStarted = std::chrono::steady_clock::now();
    }
    const bool complete = e.auditType() == kAuditEoe;
    m_group.push_back(std::move(e));
    if (complete) flushGroup();
}

void AuditJoiner::flushIfIdle(std::chrono::milliseconds idle) {
    if (m_group.empty()) return;
    if (std::chrono::steady_clock::now() - m_groupStarted >= idle) flushGroup();
}

void AuditJoiner::flushAll() { flushGroup(); }

void AuditJoiner::flushGroup() {
    if (m_group.empty()) return;
    std::vector<JournalEntry> group;
    group.swap(m_group);
    m_groupId.clear();
    for (size_t i = 0; i < group.size(); ++i) {
        if (group[i].auditType() == kAuditEoe) continue;
        std::vector<const JournalEntry*> siblings;
        siblings.reserve(group.size());
        for (size_t k = 0; k < group.size(); ++k) {
            if (k != i && group[k].auditType() != kAuditEoe) siblings.push_back(&group[k]);
        }
        m_emit(group[i], siblings);
    }
}

// --- Time ---

bool parseIsoUtcUsec(const std::string& iso, uint64_t& usec) {
    int y = 0, mo = 0, d = 0, h = 0, mi = 0, s = 0;
    int consumed = 0;
    if (std::sscanf(iso.c_str(), "%4d-%2d-%2dT%2d:%2d:%2d%n", &y, &mo, &d, &h, &mi, &s, &consumed) != 6) {
        return false;
    }
    uint64_t frac = 0;
    size_t i = static_cast<size_t>(consumed);
    if (i < iso.size() && iso[i] == '.') {
        ++i;
        int digits = 0;
        while (i < iso.size() && std::isdigit(static_cast<unsigned char>(iso[i]))) {
            if (digits < 6) { frac = frac * 10 + static_cast<uint64_t>(iso[i] - '0'); ++digits; }
            ++i;
        }
        while (digits < 6) { frac *= 10; ++digits; }
    }
    std::tm tm{};
    tm.tm_year = y - 1900;
    tm.tm_mon = mo - 1;
    tm.tm_mday = d;
    tm.tm_hour = h;
    tm.tm_min = mi;
    tm.tm_sec = s;
    std::time_t t = platformTimeGm(tm);
    if (t < 0) return false;
    usec = static_cast<uint64_t>(t) * 1000000ULL + frac;
    return true;
}

} // namespace elf
