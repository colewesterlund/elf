#include "OutputFormat.h"
#include "AgentClient.h"      // MAX_ALERT_EVIDENCE_EVENTS
#include "FieldResolver.h"
#include "Platform.h"         // wideToUtf8, time helpers
#include "RuleEngine.h"       // sigmaCategoriesFor
#include "XmlPretty.h"
#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <sstream>

namespace elf {

using json = nlohmann::json;

// --- Small helpers ----------------------------------------------------------

std::string isoTime(std::chrono::system_clock::time_point tp) {
    auto t = std::chrono::system_clock::to_time_t(tp);
    std::tm tm{};
    platformGmTime(t, tm);
    char buf[32];
    std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", &tm);
    return buf;
}

// Field value as UTF-8, "" when absent.
static std::string fieldStr(const BufferedEvent& evt, const char* cacheKey) {
    const CachedField* cf = lookupField(evt, cacheKey);
    return cf ? wideToUtf8(cf->value) : std::string();
}

static bool fieldPresent(const BufferedEvent& evt, const char* cacheKey) {
    const CachedField* cf = lookupField(evt, cacheKey);
    return cf && !cf->value.empty();
}

static std::string lowerAscii(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(),
        [](unsigned char c) { return static_cast<char>(::tolower(c)); });
    return s;
}

// "C:\Windows\System32\calc.exe" → "calc.exe" (either slash).
static std::string basename(const std::string& p) {
    auto pos = p.find_last_of("\\/");
    return pos == std::string::npos ? p : p.substr(pos + 1);
}

// "0x1f4" / "500" → 500; -1 when not a number. Security events render PIDs
// in hex, Sysmon in decimal.
static long long parseIntAny(const std::string& s) {
    if (s.empty()) return -1;
    try {
        if (s.size() > 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) {
            return std::stoll(s.substr(2), nullptr, 16);
        }
        for (char c : s) if (!std::isdigit(static_cast<unsigned char>(c))) return -1;
        return std::stoll(s);
    } catch (...) {
        return -1;
    }
}

static bool usableValue(const std::string& v) {
    return !v.empty() && v != "-";
}

std::string eventTimestampIso(const BufferedEvent& evt) {
    std::string tc = fieldStr(evt, "timecreated");
    return tc.empty() ? isoTime(evt.receivedAt) : tc;
}

double eventEpochSeconds(const BufferedEvent& evt) {
    std::string tc = fieldStr(evt, "timecreated");
    // YYYY-MM-DDTHH:MM:SS(.fraction)Z
    int Y, M, D, h, m, s;
    if (tc.size() >= 19 &&
        std::sscanf(tc.c_str(), "%4d-%2d-%2dT%2d:%2d:%2d", &Y, &M, &D, &h, &m, &s) == 6) {
        std::tm tm{};
        tm.tm_year = Y - 1900; tm.tm_mon = M - 1; tm.tm_mday = D;
        tm.tm_hour = h; tm.tm_min = m; tm.tm_sec = s;
        time_t t = platformTimeGm(tm);
        if (t != static_cast<time_t>(-1)) {
            double frac = 0.0;
            if (tc.size() > 19 && tc[19] == '.') {
                double scale = 0.1;
                for (size_t i = 20; i < tc.size() && std::isdigit(static_cast<unsigned char>(tc[i])); ++i) {
                    frac += (tc[i] - '0') * scale;
                    scale /= 10.0;
                }
            }
            return static_cast<double>(t) + frac;
        }
    }
    auto us = std::chrono::duration_cast<std::chrono::microseconds>(
        evt.receivedAt.time_since_epoch()).count();
    return static_cast<double>(us) / 1e6;
}

// Every <Data Name=..> as {Name: value}, original case.
static json eventDataObject(const BufferedEvent& evt) {
    json o = json::object();
    forEachEventData(evt.xml, [&](const std::wstring& name, const std::wstring& value) {
        o[wideToUtf8(name)] = wideToUtf8(value);
    });
    return o;
}

static int eventIdOf(const BufferedEvent& evt) { return extractEventIdCached(evt); }
static long long recordIdOf(const BufferedEvent& evt) { return extractRecordIdCached(evt); }

static int sigmaSeverityScore(const std::string& level) {
    std::string l = lowerAscii(level);
    if (l == "critical") return 99;
    if (l == "high") return 73;
    if (l == "medium") return 47;
    if (l == "low") return 21;
    if (l == "informational") return 1;
    return 0;
}

// GELF/syslog level: critical 2, high 3, medium 4, low 5, informational 6.
static int gelfLevel(const std::string& level, bool isAlert) {
    if (!isAlert) return 6;
    std::string l = lowerAscii(level);
    if (l == "critical") return 2;
    if (l == "high") return 3;
    if (l == "medium") return 4;
    if (l == "low") return 5;
    return 6;
}

// "attack.t1059.001" → "T1059.001"; "attack.lateral_movement" → "Lateral Movement".
static void threatFromTags(const std::vector<std::string>& tags,
                           std::vector<std::string>& techniques,
                           std::vector<std::string>& tactics) {
    for (const auto& t : tags) {
        std::string l = lowerAscii(t);
        if (l.rfind("attack.", 0) != 0) continue;
        std::string rest = l.substr(7);
        if (rest.size() > 1 && rest[0] == 't' && std::isdigit(static_cast<unsigned char>(rest[1]))) {
            std::string id = rest;
            id[0] = 'T';
            techniques.push_back(id);
        } else if (!rest.empty()) {
            // Title-case words; keep "and"/"of" lower (Command and Control).
            std::string out;
            bool newWord = true;
            size_t i = 0;
            while (i < rest.size()) {
                size_t j = rest.find('_', i);
                std::string w = rest.substr(i, j == std::string::npos ? std::string::npos : j - i);
                if (!out.empty()) out += ' ';
                if (w == "and" || w == "of") out += w;
                else if (!w.empty()) { w[0] = static_cast<char>(::toupper(static_cast<unsigned char>(w[0]))); out += w; }
                if (j == std::string::npos) break;
                i = j + 1;
                (void)newWord;
            }
            tactics.push_back(out);
        }
    }
}

// Remove null members and empty objects left behind by `d["a"]["b"]`
// probes whose value turned out unusable, so a 4625 without an IpAddress
// has no "source": null.
static void pruneEmpty(json& j) {
    if (!j.is_object()) return;
    for (auto it = j.begin(); it != j.end();) {
        pruneEmpty(it.value());
        if (it.value().is_null() || (it.value().is_object() && it.value().empty())) {
            it = j.erase(it);
        } else {
            ++it;
        }
    }
}

// Evidence events capped to the most recent N (same cap/semantics as the
// server mirror). Returns the number dropped.
static size_t cappedEvidence(const FormatContext& ctx,
                             std::vector<const BufferedEvent*>& out) {
    out.clear();
    if (!ctx.evidence || ctx.evidence->empty()) return 0;
    const size_t cap = AgentClient::MAX_ALERT_EVIDENCE_EVENTS;
    size_t start = ctx.evidence->size() > cap ? ctx.evidence->size() - cap : 0;
    for (size_t i = start; i < ctx.evidence->size(); ++i) out.push_back(&(*ctx.evidence)[i]);
    return start;
}

static json alsoMatchedArray(const FormatContext& ctx) {
    json a = json::array();
    if (ctx.alsoMatched) for (const auto& id : *ctx.alsoMatched) a.push_back(id);
    return a;
}

// --- json -------------------------------------------------------------------

// The core of the ELF flat document (everything except the elf block), also
// used for evidence entries.
static json jsonCore(const BufferedEvent& evt) {
    json d;
    d["@timestamp"] = eventTimestampIso(evt);
    d["received_at"] = isoTime(evt.receivedAt);
    d["host"] = fieldStr(evt, "computer");
    d["channel"] = fieldStr(evt, "channel");
    d["provider"] = fieldStr(evt, "provider");
    d["event_id"] = eventIdOf(evt);
    d["record_id"] = recordIdOf(evt);
    d["event_data"] = eventDataObject(evt);
    return d;
}

json buildJsonDoc(const BufferedEvent& evt, const FormatContext& ctx, bool isAlert) {
    json d = jsonCore(evt);
    json e;
    e["kind"] = isAlert ? "alert" : "event";
    e["action"] = ctx.action;
    e["agent_id"] = ctx.agentId;
    if (!ctx.alertId.empty()) e["alert_id"] = ctx.alertId;
    if (ctx.rule) {
        e["rule_id"] = ctx.rule->id;
        e["rule_name"] = ctx.rule->name;
        e["level"] = ctx.rule->level;
        if (!ctx.rule->category.empty()) e["category"] = ctx.rule->category;
    }
    if (isAlert) {
        e["message"] = ctx.message;
        if (ctx.alsoMatched && !ctx.alsoMatched->empty()) e["also_matched"] = alsoMatchedArray(ctx);
        std::vector<const BufferedEvent*> ev;
        size_t dropped = cappedEvidence(ctx, ev);
        if (!ev.empty()) {
            e["evidence_kind"] = ctx.evidenceIsSequence ? "sequence" : "window";
            json arr = json::array();
            for (const auto* x : ev) arr.push_back(jsonCore(*x));
            e["evidence"] = arr;
            if (dropped) e["evidence_truncated"] = dropped;
        }
    }
    d["elf"] = e;
    return d;
}

// --- ecs --------------------------------------------------------------------

static std::string ecsDataset(const std::string& channelLower) {
    if (channelLower == "security") return "windows.security";
    if (channelLower == "system") return "windows.system";
    if (channelLower == "application") return "windows.application";
    if (channelLower == "microsoft-windows-sysmon/operational") return "windows.sysmon_operational";
    if (channelLower == "microsoft-windows-powershell/operational") return "windows.powershell_operational";
    if (channelLower == "windows powershell") return "windows.powershell";
    std::string ds = "windows.";
    for (unsigned char c : channelLower) ds += std::isalnum(c) ? static_cast<char>(c) : '_';
    return ds;
}

static const char* logonTypeName(const std::string& t) {
    if (t == "2") return "Interactive";
    if (t == "3") return "Network";
    if (t == "4") return "Batch";
    if (t == "5") return "Service";
    if (t == "7") return "Unlock";
    if (t == "8") return "NetworkCleartext";
    if (t == "9") return "NewCredentials";
    if (t == "10") return "RemoteInteractive";
    if (t == "11") return "CachedInteractive";
    return nullptr;
}

static void setIfUsable(json& obj, const char* key, const std::string& v) {
    if (usableValue(v)) obj[key] = v;
}

static void setPid(json& obj, const char* key, const std::string& v) {
    long long n = parseIntAny(v);
    if (n >= 0) obj[key] = n;
}

// Sysmon "SHA256=...,MD5=...,IMPHASH=..." → process.hash.*
static void parseSysmonHashes(const std::string& hashes, json& out) {
    size_t pos = 0;
    while (pos < hashes.size()) {
        size_t comma = hashes.find(',', pos);
        std::string kv = hashes.substr(pos, comma == std::string::npos ? std::string::npos : comma - pos);
        pos = (comma == std::string::npos) ? hashes.size() : comma + 1;
        auto eq = kv.find('=');
        if (eq == std::string::npos) continue;
        std::string k = lowerAscii(kv.substr(0, eq));
        std::string v = lowerAscii(kv.substr(eq + 1));
        if (k == "md5" || k == "sha1" || k == "sha256" || k == "imphash") out[k] = v;
    }
}

// "DOMAIN\user" → user.name / user.domain
static void splitDomainUser(const std::string& v, json& user) {
    if (!usableValue(v)) return;
    auto bs = v.find('\\');
    if (bs == std::string::npos) { user["name"] = v; return; }
    user["domain"] = v.substr(0, bs);
    user["name"] = v.substr(bs + 1);
}

// --- Linux (journald, auditd) -------------------------------------------------
//
// On a Linux host the events are journal entries rendered by the platform
// collector: the channel is the syslog identifier ("audit" for the kernel
// audit transport), EventID the audit record type, and every journal
// field a Data element. The ECS document follows the Filebeat system and
// auditd modules where they have a field for it.

// Every journal entry carries _TRANSPORT (rendered as the TRANSPORT data
// field); no Windows provider emits a field of that name. Deciding per
// event keeps the formatter independent of the host it runs on.
static bool isJournalEvent(const BufferedEvent& evt) {
    return lookupField(evt, "transport") != nullptr;
}

static std::string ecsLinuxDataset(const std::string& identLower) {
    static const char* const auth[] = {
        "sshd", "sshd-session", "sudo", "su", "login", "systemd-logind", "polkitd",
        "gdm", "sssd", "useradd", "userdel", "usermod", "groupadd", "groupdel",
        "groupmod", "passwd", "chage", "chpasswd",
    };
    for (const char* a : auth) {
        if (identLower == a) return "system.auth";
    }
    return "system.syslog";
}

// Words of a syslog line, split on spaces.
static std::vector<std::string> words(const std::string& s) {
    std::vector<std::string> out;
    std::string cur;
    for (char c : s) {
        if (c == ' ' || c == '\t') { if (!cur.empty()) { out.push_back(cur); cur.clear(); } }
        else cur += c;
    }
    if (!cur.empty()) out.push_back(cur);
    return out;
}

// The word following the first occurrence of `key`, or "".
static std::string wordAfter(const std::vector<std::string>& w, const char* key) {
    for (size_t i = 0; i + 1 < w.size(); ++i) {
        if (w[i] == key) return w[i + 1];
    }
    return "";
}

// sudo's "KEY=value ; KEY=value" fields.
static std::string sudoField(const std::string& msg, const char* key) {
    std::string needle = std::string(key) + "=";
    auto p = msg.find(needle);
    if (p == std::string::npos) return "";
    p += needle.size();
    auto e = msg.find(" ; ", p);
    std::string v = msg.substr(p, e == std::string::npos ? std::string::npos : e - p);
    while (!v.empty() && (v.back() == ' ' || v.back() == '\n')) v.pop_back();
    return v;
}

// useradd/groupadd "name=bob, UID=1001, ..." fields.
static std::string accountField(const std::string& msg, const char* key) {
    std::string needle = std::string(key) + "=";
    auto p = msg.find(needle);
    if (p == std::string::npos) return "";
    p += needle.size();
    auto e = msg.find_first_of(", ", p);
    return msg.substr(p, e == std::string::npos ? std::string::npos : e - p);
}

static std::string stripQuotesAscii(std::string v) {
    if (v.size() >= 2 && (v.front() == '\'' || v.front() == '"') && v.back() == v.front()) {
        v = v.substr(1, v.size() - 2);
    }
    return v;
}

// Kernel audit records (channel "audit"). The collector joins the records
// of one audit event, so an EXECVE record also carries the SYSCALL's
// exe/pid/uid/key, and a SYSCALL record the EXECVE's argv as CommandLine.
static void ecsLinuxAudit(json& d, const BufferedEvent& evt, json& category, json& type) {
    auto f = [&](const char* key) { return fieldStr(evt, key); };
    const std::string recordType = f("type");
    const bool execve = usableValue(f("argc"));   // joined with an EXECVE record
    d["auditd"]["log"]["record_type"] = recordType;
    setPid(d["auditd"]["log"], "sequence", f("auditid"));
    setIfUsable(d["auditd"]["log"], "key", f("key"));
    setIfUsable(d["auditd"]["log"], "syscall", f("syscall"));
    setIfUsable(d["auditd"]["log"], "tty", f("tty"));
    setIfUsable(d["auditd"]["log"], "session", f("ses"));
    setIfUsable(d["auditd"]["log"], "exit", f("exit"));
    if (usableValue(f("success"))) {
        d["event"]["outcome"] = lowerAscii(f("success")) == "yes" ? "success" : "failure";
    }
    setPid(d["process"], "pid", f("pid"));
    setPid(d["process"]["parent"], "pid", f("ppid"));
    setIfUsable(d["process"], "executable", f("exe"));
    if (usableValue(f("exe"))) d["process"]["name"] = basename(f("exe"));
    else setIfUsable(d["process"], "name", f("comm"));
    setIfUsable(d["process"], "working_directory", f("cwd"));
    setIfUsable(d["process"], "command_line", f("commandline"));
    setIfUsable(d["user"], "id", f("uid"));
    setIfUsable(d["user"]["effective"], "id", f("euid"));
    setIfUsable(d["user"]["group"], "id", f("gid"));
    setIfUsable(d["user"]["audit"], "id", f("auid"));
    if (execve) {
        category = {"process"}; type = {"start"};
        d["event"]["action"] = "executed";
        if (recordType == "EXECVE") {
            json args = json::array();
            for (int i = 0; i < 1000; ++i) {
                std::string a = f(("a" + std::to_string(i)).c_str());
                if (!usableValue(a) && i > 0) break;
                if (i == 0 && !usableValue(a)) break;
                args.push_back(a);
            }
            if (!args.empty()) d["process"]["args"] = args;
        }
    } else if (!recordType.empty()) {
        d["event"]["action"] = lowerAscii(recordType);
    }
    if (recordType == "PATH" || recordType == "CWD") {
        const std::string path = recordType == "PATH" ? f("name") : f("cwd");
        setIfUsable(d["file"], "path", path);
        if (usableValue(path)) d["file"]["name"] = basename(path);
    }
}

// Syslog-style journal entries, specialized for the identifiers the
// Linux rule sets care about.
static void ecsLinuxSyslog(json& d, const BufferedEvent& evt, const std::string& ident,
                           json& category, json& type) {
    auto f = [&](const char* key) { return fieldStr(evt, key); };
    const std::string msg = f("message");
    setPid(d["process"], "pid", f("pid"));
    setIfUsable(d["process"], "executable", f("exe"));
    if (usableValue(f("exe"))) d["process"]["name"] = basename(f("exe"));
    else setIfUsable(d["process"], "name", f("comm"));
    setIfUsable(d["process"], "command_line", f("cmdline"));
    setIfUsable(d["user"], "id", f("uid"));
    setIfUsable(d["user"]["group"], "id", f("gid"));
    setIfUsable(d["service"], "name", f("systemd_unit"));
    if (usableValue(msg)) d["event"]["original"] = msg;
    const std::vector<std::string> w = words(msg);

    if (ident == "sshd" || ident == "sshd-session") {
        const std::string first = w.empty() ? "" : w[0];
        const std::string ip = wordAfter(w, "from");
        const std::string port = wordAfter(w, "port");
        if (first == "Accepted" || first == "Failed") {
            category = {"authentication"}; type = {"start"};
            d["event"]["action"] = "ssh_login";
            d["event"]["outcome"] = first == "Accepted" ? "success" : "failure";
            std::string user = wordAfter(w, "for");
            if (user == "invalid") user = wordAfter(w, "user");
            setIfUsable(d["user"], "name", user);
            if (w.size() > 1) d["auth"]["method"] = w[1];   // publickey, password, keyboard-interactive
            setIfUsable(d["source"], "ip", ip);
            setPid(d["source"], "port", port);
        } else if (first == "Invalid" && w.size() > 2 && w[1] == "user") {
            category = {"authentication"}; type = {"info"};
            d["event"]["action"] = "ssh_login";
            d["event"]["outcome"] = "failure";
            setIfUsable(d["user"], "name", w[2]);
            setIfUsable(d["source"], "ip", ip);
            setPid(d["source"], "port", port);
        } else if (first == "Disconnected" || first == "Received") {
            category = {"session"}; type = {"end"};
            d["event"]["action"] = "ssh_disconnect";
            if (first == "Disconnected") setIfUsable(d["user"], "name", wordAfter(w, "user"));
            // "Disconnected from user cole 10.0.0.1 port 22" / "Received disconnect from 10.0.0.1 port 22"
            if (!ip.empty()) setIfUsable(d["source"], "ip", ip);
            else if (w.size() > 4 && first == "Disconnected") setIfUsable(d["source"], "ip", w[4]);
            setPid(d["source"], "port", port);
        }
    } else if (ident == "sudo") {
        const std::string command = sudoField(msg, "COMMAND");
        auto colon = msg.find(" : ");
        const std::string who = colon == std::string::npos ? "" : msg.substr(0, colon);
        if (!command.empty()) {
            category = {"process"}; type = {"start"};
            d["event"]["action"] = "sudo_command";
            d["event"]["outcome"] = msg.find("command not allowed") == std::string::npos ? "success" : "failure";
            setIfUsable(d["user"], "name", who);
            setIfUsable(d["user"]["effective"], "name", sudoField(msg, "USER"));
            setIfUsable(d["process"], "working_directory", sudoField(msg, "PWD"));
            d["process"]["command_line"] = command;
            const std::string exe = command.substr(0, command.find(' '));
            d["process"]["executable"] = exe;
            d["process"]["name"] = basename(exe);
            setIfUsable(d["process"]["entry_meta"], "type", sudoField(msg, "TTY"));
        } else if (msg.find("incorrect password") != std::string::npos ||
                   msg.find("authentication failure") != std::string::npos) {
            category = {"authentication"}; type = {"start"};
            d["event"]["action"] = "sudo_authentication";
            d["event"]["outcome"] = "failure";
            setIfUsable(d["user"], "name", who);
        }
    } else if (ident == "useradd" || ident == "userdel" || ident == "usermod" ||
               ident == "groupadd" || ident == "groupdel" || ident == "groupmod") {
        category = {"iam"};
        const bool group = ident.rfind("group", 0) == 0;
        if (msg.rfind("new user", 0) == 0 || msg.rfind("new group", 0) == 0) {
            type = {group ? "group" : "user", "creation"};
            d["event"]["action"] = group ? "group-created" : "user-created";
            if (group) {
                setIfUsable(d["group"], "name", accountField(msg, "name"));
                setIfUsable(d["group"], "id", accountField(msg, "GID"));
            } else {
                setIfUsable(d["user"], "name", accountField(msg, "name"));
                setIfUsable(d["user"], "id", accountField(msg, "UID"));
                setIfUsable(d["user"]["group"], "id", accountField(msg, "GID"));
            }
        } else if (msg.rfind("delete user", 0) == 0 || msg.rfind("removed group", 0) == 0 ||
                   msg.rfind("delete group", 0) == 0) {
            type = {group ? "group" : "user", "deletion"};
            d["event"]["action"] = group ? "group-deleted" : "user-deleted";
            const std::string name = w.size() > 2 ? stripQuotesAscii(w[2]) : "";
            if (group) setIfUsable(d["group"], "name", name);
            else setIfUsable(d["user"], "name", name);
        } else if (msg.rfind("add '", 0) == 0 && msg.find("' to group '") != std::string::npos) {
            type = {"group", "change"};
            d["event"]["action"] = "user-added-to-group";
            auto q1 = msg.find('\'');
            auto q2 = msg.find('\'', q1 + 1);
            auto g1 = msg.find("to group '");
            if (q1 != std::string::npos && q2 != std::string::npos) d["user"]["name"] = msg.substr(q1 + 1, q2 - q1 - 1);
            if (g1 != std::string::npos) {
                auto gs = g1 + 10;
                auto ge = msg.find('\'', gs);
                if (ge != std::string::npos) d["group"]["name"] = msg.substr(gs, ge - gs);
            }
        } else {
            type = {group ? "group" : "user", "change"};
            d["event"]["action"] = ident;
        }
    } else if (ident == "systemd" && w.size() >= 2 &&
               (w[0] == "Started" || w[0] == "Stopped" || w[0] == "Starting" || w[0] == "Stopping" ||
                w[0] == "Failed")) {
        d["event"]["action"] = w[0] == "Started" ? "service-started"
                             : w[0] == "Stopped" ? "service-stopped"
                             : w[0] == "Failed"  ? "service-failed" : lowerAscii(w[0]);
        if (!usableValue(f("systemd_unit"))) {
            std::string desc = msg.substr(msg.find(' ') + 1);
            if (!desc.empty() && desc.back() == '.') desc.pop_back();
            // "Started session-1.scope - Session 1 of User cole." names the unit first.
            auto dash = desc.find(" - ");
            d["service"]["name"] = dash == std::string::npos ? desc : desc.substr(0, dash);
        }
    } else if (ident == "cron" || ident == "crond") {
        // "(root) CMD (run-parts /etc/cron.hourly)"
        auto cmd = msg.find("CMD (");
        if (cmd != std::string::npos && msg.size() > cmd + 5) {
            category = {"process"}; type = {"start"};
            d["event"]["action"] = "cron_command";
            std::string c = msg.substr(cmd + 5);
            if (!c.empty() && c.back() == ')') c.pop_back();
            d["process"]["command_line"] = c;
            if (!msg.empty() && msg[0] == '(') {
                auto close = msg.find(')');
                if (close != std::string::npos) d["user"]["name"] = msg.substr(1, close - 1);
            }
        }
    }
}

json buildEcsDoc(const BufferedEvent& evt, const FormatContext& ctx, bool isAlert) {
    const std::string channel = fieldStr(evt, "channel");
    const std::string channelLower = lowerAscii(channel);
    const int eid = eventIdOf(evt);
    const std::string eidStr = eid >= 0 ? std::to_string(eid) : std::string();
    auto f = [&](const char* key) { return fieldStr(evt, key); };
    const bool lin = isJournalEvent(evt);

    json d;
    // (a) common
    d["@timestamp"] = eventTimestampIso(evt);
    d["ecs"]["version"] = "8.11.0";
    d["event"]["created"] = isoTime(evt.receivedAt);
    d["event"]["kind"] = isAlert ? "alert" : "event";
    d["event"]["code"] = eidStr;
    d["event"]["provider"] = f("provider");
    d["host"]["name"] = f("computer");
    d["host"]["hostname"] = f("computer");
    if (lin) {
        const bool audit = channelLower == "audit";
        d["event"]["module"] = audit ? "auditd" : "system";
        d["event"]["dataset"] = audit ? "auditd.log" : ecsLinuxDataset(channelLower);
        d["event"]["sequence"] = recordIdOf(evt);
        d["host"]["os"]["type"] = "linux";
        setIfUsable(d["log"]["syslog"], "identifier", f("syslog_identifier"));
        setPid(d["log"]["syslog"]["facility"], "code", f("syslog_facility"));
        setPid(d["log"]["syslog"], "priority", f("priority"));
        d["journald"]["fields"] = eventDataObject(evt);
    } else {
        d["event"]["module"] = "windows";
        d["event"]["dataset"] = ecsDataset(channelLower);
        d["winlog"]["api"] = "wineventlog";
        d["winlog"]["channel"] = channel;
        d["winlog"]["event_id"] = eidStr;
        d["winlog"]["record_id"] = recordIdOf(evt);
        d["winlog"]["provider_name"] = f("provider");
        d["winlog"]["computer_name"] = f("computer");
        d["winlog"]["event_data"] = eventDataObject(evt);
    }
    d["agent"]["type"] = "elf";
    d["agent"]["id"] = ctx.agentId;
    json tags = json::array({"elf"});

    // (b) Sigma category → ECS category/type
    std::vector<std::string> cats = sigmaCategoriesFor(channelLower, eid);
    auto has = [&](const char* c) { return std::find(cats.begin(), cats.end(), c) != cats.end(); };
    json category = json::array(), type = json::array();
    if (has("process_creation"))        { category = {"process"}; type = {"start"}; }
    else if (has("process_termination")){ category = {"process"}; type = {"end"}; }
    else if (has("network_connection")) { category = {"network"}; type = {"connection", "start"}; }
    else if (has("dns_query"))          { category = {"network"}; type = {"protocol"};
                                          d["network"]["protocol"] = "dns";
                                          setIfUsable(d["dns"]["question"], "name", f("queryname")); }
    else if (has("file_event") || has("file_change")) {
        category = {"file"}; type = {has("file_event") ? "creation" : "change"};
        setIfUsable(d["file"], "path", f("targetfilename"));
        if (usableValue(f("targetfilename"))) d["file"]["name"] = basename(f("targetfilename"));
    }
    else if (has("file_delete") || has("file_delete_detected")) {
        category = {"file"}; type = {"deletion"};
        setIfUsable(d["file"], "path", f("targetfilename"));
        if (usableValue(f("targetfilename"))) d["file"]["name"] = basename(f("targetfilename"));
    }
    else if (has("image_load"))         { category = {"library"}; type = {"start"};
                                          setIfUsable(d["dll"], "path", f("imageloaded"));
                                          if (usableValue(f("imageloaded"))) d["dll"]["name"] = basename(f("imageloaded")); }
    else if (has("driver_load"))        { category = {"driver"}; type = {"start"};
                                          setIfUsable(d["dll"], "path", f("imageloaded")); }
    else if (has("registry_add"))       { category = {"registry"}; type = {"creation"};
                                          setIfUsable(d["registry"], "path", f("targetobject")); }
    else if (has("registry_delete"))    { category = {"registry"}; type = {"deletion"};
                                          setIfUsable(d["registry"], "path", f("targetobject")); }
    else if (has("registry_set") || has("registry_rename")) {
        category = {"registry"}; type = {"change"};
        setIfUsable(d["registry"], "path", f("targetobject"));
        setIfUsable(d["registry"], "value", f("details"));
    }
    else if (has("create_remote_thread") || has("process_access")) {
        category = {"process"}; type = {"access"};
        setIfUsable(d["process"]["target"], "executable", f("targetimage"));
        setPid(d["process"]["target"], "pid", f("targetprocessid"));
    }
    else if (has("pipe_created"))       { category = {"file"}; type = {"creation"};
                                          setIfUsable(d["file"], "name", f("pipename")); }
    else if (has("ps_script") || has("ps_module") || has("ps_classic_start") ||
             has("ps_classic_provider_start") || has("ps_classic_script")) {
        category = {"process"}; type = {"info"};
    }
    else if (!cats.empty())             { category = {"process"}; type = {"info"}; }

    // (c) per-event specializations
    const bool security = !lin && channelLower == "security";
    const bool sysmon = !lin && channelLower == "microsoft-windows-sysmon/operational";
    if (lin) {
        if (channelLower == "audit") ecsLinuxAudit(d, evt, category, type);
        else ecsLinuxSyslog(d, evt, channelLower, category, type);
    } else if (security && eid == 4688) {
        d["event"]["action"] = "created-process";
        setPid(d["process"], "pid", f("newprocessid"));
        setIfUsable(d["process"], "executable", f("newprocessname"));
        if (usableValue(f("newprocessname"))) d["process"]["name"] = basename(f("newprocessname"));
        setIfUsable(d["process"], "command_line", f("commandline"));
        setPid(d["process"]["parent"], "pid", f("processid"));
        setIfUsable(d["process"]["parent"], "executable", f("parentprocessname"));
        if (usableValue(f("parentprocessname"))) d["process"]["parent"]["name"] = basename(f("parentprocessname"));
        setIfUsable(d["user"], "name", f("subjectusername"));
        setIfUsable(d["user"], "domain", f("subjectdomainname"));
        setIfUsable(d["user"], "id", f("subjectusersid"));
        setIfUsable(d["winlog"]["logon"], "id", f("subjectlogonid"));
        setIfUsable(d["process"]["user"], "name", f("targetusername"));
        setIfUsable(d["process"]["user"], "domain", f("targetdomainname"));
    } else if (security && (eid == 4624 || eid == 4625)) {
        category = {"authentication"}; type = {"start"};
        d["event"]["action"] = eid == 4624 ? "logged-in" : "logon-failed";
        d["event"]["outcome"] = eid == 4624 ? "success" : "failure";
        setIfUsable(d["user"], "name", f("targetusername"));
        setIfUsable(d["user"], "domain", f("targetdomainname"));
        setIfUsable(d["user"], "id", f("targetusersid"));
        setIfUsable(d["source"], "ip", f("ipaddress"));
        setPid(d["source"], "port", f("ipport"));
        setIfUsable(d["source"], "domain", f("workstationname"));
        if (const char* lt = logonTypeName(f("logontype"))) d["winlog"]["logon"]["type"] = lt;
        setIfUsable(d["winlog"]["logon"], "id", f("targetlogonid"));
        setIfUsable(d["process"], "executable", f("processname"));
        if (usableValue(f("processname"))) d["process"]["name"] = basename(f("processname"));
        setPid(d["process"], "pid", f("processid"));
    } else if (security && eid == 5156) {
        type = {"connection", "allowed"};
        d["event"]["action"] = "connection-allowed";
        setIfUsable(d["source"], "ip", f("sourceaddress"));
        setPid(d["source"], "port", f("sourceport"));
        setIfUsable(d["destination"], "ip", f("destaddress"));
        setPid(d["destination"], "port", f("destport"));
        std::string proto = f("protocol");
        if (proto == "6") d["network"]["transport"] = "tcp";
        else if (proto == "17") d["network"]["transport"] = "udp";
        else if (proto == "1") d["network"]["transport"] = "icmp";
        else if (!proto.empty()) d["network"]["transport"] = proto;
        std::string dir = f("direction");
        if (dir == "%%14592") d["network"]["direction"] = "ingress";
        else if (dir == "%%14593") d["network"]["direction"] = "egress";
        setPid(d["process"], "pid", f("processid"));
        setIfUsable(d["process"], "executable", f("application"));
    } else if (security && eid == 1102) {
        category = {"iam"}; type = {"admin", "change"};
        d["event"]["action"] = "audit-log-cleared";
        setIfUsable(d["user"], "name", f("subjectusername"));
        setIfUsable(d["user"], "domain", f("subjectdomainname"));
        setIfUsable(d["user"], "id", f("subjectusersid"));
        setIfUsable(d["winlog"]["logon"], "id", f("subjectlogonid"));
    } else if (sysmon && eid == 1) {
        d["event"]["action"] = "process-create";
        setPid(d["process"], "pid", f("processid"));
        setIfUsable(d["process"], "entity_id", f("processguid"));
        setIfUsable(d["process"], "executable", f("image"));
        if (usableValue(f("image"))) d["process"]["name"] = basename(f("image"));
        setIfUsable(d["process"], "command_line", f("commandline"));
        setIfUsable(d["process"], "working_directory", f("currentdirectory"));
        setPid(d["process"]["parent"], "pid", f("parentprocessid"));
        setIfUsable(d["process"]["parent"], "entity_id", f("parentprocessguid"));
        setIfUsable(d["process"]["parent"], "executable", f("parentimage"));
        if (usableValue(f("parentimage"))) d["process"]["parent"]["name"] = basename(f("parentimage"));
        setIfUsable(d["process"]["parent"], "command_line", f("parentcommandline"));
        if (usableValue(f("hashes"))) { json h; parseSysmonHashes(f("hashes"), h); if (!h.empty()) d["process"]["hash"] = h; }
        setIfUsable(d["process"]["pe"], "original_file_name", f("originalfilename"));
        setIfUsable(d["process"]["pe"], "company", f("company"));
        setIfUsable(d["process"]["pe"], "description", f("description"));
        setIfUsable(d["process"]["pe"], "product", f("product"));
        setIfUsable(d["process"]["pe"], "file_version", f("fileversion"));
        splitDomainUser(f("user"), d["user"]);
    } else if (sysmon && eid == 3) {
        d["event"]["action"] = "network-connection";
        setIfUsable(d["source"], "ip", f("sourceip"));
        setPid(d["source"], "port", f("sourceport"));
        setIfUsable(d["source"], "domain", f("sourcehostname"));
        setIfUsable(d["destination"], "ip", f("destinationip"));
        setPid(d["destination"], "port", f("destinationport"));
        setIfUsable(d["destination"], "domain", f("destinationhostname"));
        setIfUsable(d["network"], "transport", lowerAscii(f("protocol")));
        if (lowerAscii(f("sourceisipv6")) == "true") d["network"]["type"] = "ipv6";
        else if (usableValue(f("sourceisipv6"))) d["network"]["type"] = "ipv4";
        if (usableValue(f("initiated"))) d["network"]["direction"] = lowerAscii(f("initiated")) == "true" ? "egress" : "ingress";
        setPid(d["process"], "pid", f("processid"));
        setIfUsable(d["process"], "entity_id", f("processguid"));
        setIfUsable(d["process"], "executable", f("image"));
        if (usableValue(f("image"))) d["process"]["name"] = basename(f("image"));
        splitDomainUser(f("user"), d["user"]);
    } else if (channelLower == "system" && eid == 7045) {
        category = {"configuration"}; type = {"creation"};
        d["event"]["action"] = "service-installed";
        setIfUsable(d["service"], "name", f("servicename"));
        setIfUsable(d["service"], "type", f("servicetype"));
        std::string ip = f("imagepath");
        if (usableValue(ip)) {
            d["process"]["command_line"] = ip;
            std::string exe;
            if (ip[0] == '"') { auto q = ip.find('"', 1); exe = ip.substr(1, q == std::string::npos ? std::string::npos : q - 1); }
            else { auto sp = ip.find(' '); exe = ip.substr(0, sp); }
            d["process"]["executable"] = exe;
            d["process"]["name"] = basename(exe);
        }
        setIfUsable(d["user"], "name", f("accountname"));
    } else if (channelLower == "microsoft-windows-powershell/operational" && eid == 4104) {
        d["event"]["action"] = "script-block-logged";
        setIfUsable(d["powershell"]["file"], "script_block_text", f("scriptblocktext"));
        setIfUsable(d["powershell"]["file"], "script_block_id", f("scriptblockid"));
        setPid(d["powershell"], "sequence", f("messagenumber"));
        setPid(d["powershell"], "total", f("messagetotal"));
        setIfUsable(d["file"], "path", f("path"));
        if (usableValue(f("path"))) d["file"]["name"] = basename(f("path"));
    }
    if (!category.empty()) d["event"]["category"] = category;
    if (!type.empty()) d["event"]["type"] = type;

    // Alert decoration
    if (isAlert) {
        d["message"] = ctx.message;
        if (ctx.rule) {
            d["rule"]["id"] = ctx.rule->id;
            d["rule"]["name"] = ctx.rule->name;
            d["rule"]["description"] = ctx.rule->description;
            if (!ctx.rule->category.empty()) d["rule"]["category"] = ctx.rule->category;
            d["rule"]["ruleset"] = "sigma";
            d["event"]["severity"] = sigmaSeverityScore(ctx.rule->level);
            for (const auto& t : ctx.rule->tags) tags.push_back(t);
            std::vector<std::string> techniques, tactics;
            threatFromTags(ctx.rule->tags, techniques, tactics);
            if (!techniques.empty() || !tactics.empty()) {
                d["threat"]["framework"] = "MITRE ATT&CK";
                if (!techniques.empty()) d["threat"]["technique"]["id"] = techniques;
                if (!tactics.empty()) d["threat"]["tactic"]["name"] = tactics;
            }
        }
        d["elf"]["action"] = ctx.action;
        if (ctx.alsoMatched && !ctx.alsoMatched->empty()) d["elf"]["also_matched"] = alsoMatchedArray(ctx);
        std::vector<const BufferedEvent*> ev;
        size_t dropped = cappedEvidence(ctx, ev);
        if (!ev.empty()) {
            d["elf"]["evidence_kind"] = ctx.evidenceIsSequence ? "sequence" : "window";
            json arr = json::array();
            for (const auto* x : ev) {
                json r;
                r["@timestamp"] = eventTimestampIso(*x);
                r["event"]["code"] = std::to_string(eventIdOf(*x));
                if (lin) {
                    r["event"]["sequence"] = recordIdOf(*x);
                    r["journald"]["fields"] = eventDataObject(*x);
                } else {
                    r["winlog"]["record_id"] = recordIdOf(*x);
                    r["winlog"]["event_data"] = eventDataObject(*x);
                }
                arr.push_back(r);
            }
            d["elf"]["evidence"] = arr;
            if (dropped) d["elf"]["evidence_truncated"] = dropped;
        }
    } else {
        d["elf"]["action"] = ctx.action;
        if (ctx.rule) { d["rule"]["id"] = ctx.rule->id; d["rule"]["name"] = ctx.rule->name; }
    }
    d["tags"] = tags;
    if (!ctx.alertId.empty()) d["elf"]["alert_id"] = ctx.alertId;
    pruneEmpty(d);
    return d;
}

// --- hec --------------------------------------------------------------------

json wrapHec(json doc, const BufferedEvent& evt, const FormatContext& ctx, bool isAlert) {
    json env;
    env["time"] = eventEpochSeconds(evt);
    env["host"] = fieldStr(evt, "computer");
    env["source"] = "elf";
    std::string st = (ctx.dest && !ctx.dest->opts.sourcetype.empty())
        ? ctx.dest->opts.sourcetype : (isAlert ? "elf:alert" : "elf:event");
    env["sourcetype"] = st;
    if (ctx.dest && !ctx.dest->opts.index.empty()) env["index"] = ctx.dest->opts.index;
    env["event"] = std::move(doc);
    return env;
}

// --- gelf -------------------------------------------------------------------

json buildGelf(const BufferedEvent& evt, const FormatContext& ctx, bool isAlert) {
    json g;
    g["version"] = "1.1";
    g["host"] = fieldStr(evt, "computer");
    const int eid = eventIdOf(evt);
    std::string ruleName = ctx.rule ? ctx.rule->name : std::string();
    g["short_message"] = isAlert
        ? (ruleName.empty() ? "ELF alert" : ruleName)
        : (fieldStr(evt, "channel") + " " + std::to_string(eid));
    g["timestamp"] = eventEpochSeconds(evt);
    g["level"] = gelfLevel(ctx.rule ? ctx.rule->level : "", isAlert);
    // GELF forbids nested objects: everything else is a flat "_" field.
    g["_elf_kind"] = isAlert ? "alert" : "event";
    g["_elf_action"] = ctx.action;
    g["_elf_agent_id"] = ctx.agentId;
    if (!ctx.alertId.empty()) g["_elf_alert_id"] = ctx.alertId;
    if (ctx.rule) {
        g["_elf_rule_id"] = ctx.rule->id;
        g["_elf_rule_name"] = ctx.rule->name;
        g["_elf_level"] = ctx.rule->level;
        if (!ctx.rule->category.empty()) g["_elf_category"] = ctx.rule->category;
    }
    g["_event_id"] = eid;
    g["_record_id"] = recordIdOf(evt);
    g["_channel"] = fieldStr(evt, "channel");
    g["_provider"] = fieldStr(evt, "provider");
    g["_event_time"] = eventTimestampIso(evt);
    forEachEventData(evt.xml, [&](const std::wstring& name, const std::wstring& value) {
        g["_event_data_" + wideToUtf8(name)] = wideToUtf8(value);
    });
    if (isAlert) {
        g["_elf_message"] = ctx.message;
        if (ctx.alsoMatched && !ctx.alsoMatched->empty()) {
            std::string joined;
            for (const auto& id : *ctx.alsoMatched) { if (!joined.empty()) joined += ","; joined += id; }
            g["_elf_also_matched"] = joined;
        }
        std::vector<const BufferedEvent*> ev;
        size_t dropped = cappedEvidence(ctx, ev);
        if (!ev.empty()) {
            g["_elf_evidence_count"] = static_cast<int>(ev.size()) + static_cast<int>(dropped);
            std::string ids;
            for (const auto* x : ev) { if (!ids.empty()) ids += ","; ids += std::to_string(recordIdOf(*x)); }
            g["_elf_evidence_record_ids"] = ids;
        }
        g["full_message"] = wideToUtf8(evt.xml);
    }
    return g;
}

// --- sentinel ---------------------------------------------------------------

json buildSentinelRow(const BufferedEvent& evt, const FormatContext& ctx, bool isAlert) {
    json r;
    r["TimeGenerated"] = eventTimestampIso(evt);
    r["Host"] = fieldStr(evt, "computer");
    r["Channel"] = fieldStr(evt, "channel");
    r["Provider"] = fieldStr(evt, "provider");
    r["EventId"] = eventIdOf(evt);
    r["RecordId"] = recordIdOf(evt);
    r["Kind"] = isAlert ? "alert" : "event";
    r["Action"] = ctx.action;
    r["AgentId"] = ctx.agentId;
    if (!ctx.alertId.empty()) r["AlertId"] = ctx.alertId;
    if (ctx.rule) {
        r["RuleId"] = ctx.rule->id;
        r["RuleName"] = ctx.rule->name;
        r["Level"] = ctx.rule->level;
        if (!ctx.rule->category.empty()) r["Category"] = ctx.rule->category;
    }
    r["EventData"] = eventDataObject(evt);
    if (isAlert) {
        r["Message"] = ctx.message;
        r["AlsoMatched"] = alsoMatchedArray(ctx);
        std::vector<const BufferedEvent*> ev;
        size_t dropped = cappedEvidence(ctx, ev);
        json arr = json::array();
        for (const auto* x : ev) {
            json e;
            e["TimeCreated"] = eventTimestampIso(*x);
            e["EventId"] = eventIdOf(*x);
            e["RecordId"] = recordIdOf(*x);
            e["EventData"] = eventDataObject(*x);
            arr.push_back(e);
        }
        r["Evidence"] = arr;
        if (dropped) r["EvidenceTruncated"] = dropped;
        r["EventXml"] = wideToUtf8(evt.xml);
    }
    return r;
}

// --- raw --------------------------------------------------------------------

std::string rawXmlLines(const std::vector<BufferedEvent>& events) {
    std::ostringstream ss;
    for (size_t i = 0; i < events.size(); ++i) {
        // wideToUtf8 (WideCharToMultiByte); the naive std::string(w.begin(),
        // w.end()) truncates each wchar_t to a single char and produces
        // invalid UTF-8 for non-ASCII content (rendered as U+FFFD).
        if (i) ss << "\n";
        ss << wideToUtf8(events[i].xml);
    }
    return ss.str();
}

std::string alertToRawPretty(const BufferedEvent& evt, const std::string& ruleId,
                             const std::string& message,
                             const std::vector<BufferedEvent>& evidenceEvents,
                             const std::string& evidenceLabel,
                             const std::vector<std::string>& alsoMatched,
                             const std::string& alertId) {
    std::ostringstream ss;
    ss << "# ELF Alert\n"
       << "rule_id: " << ruleId << "\n";
    if (!alertId.empty()) ss << "alert_id: " << alertId << "\n";
    ss << "message: " << message << "\n"
       << "timestamp: " << isoTime(evt.receivedAt) << "\n";
    // Rules that also matched this event but lost the severity race. A
    // separate header line (never `rule_id:`) so consumers grepping for the
    // firing rule are not misled.
    if (!alsoMatched.empty()) {
        ss << "also_matched: ";
        for (size_t i = 0; i < alsoMatched.size(); ++i) {
            if (i) ss << ", ";
            ss << alsoMatched[i];
        }
        ss << "\n";
    }
    ss << "---\n"
       << prettyPrintXml(evt.xml);
    // Correlation evidence: the events that formed the sequence / filled
    // the threshold window. Appended as a labeled section so an analyst
    // reading the file sees every contributing event, not just the trigger.
    if (!evidenceEvents.empty()) {
        ss << "\n\n# " << evidenceLabel << " (" << evidenceEvents.size() << ")\n";
        for (size_t i = 0; i < evidenceEvents.size(); ++i) {
            ss << "# --- " << evidenceLabel << " [" << (i + 1) << "] ---\n"
               << prettyPrintXml(evidenceEvents[i].xml);
            if (i + 1 < evidenceEvents.size()) ss << "\n";
        }
    }
    return ss.str();
}

// --- Dispatch ---------------------------------------------------------------

static std::string dumpDoc(const json& j) {
    // `replace` so a stray invalid UTF-16 surrogate in event data can never
    // throw on the engine thread.
    return j.dump(-1, ' ', false, json::error_handler_t::replace);
}

static const std::string& formatOf(const FormatContext& ctx) {
    static const std::string raw = "raw";
    return ctx.dest ? ctx.dest->opts.format : raw;
}

static void addAuthHeader(FormattedPayload& p, const FormatContext& ctx) {
    if (!ctx.dest) return;
    const auto& o = ctx.dest->opts;
    if (o.format == "hec") {
        if (!o.token.empty()) p.headers.emplace_back("Authorization", "Splunk " + o.token);
    } else if (o.format == "sentinel") {
        // Bearer token attached by the destination worker (OAuth2).
    } else if (!o.token.empty()) {
        p.headers.emplace_back("Authorization", "Bearer " + o.token);
    }
}

// Build one document per event for the structured formats.
static json docFor(const BufferedEvent& evt, const FormatContext& ctx, bool isAlert,
                   const std::string& format) {
    if (format == "ecs") return buildEcsDoc(evt, ctx, isAlert);
    if (format == "hec") {
        bool ecs = ctx.dest && ctx.dest->opts.event == "ecs";
        return wrapHec(ecs ? buildEcsDoc(evt, ctx, isAlert) : buildJsonDoc(evt, ctx, isAlert),
                       evt, ctx, isAlert);
    }
    if (format == "gelf") return buildGelf(evt, ctx, isAlert);
    if (format == "sentinel") return buildSentinelRow(evt, ctx, isAlert);
    return buildJsonDoc(evt, ctx, isAlert);
}

// Chunking limits per format.
static constexpr size_t kMaxDocsPerPost = 1000;
static constexpr size_t kMaxNdjsonBytes = 2 * 1024 * 1024;
static constexpr size_t kMaxSentinelBytes = 1024 * 1024;   // Logs Ingestion API limit

static std::vector<FormattedPayload> packDocs(const std::vector<std::string>& docs,
                                              const FormatContext& ctx) {
    const std::string& fmt = formatOf(ctx);
    std::vector<FormattedPayload> out;
    if (fmt == "gelf") {
        // One message per request (GELF HTTP inputs take a single message).
        for (const auto& d : docs) {
            FormattedPayload p;
            p.body = d;
            p.contentType = "application/json";
            addAuthHeader(p, ctx);
            out.push_back(std::move(p));
        }
        return out;
    }
    const bool ndjson = (fmt == "json" || fmt == "ecs");
    const bool array = (fmt == "sentinel");
    const size_t maxBytes = array ? kMaxSentinelBytes : kMaxNdjsonBytes;
    FormattedPayload cur;
    size_t count = 0;
    auto flush = [&]() {
        if (count == 0) return;
        if (array) cur.body += "]";
        cur.contentType = ndjson ? "application/x-ndjson" : "application/json";
        addAuthHeader(cur, ctx);
        out.push_back(std::move(cur));
        cur = FormattedPayload();
        count = 0;
    };
    for (const auto& d : docs) {
        if (count > 0 && (count >= kMaxDocsPerPost || cur.body.size() + d.size() + 2 > maxBytes)) {
            flush();
        }
        if (count == 0) cur.body = array ? "[" : "";
        else cur.body += array ? "," : "\n";
        cur.body += d;
        ++count;
    }
    flush();
    return out;
}

std::vector<FormattedPayload> formatEvents(const std::vector<BufferedEvent>& events,
                                           const FormatContext& ctx) {
    const std::string& fmt = formatOf(ctx);
    if (fmt == "raw") {
        FormattedPayload p;
        p.body = rawXmlLines(events);
        return {p};
    }
    std::vector<std::string> docs;
    docs.reserve(events.size());
    for (const auto& e : events) docs.push_back(dumpDoc(docFor(e, ctx, false, fmt)));
    return packDocs(docs, ctx);
}

std::vector<FormattedPayload> formatAlert(const BufferedEvent& trigger,
                                          const FormatContext& ctx) {
    const std::string& fmt = formatOf(ctx);
    if (fmt == "raw") {
        static const std::vector<BufferedEvent> kNone;
        static const std::vector<std::string> kNoIds;
        FormattedPayload p;
        p.body = alertToRawPretty(trigger, ctx.rule ? ctx.rule->id : "", ctx.message,
                                  ctx.evidence ? *ctx.evidence : kNone,
                                  ctx.evidenceIsSequence ? "Sequence events" : "Window events",
                                  ctx.alsoMatched ? *ctx.alsoMatched : kNoIds,
                                  ctx.alertId);
        return {p};
    }
    std::vector<std::string> docs{dumpDoc(docFor(trigger, ctx, true, fmt))};
    return packDocs(docs, ctx);
}

} // namespace elf
