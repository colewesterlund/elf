#include "Config.h"
#include "Console.h"
#include <fstream>
#include <algorithm>
#include <iostream>
#include <sstream>
#include <filesystem>
#include "Platform.h"

namespace elf {

const Destination* Config::resolveDestination(const std::string& name) const {
    auto it = destinations.find(name);
    if (it == destinations.end()) return nullptr;
    return &it->second;
}

// Resolve the directory containing the running exe (trailing backslash).
// Windows services start with CWD = System32, so any relative path in
// config.ini (e.g. `directory=rules`) would resolve against System32 and
// silently fail. We anchor relative paths to the exe directory instead,
// which is where config.ini lives (Program Files\ELFAgent) and where the
// install script creates the rules/lists/output subdirectories.

// Return true if `path` is absolute (drive letter, UNC, or starts with `/`
// or `\`). Used to decide whether to anchor a relative path to the exe dir.

// Resolve a relative directory path against the exe directory. Absolute
// paths and environment-variable-expanded paths are returned unchanged.
// Returns the resolved path with a trailing backslash so concatenation
// (e.g. dir + "file.yaml") works uniformly.
static std::string resolveDirAgainstExe(const std::string& dir) {
    if (dir.empty()) return dir;
    if (platformIsAbsolutePath(dir)) {
        std::string out = dir;
        if (out.back() != '\\' && out.back() != '/') out += platformPathSep();
        return out;
    }
    std::string exeDir = platformExeDir();
    if (exeDir.empty()) {
        // Couldn't determine exe dir (very unusual); fall back to the
        // path as-is so the caller still has something to try.
        std::string out = dir;
        if (out.back() != '\\' && out.back() != '/') out += platformPathSep();
        return out;
    }
    return exeDir + dir + platformPathSep();
}

// --- Data root + file destination resolution ---

static std::string g_dataRootOverride;
static std::mutex g_dataRootMutex;

void setDataRootDir(const std::string& dir) {
    std::lock_guard<std::mutex> lock(g_dataRootMutex);
    g_dataRootOverride = dir;
    if (!g_dataRootOverride.empty() && g_dataRootOverride.back() != '\\' &&
        g_dataRootOverride.back() != '/') {
        g_dataRootOverride += platformPathSep();
    }
}

std::string dataRootDir() {
    {
        std::lock_guard<std::mutex> lock(g_dataRootMutex);
        if (!g_dataRootOverride.empty()) return g_dataRootOverride;
    }
    std::string p = platformDefaultDataDir();
    std::error_code ec;
    if (!p.empty() && std::filesystem::is_directory(p, ec)) return p;
    return platformExeDir();
}

std::string resolveFileDestinationPath(const std::string& path) {
    if (path.empty()) return path;
    // http(s):// destinations keep the full URL as the path; leave as-is.
    if (path.rfind("http://", 0) == 0 || path.rfind("https://", 0) == 0) {
        return path;
    }
    std::string p = path;
    // file:///C:/x parses to "/C:/x": drop the slash in front of the drive.
    if (p.size() >= 3 && (p[0] == '/' || p[0] == '\\') &&
        std::isalpha((unsigned char)p[1]) && p[2] == ':') {
        p = p.substr(1);
    }
    if (platformIsAbsolutePath(p)) return p;
    if (p.rfind("./", 0) == 0 || p.rfind(".\\", 0) == 0) p = p.substr(2);
    return dataRootDir() + p;
}

ConfigStore& ConfigStore::instance() {
    static ConfigStore s;
    return s;
}

// Trim whitespace from both ends of a string (in place).
static void trim(std::string& s) {
    s.erase(s.begin(), std::find_if(s.begin(), s.end(),
        [](unsigned char ch) { return !std::isspace(ch); }));
    s.erase(std::find_if(s.rbegin(), s.rend(),
        [](unsigned char ch) { return !std::isspace(ch); }).base(), s.end());
}

// --- Destination URL parsing ---

static std::string percentDecode(const std::string& s) {
    std::string out;
    out.reserve(s.size());
    for (size_t i = 0; i < s.size(); ++i) {
        if (s[i] == '%' && i + 2 < s.size() && std::isxdigit((unsigned char)s[i + 1]) &&
            std::isxdigit((unsigned char)s[i + 2])) {
            out += static_cast<char>(std::stoi(s.substr(i + 1, 2), nullptr, 16));
            i += 2;
        } else if (s[i] == '+') {
            out += ' ';
        } else {
            out += s[i];
        }
    }
    return out;
}

// `env:NAME` → the value of environment variable NAME (empty + error if
// unset), anything else unchanged. Lets a site keep SIEM tokens out of the
// URL that is stored on the server.
static std::string resolveSecretValue(const std::string& v, const std::string& destName,
                                      const char* key) {
    if (v.rfind("env:", 0) != 0) return v;
    std::string var = v.substr(4);
    std::string val = platformGetEnv(var);
    if (val.empty()) {
        logError("[Config] destination '" + destName + "': " + key + "=env:" + var +
                 " but that environment variable is not set; the value is empty.");
        return "";
    }
    return val;
}

static bool isSecretKey(const std::string& k) {
    return k == "token" || k == "secret" || k == "apikey";
}

std::string redactedUrl(const std::string& url) {
    auto q = url.find('?');
    if (q == std::string::npos) return url;
    std::string out = url.substr(0, q + 1);
    std::string query = url.substr(q + 1);
    size_t pos = 0;
    while (pos <= query.size()) {
        size_t amp = query.find('&', pos);
        std::string kv = query.substr(pos, amp == std::string::npos ? std::string::npos : amp - pos);
        auto eq = kv.find('=');
        std::string k = kv.substr(0, eq);
        if (eq != std::string::npos && isSecretKey(k)) kv = k + "=***";
        out += kv;
        if (amp == std::string::npos) break;
        out += '&';
        pos = amp + 1;
    }
    return out;
}

Destination parseDestinationUrl(const std::string& name, const std::string& url) {
    Destination d;
    d.name = name;
    d.url = url;

    // Split off the query string. Windows file names cannot contain '?', so
    // this is unambiguous for file:// too.
    std::string base = url, query;
    auto qpos = url.find('?');
    if (qpos != std::string::npos) {
        base = url.substr(0, qpos);
        query = url.substr(qpos + 1);
    }

    // file:///path  -> scheme=file, path=/path
    // http://host:port/path -> scheme=http, path=full url (minus our keys)
    auto schemeEnd = base.find("://");
    if (schemeEnd == std::string::npos) {
        // No scheme: treat as a local file path.
        d.scheme = "file";
        d.path = base;
    } else {
        d.scheme = base.substr(0, schemeEnd);
        if (d.scheme == "file") {
            // file://<path>; skip the two slashes after :
            d.path = base.substr(schemeEnd + 3);
        } else {
            // http(s) etc.: keep the full URL as the path for the client.
            d.path = base;
        }
    }

    // Consume known option keys; pass the rest through to the endpoint
    // (e.g. Elastic's ?pipeline=, Azure's api-version=).
    std::string passthrough;
    size_t pos = 0;
    while (!query.empty() && pos <= query.size()) {
        size_t amp = query.find('&', pos);
        std::string kv = query.substr(pos, amp == std::string::npos ? std::string::npos : amp - pos);
        pos = (amp == std::string::npos) ? query.size() + 1 : amp + 1;
        if (kv.empty()) continue;
        auto eq = kv.find('=');
        std::string k = percentDecode(kv.substr(0, eq));
        std::string v = (eq == std::string::npos) ? "" : percentDecode(kv.substr(eq + 1));
        std::transform(k.begin(), k.end(), k.begin(),
            [](unsigned char c) { return static_cast<char>(::tolower(c)); });
        auto& o = d.opts;
        if (k == "format") {
            std::transform(v.begin(), v.end(), v.begin(),
                [](unsigned char c) { return static_cast<char>(::tolower(c)); });
            o.format = v;
        } else if (k == "event") {
            o.event = v;
        } else if (k == "token") {
            o.token = resolveSecretValue(v, name, "token");
        } else if (k == "index") {
            o.index = v;
        } else if (k == "sourcetype") {
            o.sourcetype = v;
        } else if (k == "tenant") {
            o.tenant = v;
        } else if (k == "client") {
            o.client = v;
        } else if (k == "secret") {
            o.secret = resolveSecretValue(v, name, "secret");
        } else if (k == "insecure") {
            o.insecure = (v == "1" || v == "true" || v == "yes");
        } else if (d.scheme != "file") {
            if (!passthrough.empty()) passthrough += '&';
            passthrough += kv;
        }
    }
    if (!passthrough.empty()) d.path += "?" + passthrough;

    static const char* kFormats[] = {"raw", "json", "ecs", "hec", "gelf", "sentinel"};
    bool known = false;
    for (const char* f : kFormats) if (d.opts.format == f) known = true;
    if (!known) {
        logError("[Config] destination '" + name + "': unknown format '" + d.opts.format +
                 "' (valid: raw, json, ecs, hec, gelf, sentinel); using raw.");
        d.opts.format = "raw";
    }
    if (d.opts.format == "hec" && d.opts.event.empty()) d.opts.event = "json";
    if (d.opts.insecure && d.scheme != "file") {
        logNotice("[Config] destination '" + name + "' has insecure=1: certificate "
                  "errors are ignored / secrets may travel over cleartext (lab use only).");
    }
    return d;
}

bool ConfigStore::load(const std::string& path) {
    Config cfg;
    std::ifstream file(path);
    if (!file.is_open()) {
        logError("[Config] Could not open " + path);
        return false;
    }

    std::string line;
    std::string section;

    while (std::getline(file, line)) {
        // Handle UTF-8 BOM on the first line.
        if (line.size() >= 3 && line[0] == '\xEF' && line[1] == '\xBB' && line[2] == '\xBF') {
            line = line.substr(3);
        }
        // Strip trailing CR (CRLF files).
        if (!line.empty() && line.back() == '\r') line.pop_back();
        trim(line);

        if (line.empty() || line[0] == ';' || line[0] == '#') continue;

        if (line.front() == '[' && line.back() == ']') {
            section = line.substr(1, line.size() - 2);
            continue;
        }

        size_t eq = line.find('=');
        if (eq == std::string::npos) continue;
        std::string key = line.substr(0, eq);
        std::string val = line.substr(eq + 1);
        trim(key);
        trim(val);

        if (section == "buffer") {
            if (key == "retention_seconds") cfg.retention_seconds = std::stoi(val);
            else if (key == "max_events") cfg.max_events = static_cast<size_t>(std::stoull(val));
        } else if (section == "rules") {
            if (key == "directory") cfg.rules_directory = val;
        } else if (section == "lists") {
            if (key == "directory") cfg.lists_directory = val;
        } else if (section == "server") {
            if (key == "url") cfg.server.url = val;
            else if (key == "poll_interval_seconds") cfg.server.poll_interval_seconds = std::stoi(val);
            else if (key == "agent_id") cfg.server.agent_id = val;
            else if (key == "auth_token") cfg.server.auth_token = val;
        } else if (section == "collect") {
            // [collect] is optional. The only key is `channels`: a
            // comma-separated list of Windows channels to subscribe to
            // (with all events). When non-empty, this overrides the
            // auto-derived channels from rules. Channel names are
            // case-insensitive on Windows; we store them as-is and
            // lowercase at use time.
            if (key == "channels") {
                std::stringstream ss(val);
                std::string item;
                while (std::getline(ss, item, ',')) {
                    trim(item);
                    if (!item.empty()) cfg.collect.channels.push_back(item);
                }
            }
        } else if (section == "logging") {
            // [logging] is optional. Controls verbosity, rotation, and
            // (optionally) the log directory. Defaults give a bounded,
            // low-verbosity log suitable for unattended service operation.
            if (key == "level") {
                cfg.logging.level = val;
            } else if (key == "max_file_size_mb") {
                cfg.logging.max_file_size_mb = std::stoi(val);
            } else if (key == "max_files") {
                cfg.logging.max_files = std::stoi(val);
            } else if (key == "directory") {
                cfg.logging.directory = val;
            }
        } else if (section == "spool") {
            // [spool] is optional. Controls the disk-backed pending-POST
            // queue size cap and (optionally) its directory. Defaults give
            // a 100MB bounded spool so a long network outage can't fill
            // the disk.
            if (key == "max_spool_mb") {
                cfg.spool.max_spool_mb = std::stoi(val);
            } else if (key == "directory") {
                cfg.spool.directory = val;
            }
        } else if (section == "destinations") {
            cfg.destinations[key] = parseDestinationUrl(key, val);
        } else if (section == "paths") {
            // [paths] is optional. `data_directory` overrides the writable
            // data root that relative file:// destinations resolve against.
            if (key == "data_directory" && !val.empty()) {
                setDataRootDir(resolveDirAgainstExe(val));
            }
        }
    }

    // Resolve relative paths against the exe directory. Windows services
    // start with CWD = System32, so a relative `directory=rules` would
    // resolve to C:\Windows\System32\rules (doesn't exist) and silently
    // load zero rules. Anchoring to the exe dir (Program Files\ELFAgent)
    // makes the paths work regardless of CWD. Absolute paths are passed
    // through unchanged. This is the safety net for hand-edited config.ini
    // files; the install script also writes absolute paths now.
    cfg.rules_directory = resolveDirAgainstExe(cfg.rules_directory);
    cfg.lists_directory = resolveDirAgainstExe(cfg.lists_directory);
    if (!cfg.logging.directory.empty()) {
        cfg.logging.directory = resolveDirAgainstExe(cfg.logging.directory);
    }
    if (!cfg.spool.directory.empty()) {
        cfg.spool.directory = resolveDirAgainstExe(cfg.spool.directory);
    }
    // File destinations resolve against the DATA root (not the exe dir):
    // that is the only tree the service account can write.
    for (auto& [name, dest] : cfg.destinations) {
        if (dest.scheme == "file") {
            dest.path = resolveFileDestinationPath(dest.path);
        }
    }

    std::lock_guard<std::mutex> lock(m_mutex);
    m_config = std::move(cfg);
    return true;
}

Config ConfigStore::get() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_config;
}

void ConfigStore::set(const Config& cfg) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_config = cfg;
}

} // namespace elf
