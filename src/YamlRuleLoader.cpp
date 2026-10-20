#include "YamlRuleLoader.h"
#include "Console.h"
#include <yaml-cpp/yaml.h>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <algorithm>
#include <cctype>

namespace elf {

// The regular files in `dir` with one of the extensions, sorted by name.
// Directory enumeration order is whatever the filesystem returns (NTFS
// sorts, ext4 hashes), and rule order decides which of two equally severe
// rules wins a tie, so the load order has to be the same on every host.
// Enumeration errors are ignored: a file that vanishes between listing and
// loading (the poll thread deleting a stale rule) is handled by the loader.
static std::vector<std::filesystem::path> sortedFiles(const std::string& dir,
                                                      std::initializer_list<const char*> exts) {
    std::vector<std::filesystem::path> files;
    std::error_code ec;
    for (auto& entry : std::filesystem::directory_iterator(dir, ec)) {
        std::error_code feErr;
        if (!entry.is_regular_file(feErr)) continue;
        const std::string ext = entry.path().extension().string();
        bool wanted = false;
        for (const char* e : exts) wanted = wanted || ext == e;
        if (wanted) files.push_back(entry.path());
    }
    std::sort(files.begin(), files.end(), [](const std::filesystem::path& a, const std::filesystem::path& b) {
        return a.filename().generic_string() < b.filename().generic_string();
    });
    return files;
}

// --- ListStore ---

void ListStore::loadFromDirectory(const std::string& dir) {
    std::error_code ec;
    if (!std::filesystem::is_directory(dir, ec)) return;
    for (const auto& path : sortedFiles(dir, {".txt", ".list"})) {
        std::string name = path.stem().string();

        std::ifstream f(path);
        if (!f.is_open()) continue;
        std::vector<std::string> values;
        std::string line;
        while (std::getline(f, line)) {
            // Strip trailing CR (CRLF files).
            if (!line.empty() && line.back() == '\r') line.pop_back();
            // Trim leading/trailing whitespace.
            auto first = line.find_first_not_of(" \t");
            if (first == std::string::npos) continue;  // blank line
            auto last = line.find_last_not_of(" \t\r");
            std::string trimmed = line.substr(first, last - first + 1);
            if (trimmed.empty()) continue;
            if (trimmed[0] == '#') continue;  // comment
            values.push_back(trimmed);
        }
        m_lists[name] = std::move(values);
    }
}

const std::vector<std::string>* ListStore::resolve(const std::string& name) const {
    auto it = m_lists.find(name);
    if (it == m_lists.end()) return nullptr;
    return &it->second;
}

bool ListStore::exists(const std::string& name) const {
    return m_lists.find(name) != m_lists.end();
}

// --- Sigma field-modifier parsing ---
//
// A Sigma field key looks like "Image|contains" or "CommandLine|endswith|all".
// The first token (before the first '|') is the field name; subsequent tokens
// are modifiers. The operator is the first modifier that isn't "all"; "all"
// is a flag that flips list semantics from OR to AND.
//
// Supported operators: contains, startswith, endswith, re, exists, equals
// (equals is the default when no operator modifier is present).
static SigmaField parseSigmaField(const std::string& keyWithMods,
                                  const YAML::Node& valueNode,
                                  const ListStore* lists,
                                  const std::string& ruleId) {
    SigmaField f;

    // Split the key on '|'.
    std::vector<std::string> tokens;
    std::string cur;
    for (char c : keyWithMods) {
        if (c == '|') { tokens.push_back(cur); cur.clear(); }
        else cur += c;
    }
    if (!cur.empty()) tokens.push_back(cur);

    if (tokens.empty()) return f;
    f.field = tokens[0];

    // Parse modifiers. Sigma modifiers we recognize and map to an operator:
    //   contains / startswith / endswith / re / exists / equals / cidr: native
    //   all: flag (AND list values instead of OR)
    // Sigma modifiers we recognize but approximate (no native support yet):
    //   windash:      treat as `contains` (Sigma: value or value with
    //                   dashes/underscores replaced by spaces). Good enough
    //                   for substring detection without false negatives on
    //                   the plain value.
    //   base64offset: treat as `contains` (Sigma: match across base64
    //                   encoding offsets). Approximate.
    //   base64:       treat as `contains` (Sigma: base64-encode the value
    //                   before matching). We match the literal value as a
    //                   substring; this can miss encoded variants but never
    //                   false-positives. A future enhancement can add a
    //                   base64 evaluator.
    //   wide:         Sigma says the value may be UTF-16LE encoded in the event.
    //                   Our XML is already decoded to wide chars, so the
    //                   literal value matches correctly. No-op for us.
    //   i:            Sigma case-insensitive match. Our matching is already
    //                   case-insensitive, so this is a no-op.
    //   fieldref:     treat as `equals` (Sigma: compare to another field's
    //                   value). The engine resolves field names, so this is
    //                   a reasonable approximation for equality-style refs.
    // These are valid Sigma modifiers; recognizing them (instead of warning
    // "unknown") keeps SigmaHQ rules parsing cleanly per the Sigma standard.
    // The approximation is documented; a future enhancement can add native
    // evaluators.
    std::string op = "equals";  // default
    for (size_t i = 1; i < tokens.size(); ++i) {
        std::string m = tokens[i];
        // Lowercase compare.
        std::string ml = m;
        std::transform(ml.begin(), ml.end(), ml.begin(),
            [](unsigned char c) { return static_cast<char>(::tolower(c)); });
        if (ml == "all") {
            f.all = true;
        } else if (ml == "contains" || ml == "startswith" || ml == "endswith" ||
                   ml == "re" || ml == "exists" || ml == "equals" || ml == "cidr") {
            op = ml;
        } else if (ml == "windash" || ml == "base64offset" || ml == "base64") {
            // Approximate as contains (substring); see comment above.
            if (op == "equals") op = "contains";
        } else if (ml == "wide" || ml == "i" || ml == "fieldref") {
            // No-op for our matching (see comment above).
        } else {
            // Genuinely unknown modifier: ignore but keep parsing. Log to
            // error.log so it's visible without flooding the console. Include
            // the rule id so the user can find and fix the rule.
            std::string rid = ruleId.empty() ? "<unknown>" : ruleId;
            logError("[YamlRuleLoader] Unknown modifier '" + m +
                     "' on field '" + f.field + "' in rule '" + rid +
                     "'; ignoring");
        }
    }
    f.op = op;

    // Parse the value(s). A YAML scalar becomes a single value; a YAML
    // sequence becomes a list. The "exists" operator ignores the value.
    if (op == "exists") {
        // No values needed.
        return f;
    }

    // Collect raw string values from the YAML node, then expand any `@@list`
    // references from the ListStore. A `@@name` reference is replaced in-place
    // by the list's values; a missing/empty list contributes nothing. We track
    // `referencedList` so the engine knows that an empty `values` vector means
    // "the referenced list was missing/empty → match nothing" rather than
    // "no values specified → treat as exists".
    std::vector<std::string> rawValues;
    if (valueNode.IsSequence()) {
        for (const auto& v : valueNode) {
            rawValues.push_back(v.as<std::string>());
        }
    } else if (valueNode.IsScalar()) {
        rawValues.push_back(valueNode.as<std::string>());
    } else if (valueNode.IsNull()) {
        // Sigma `field: null` matches events where the field is absent or
        // empty (null). This is the OPPOSITE of `exists`: it matches the
        // absence of a value, not its presence. Used in filter selections
        // like `filter_main_cli_null: CommandLine: null` to exclude events
        // that lack a CommandLine. Treating it as `exists` would invert the
        // filter: it would match events that HAVE a CommandLine, excluding
        // exactly the events the rule is meant to alert on.
        f.op = "null";
        return f;
    }

    for (const auto& rv : rawValues) {
        if (rv.size() >= 2 && rv[0] == '@' && rv[1] == '@') {
            // List reference: @@name
            std::string listName = rv.substr(2);
            // Trim surrounding whitespace from the list name.
            auto first = listName.find_first_not_of(" \t");
            auto last = listName.find_last_not_of(" \t");
            if (first != std::string::npos) {
                listName = listName.substr(first, last - first + 1);
            }
            f.referencedList = true;
            if (!lists) {
                logError("[YamlRuleLoader] Rule field '" + f.field +
                         "' references list '@@" + listName +
                         "' but no list store is available; "
                         "this field will match nothing.");
                continue;
            }
            const auto* vals = lists->resolve(listName);
            if (!vals) {
                logError("[YamlRuleLoader] Rule field '" + f.field +
                         "' references list '@@" + listName +
                         "' which was not found in the lists directory; "
                         "this field will match nothing.");
                continue;
            }
            if (vals->empty()) {
                logError("[YamlRuleLoader] Rule field '" + f.field +
                         "' references list '@@" + listName +
                         "' which is empty; this field will match nothing.");
                continue;
            }
            for (const auto& lv : *vals) {
                f.values.push_back(lv);
            }
        } else {
            f.values.push_back(rv);
        }
    }
    return f;
}

// Parse a Sigma selection. A selection is a YAML map of field→value(s), OR a
// special `keywords:` block (a list of strings matched against raw XML), OR
// a YAML sequence of maps (the Sigma "OR of maps" pattern, where the
// selection matches if ANY map matches). `name` is the selection's key in
// the detection map.
static SigmaSelection parseSelection(const std::string& name,
                                      const YAML::Node& selNode,
                                      const ListStore* lists,
                                      const std::string& ruleId) {
    SigmaSelection sel;
    sel.name = name;

    if (!selNode.IsMap()) {
        if (selNode.IsSequence()) {
            // Inspect the items. If every item is a map, this is the Sigma
            // "OR of maps" pattern:
            //   selection_image:
            //     - Image|endswith: '\sqlps.exe'
            //     - OriginalFileName: 'sqlps.exe'
            // Each map becomes one alternative sub-selection (its fields
            // ANDed within the map); the parent selection ORs them. If the
            // items are scalars instead, it's a keywords list.
            bool allMaps = true;
            bool anyMap = false;
            for (const auto& v : selNode) {
                if (v.IsMap()) { anyMap = true; }
                else { allMaps = false; }
            }
            if (anyMap && allMaps) {
                int idx = 0;
                for (const auto& v : selNode) {
                    SigmaSelection alt = parseSelection(
                        name + "__alt" + std::to_string(idx), v, lists, ruleId);
                    sel.alternatives.push_back(std::move(alt));
                    ++idx;
                }
            } else {
                // Scalar items → keywords list.
                sel.keywords = true;
                for (const auto& v : selNode) {
                    sel.keywordValues.push_back(v.as<std::string>());
                }
            }
        }
        return sel;
    }

    for (const auto& kv : selNode) {
        std::string key = kv.first.as<std::string>();
        YAML::Node val = kv.second;

        // "keywords" is a special selection name in Sigma, but if it appears
        // as a key inside a selection map, treat it as a field named keywords.
        if (key == "keywords") {
            sel.keywords = true;
            if (val.IsSequence()) {
                for (const auto& v : val) sel.keywordValues.push_back(v.as<std::string>());
            } else if (val.IsScalar()) {
                sel.keywordValues.push_back(val.as<std::string>());
            }
            continue;
        }
        sel.fields.push_back(parseSigmaField(key, val, lists, ruleId));
    }
    return sel;
}

// Parse the Sigma `detection` section into selections + condition.
static void parseDetectionSection(const YAML::Node& detNode,
                                  std::vector<SigmaSelection>& selections,
                                  std::string& condition,
                                  const ListStore* lists,
                                  const std::string& ruleId) {
    if (!detNode || !detNode.IsMap()) return;

    for (const auto& kv : detNode) {
        std::string key = kv.first.as<std::string>();
        if (key == "condition") {
            condition = kv.second.as<std::string>("");
            continue;
        }
        // Everything else is a named selection (or the special "keywords").
        selections.push_back(parseSelection(key, kv.second, lists, ruleId));
    }
}

// Parse the ELF extension block (under top-level `elf:` or top-level
// `actions:`/`threshold`/`sequence` for backward convenience). Returns
// actions, sets type/threshold/timeframe/sequence.
static std::vector<Action> parseElfBlock(const YAML::Node& root, Detection& out,
                                        const ListStore* lists) {
    std::vector<Action> actions;

    YAML::Node elf = root["elf"];
    YAML::Node actionsNode = elf ? elf["actions"] : root["actions"];
    if (actionsNode) {
        for (const auto& a : actionsNode) {
            Action act;
            act.type = a["type"].as<std::string>("");
            act.destination = a["destination"].as<std::string>("");
            act.message = a["message"].as<std::string>("");
            // Skip unknown action types entirely. The server's validator
            // rejects these at save time, but a rule file can still be
            // edited directly on disk. Keeping the action in the vector
            // would let the rule match and print "[FORWARD] Rule fired:"
            // for every event while runFireActions silently ignores the
            // unknown type, confusing spurious output with no effect.
            // Dropping the action aligns the agent with the server: an
            // invalid action is rejected, not silently included.
            if (!act.type.empty() &&
                act.type != "forward_event" &&
                act.type != "alert" &&
                act.type != "forward_buffer") {
                logError("[YamlRuleLoader] WARNING: rule '" + out.id +
                         "' has unknown action type '" + act.type +
                         "'; valid types are forward_event, alert, "
                         "forward_buffer. This action will be ignored.");
                continue;  // drop the invalid action
            }
            actions.push_back(act);
        }
    }

    // Threshold (sliding-window count) correlation.
    YAML::Node threshNode = elf ? elf["threshold"] : root["threshold"];
    YAML::Node timeNode = elf ? elf["timeframe"] : root["timeframe"];
    if (threshNode) {
        out.type = Detection::Type::Threshold;
        try { out.threshold = threshNode.as<int>(); } catch (...) {}
    }

    // group_by: scope the threshold count per group (mandatory for threshold
    // rules). Accept a scalar (group_by: User) or a sequence
    // (group_by: [User, Computer]). Mirrors the elf-first / top-level fallback
    // pattern used for the other ELF keys.
    YAML::Node groupByNode = elf ? elf["group_by"] : root["group_by"];
    if (groupByNode) {
        if (groupByNode.IsSequence()) {
            for (const auto& g : groupByNode) {
                out.group_by.push_back(g.as<std::string>(""));
            }
        } else if (groupByNode.IsScalar()) {
            out.group_by.push_back(groupByNode.as<std::string>(""));
        }
    }

    // threshold_op: comparison operator for the fire condition. Empty/absent
    // = "gte" (the default, applied by the engine). The loader does NOT
    // validate the value here; the server validates at save time, and the
    // engine falls back to "gte" for any unrecognized value for safety.
    YAML::Node opNode = elf ? elf["threshold_op"] : root["threshold_op"];
    if (opNode && opNode.IsScalar()) {
        out.threshold_op = opNode.as<std::string>("");
    }

    // distinct: count unique resolved values of these field(s) within the
    // window instead of raw matching events (e.g. a ping-sweep rule counts
    // unique DestAddress values, so `ping -n 10 <onehost>`, 10 events and 1
    // unique destination, does not fire a threshold-5 rule). Accept a
    // scalar (distinct: DestAddress) or a sequence (distinct:
    // [DestAddress, DestPort]). Mirrors the elf-first / top-level fallback
    // pattern used for the other ELF keys.
    YAML::Node distinctNode = elf ? elf["distinct"] : root["distinct"];
    if (distinctNode) {
        if (distinctNode.IsSequence()) {
            for (const auto& d : distinctNode) {
                out.distinct_by.push_back(d.as<std::string>(""));
            }
        } else if (distinctNode.IsScalar()) {
            out.distinct_by.push_back(distinctNode.as<std::string>(""));
        }
        if (out.type != Detection::Type::Threshold && !out.distinct_by.empty()) {
            // distinct is only honored by threshold rules. The server
            // rejects it at save time; for a hand-edited file, warn and
            // ignore rather than refuse to load (the rule still works as
            // its declared type; the key is simply meaningless there).
            logError("[YamlRuleLoader] WARNING: rule '" + out.id +
                     "' uses 'distinct' but is not a threshold rule; "
                     "distinct is only supported on threshold rules and "
                     "will be ignored.");
            out.distinct_by.clear();
        }
    }

    // Sequence (ordered stages) correlation. Each stage is a mini detection
    // (selections + condition).
    YAML::Node seqNode = elf ? elf["sequence"] : root["sequence"];
    if (seqNode && seqNode.IsSequence()) {
        out.type = Detection::Type::Sequence;
        for (const auto& stage : seqNode) {
            Detection::SequenceStage s;
            if (stage.IsMap()) {
                parseDetectionSection(stage, s.selections, s.condition, lists, out.id);
            }
            out.sequence.push_back(s);
        }
    }

    // Timeframe (seconds). Accept "60s"/"5m"/"2h"/"1d" or a bare integer
    // (seconds). Parsed by hand: std::stoi("5m") does NOT throw, it
    // returns 5 (leading digits), so a "try stoi first" approach would turn
    // every minute/hour window into that many SECONDS.
    if (timeNode) {
        std::string t = timeNode.as<std::string>("");
        if (!t.empty()) {
            long long n = 0; size_t i = 0;
            while (i < t.size() && std::isspace((unsigned char)t[i])) ++i;
            while (i < t.size() && std::isdigit((unsigned char)t[i]) && n < 100000000LL) {
                n = n * 10 + (t[i] - '0'); ++i;
            }
            while (i < t.size() && std::isspace((unsigned char)t[i])) ++i;
            char u = (i < t.size()) ? static_cast<char>(std::tolower((unsigned char)t[i])) : 's';
            switch (u) {
                case 's': break;
                case 'm': n *= 60; break;
                case 'h': n *= 3600; break;
                case 'd': n *= 86400; break;
                default:
                    logError("[YamlRuleLoader] Rule '" + out.id + "': unrecognized "
                             "timeframe unit in '" + t + "' (use s/m/h/d); treating as seconds.");
                    break;
            }
            if (n > 0x7fffffffLL) n = 0x7fffffffLL;
            out.time_window_seconds = static_cast<int>(n);
        }
    }

    // Warn about an impossible combination: forward_event forwards every
    // matching event immediately, but threshold/sequence rules only fire
    // once their correlation window is satisfied. The server's validator
    // rejects this on save; log a warning here if a hand-edited rule file
    // contains it so the misconfiguration is visible in the agent log.
    if (out.type != Detection::Type::Simple) {
        for (const auto& a : actions) {
            if (a.type == "forward_event") {
                const char* kind =
                    (out.type == Detection::Type::Threshold) ? "threshold" : "sequence";
                logError(std::string("[YamlRuleLoader] WARNING: rule uses 'forward_event' ")
                         + "with a " + kind + " rule; forward_event is only "
                         + "valid for simple rules and will be ignored on fire.");
                break;
            }
        }
    }
    return actions;
}

LoadResult loadRuleFile(const std::string& path, Detection& out,
                        const ListStore* lists) {
    // If the file doesn't exist at all, it was removed between the
    // directory_iterator enumeration and now, a benign TOCTOU race with the
    // poll thread's writeRulesToDisk (which deletes rule files the server no
    // longer includes). Treat this as "skip" rather than a parse failure so
    // a group change that empties the ruleset doesn't leave stale rules
    // behind (allParsed stays true, the reload swaps in the new, possibly
    // empty, ruleset).
    std::error_code existEc;
    if (!std::filesystem::exists(path, existEc)) {
        return LoadResult::Missing;
    }

    YAML::Node root;
    try {
        root = YAML::LoadFile(path);
    } catch (const std::exception& e) {
        logError("[YamlRuleLoader] Failed to parse " + path + ": " + e.what());
        return LoadResult::Failed;
    }

    if (!root.IsMap()) {
        logError("[YamlRuleLoader] Top-level YAML must be a mapping in " + path);
        return LoadResult::Failed;
    }

    // --- Sigma top-level metadata ---
    out.title = root["title"].as<std::string>("");
    out.id = root["id"].as<std::string>("");
    out.status = root["status"].as<std::string>("");
    out.description = root["description"].as<std::string>("");
    out.level = root["level"].as<std::string>("");

    if (root["tags"]) {
        for (const auto& t : root["tags"]) out.tags.push_back(t.as<std::string>());
    }
    if (root["references"]) {
        for (const auto& r : root["references"]) out.references.push_back(r.as<std::string>());
    }
    if (root["falsepositives"]) {
        if (root["falsepositives"].IsSequence()) {
            for (const auto& fp : root["falsepositives"]) out.falsepositives.push_back(fp.as<std::string>());
        } else if (root["falsepositives"].IsScalar()) {
            out.falsepositives.push_back(root["falsepositives"].as<std::string>());
        }
    }

    // Derived fields.
    out.name = out.title;
    out.severity = out.level;
    // status deprecated/unsupported → disabled.
    std::string st = out.status;
    std::transform(st.begin(), st.end(), st.begin(),
        [](unsigned char c) { return static_cast<char>(::tolower(c)); });
    out.enabled = (st != "deprecated" && st != "unsupported");

    // --- logsource ---
    if (root["logsource"] && root["logsource"].IsMap()) {
        YAML::Node ls = root["logsource"];
        if (ls["product"]) {
            if (ls["product"].IsSequence()) {
                for (const auto& p : ls["product"]) out.platforms.push_back(p.as<std::string>());
            } else {
                out.platforms.push_back(ls["product"].as<std::string>());
            }
            // Keep a lowercase copy of the first product for logsource
            // filtering (e.g. "windows").
            if (!out.platforms.empty()) {
                out.logsource_product = out.platforms.front();
                std::transform(out.logsource_product.begin(),
                               out.logsource_product.end(),
                               out.logsource_product.begin(),
                    [](unsigned char c) { return static_cast<char>(::tolower(c)); });
            }
        }
        if (ls["service"]) {
            if (ls["service"].IsSequence()) {
                for (const auto& s : ls["service"]) out.log_sources.push_back(s.as<std::string>());
            } else {
                out.log_sources.push_back(ls["service"].as<std::string>());
            }
        }
        // Sigma `logsource.category` identifies the event type (e.g.
        // process_creation, network_connection, file_change). The engine uses
        // this to skip rules that don't apply to an event's category, so a
        // process_creation rule is never evaluated against a 5158 WFP
        // network event. Stored lowercase for case-insensitive comparison.
        if (ls["category"]) {
            out.logsource_category = ls["category"].as<std::string>("");
            std::transform(out.logsource_category.begin(),
                           out.logsource_category.end(),
                           out.logsource_category.begin(),
                [](unsigned char c) { return static_cast<char>(::tolower(c)); });
        }
    }

    // --- detection ---
    if (root["detection"]) {
        parseDetectionSection(root["detection"], out.selections, out.condition, lists, out.id);
    }

    // --- ELF extension block (actions / threshold / sequence / timeframe) ---
    out.actions = parseElfBlock(root, out, lists);

    // group_by is mandatory for threshold rules. A threshold rule without it
    // would count globally (one shared window), which is the false-positive
    // trap this feature exists to remove. Refuse to load so a
    // hand-edited rule file can't silently fall back to global counting;
    // loadRuleFile returns Failed, which sets allParsed=false so the agent
    // keeps the last good ruleset on the next reload (same pattern as the
    // "no valid actions" check in loadRulesFromDirectory).
    if (out.type == Detection::Type::Threshold && out.group_by.empty()) {
        logError("[YamlRuleLoader] Rule '" + out.id +
                 "' is a threshold rule but has no group_by; threshold "
                 "rules require group_by (e.g. group_by: TargetUserName) "
                 "to scope the count per group. Refusing to load.");
        return LoadResult::Failed;
    }

    // If no condition was specified but there are selections, default to
    // "selection" (the first selection) for backward simplicity, or "all of
    // them" if there are multiple.
    if (out.condition.empty() && !out.selections.empty()) {
        if (out.selections.size() == 1) {
            out.condition = out.selections[0].name;
        } else {
            out.condition = "all of them";
        }
    }

    // Precompute cache keys, lowercased values, regexes and the condition
    // AST once here, so the per-event matcher does no parsing at all.
    compileDetection(out);

    return LoadResult::Ok;
}

std::vector<Detection> loadRulesFromDirectory(const std::string& dir) {
    bool allParsed = true;
    return loadRulesFromDirectory(dir, allParsed);
}

std::vector<Detection> loadRulesFromDirectory(const std::string& dir, bool& allParsed) {
    // No lists directory → no list expansion. `@@` references resolve to
    // nothing (the field matches nothing), which is the safe default.
    return loadRulesFromDirectory(dir, std::string(), allParsed);
}

LoadSummary loadRules(const std::string& dir, const std::string& listsDir) {
    LoadSummary s;
    std::error_code ec;
    if (!std::filesystem::is_directory(dir, ec)) {
        logError("[YamlRuleLoader] Rules directory not found: " + dir);
        s.dirMissing = true;
        return s;
    }

    // Load reusable lists from the lists directory (if it exists). A missing
    // lists directory is not an error; `@@` references just resolve to
    // nothing and the rules still load.
    ListStore lists;
    if (!listsDir.empty()) {
        lists.loadFromDirectory(listsDir);
    }

    auto noteFailure = [&](const std::string& path) {
        ++s.failed;
        if (s.failedFiles.size() < 20) s.failedFiles.push_back(path);
    };

    for (const auto& path : sortedFiles(dir, {".yaml", ".yml"})) {
        Detection d;
        // Wrap each file load in a try/catch so a YAML parse exception in one
        // rule (e.g. a malformed SigmaHQ rule with an unsupported construct)
        // is reported with the file name and skipped, instead of escaping
        // and crashing the whole agent. Without this, an uncaught exception
        // from YAML::Load would propagate up through the reload thread and
        // terminate the process.
        LoadResult res = LoadResult::Failed;
        try {
            res = loadRuleFile(path.string(), d, &lists);
        } catch (const std::exception& e) {
            logError("[YamlRuleLoader] EXCEPTION loading " + path.string() +
                     ": " + e.what() + "; skipping this rule.");
            noteFailure(path.string());
            continue;
        } catch (...) {
            logError("[YamlRuleLoader] UNKNOWN EXCEPTION loading " + path.string() +
                     "; skipping this rule.");
            noteFailure(path.string());
            continue;
        }
        if (res == LoadResult::Ok) {
            if (!d.enabled) {
                ++s.disabled;
                continue;
            }
            if (d.id.empty()) {
                logError("[YamlRuleLoader] Rule without id in " + path.string() + " - skipping");
                noteFailure(path.string());
                continue;
            }
            // A rule with no valid actions would match events and print
            // "[FORWARD] Rule fired:" for every match while doing nothing
            // (no alert, no forward). This happens when a rule's only
            // actions had unknown types (e.g. "forward_alert") that
            // parseElfBlock dropped. Skip the rule entirely so the agent
            // applies the same rejection the server's validator does at
            // save time: an invalid rule is not loaded, not silently
            // matched-and-ignored.
            if (d.actions.empty()) {
                logError("[YamlRuleLoader] Rule '" + d.id + "' in " + path.string() +
                         " has no valid actions (all action types were "
                         "unknown or none were specified) - skipping. "
                         "Valid action types: forward_event, alert, forward_buffer.");
                noteFailure(path.string());
                continue;
            }
            ++s.parsed;
            s.rules.push_back(std::move(d));
        } else if (res == LoadResult::Missing) {
            // File vanished between directory enumeration and open, a benign
            // race with the poll thread's writeRulesToDisk (which deletes rule
            // files the server no longer includes). Skip silently; this is
            // NOT a parse error and must not block the reload.
            ++s.missing;
            continue;
        } else {
            // LoadResult::Failed; loadRuleFile already printed the error.
            noteFailure(path.string());
        }
    }
    // One summary line per load, not one per rule: with thousands of rules
    // a per-rule line would be most of the log file.
    logInfo("[YamlRuleLoader] Loaded " + std::to_string(s.parsed) + " rule(s) from " +
            dir + " (" + std::to_string(s.disabled) + " disabled, " +
            std::to_string(s.failed) + " failed, " + std::to_string(s.missing) +
            " vanished)");
    if (s.failed > 0) {
        std::string names;
        for (const auto& f : s.failedFiles) {
            if (!names.empty()) names += ", ";
            names += std::filesystem::path(f).filename().string();
        }
        logError("[YamlRuleLoader] " + std::to_string(s.failed) +
                 " rule file(s) failed to load and were skipped: " + names +
                 (s.failed > s.failedFiles.size() ? ", ..." : ""));
    }
    return s;
}

std::vector<Detection> loadRulesFromDirectory(const std::string& dir,
                                               const std::string& listsDir,
                                               bool& allParsed) {
    LoadSummary s = loadRules(dir, listsDir);
    allParsed = !s.dirMissing && s.failed == 0;
    return std::move(s.rules);
}

std::vector<Detection> loadRulesFromDirectory(const std::string& dir,
                                               const std::string& listsDir) {
    bool allParsed = true;
    return loadRulesFromDirectory(dir, listsDir, allParsed);
}

} // namespace elf
