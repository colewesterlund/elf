#include "RuleEngine.h"
#include <cstring>
#include "Platform.h"
#include "Config.h"
#include "FieldResolver.h"
#include "Console.h"
#include <iostream>
#include <chrono>
#include <cstdlib>
#include <string>
#include <algorithm>
#include <cctype>
#include <map>
#include <optional>
#include <set>
#include <unordered_set>

namespace elf {

// Forward declarations for helpers defined with the category table below
// (buildRuleSet needs them before the table is defined).
static std::string normalizeCategory(std::string cat);
static bool isKnownCategory(const std::string& cat);

// When ELF_DEBUG is set, the engine logs the EventID/Channel of every new
// event it evaluates, plus which rules it tries. Useful for diagnosing why a
// rule isn't matching.
static bool debugEnabled() {
    static bool v = [] {
        const char* e = std::getenv("ELF_DEBUG");
        return e && (std::string(e) == "1" || std::string(e) == "true");
    }();
    return v;
}

// Dedup entries older than this are pruned to bound memory. 30 min is well
// beyond any realistic buffer retention, so re-evaluation after a buffer
// shrink still benefits from dedup.
static constexpr auto ALERT_DEDUP_TTL = std::chrono::minutes(30);
// Prune the dedup sets at most this often to avoid walking every rule state
// on every 2 s pass.
static constexpr auto DEDUP_PRUNE_INTERVAL = std::chrono::seconds(60);

RuleEngine::RuleEngine(EventBuffer& buffer, Forwarder& forwarder)
    : m_buffer(buffer), m_forwarder(forwarder),
      m_lastDedupPrune(std::chrono::system_clock::now()),
      m_alertRng(std::random_device{}()) {}

// A 16-hex-digit id that is unique per rule fire. It is written on the
// alert and on every event of the batch that fire forwarded (file,
// SIEM and server mirror alike), so an analyst can pull one incident's
// alert and context together with a single search.
std::string RuleEngine::newAlertId() {
    uint64_t v = m_alertRng();
    char buf[17];
    std::snprintf(buf, sizeof(buf), "%016llx", static_cast<unsigned long long>(v));
    return buf;
}

// The Sigma logsource.product values the engine distinguishes.
static constexpr const char* kProdWindows = "windows";
static constexpr const char* kProdLinux   = "linux";

static std::string g_hostProductOverride;

const char* hostSigmaProduct() {
    return g_hostProductOverride.empty() ? platformSigmaProduct() : g_hostProductOverride.c_str();
}

void setHostSigmaProductForTests(const std::string& product) {
    g_hostProductOverride = product;
}

// Forward declaration: sigmaServiceChannelMap() is defined later in this file
// but is needed by reload() to build the channel-keyed rule index.
static const std::vector<std::pair<std::string, std::vector<std::string>>>&
sigmaServiceChannelMap();

// Build a fully-indexed, immutable RuleSet from a list of rules. The index
// is the key optimization for large rulesets: instead of checking every
// rule against every event, we pre-compute which channels each rule
// applies to (from its logsource.service) so evaluateOnce can skip rules
// that can't possibly match the event's channel. With 1000+ rules this cuts
// the per-event evaluation count from 1000 to ~10-50 (the rules for that
// channel + the catch-all rules), a 20-100x speedup.
//
// Runs entirely outside the engine lock: the set is built, then swapped in
// with one pointer assignment, so a reload of thousands of rules never
// stalls an evaluation pass.
static std::shared_ptr<const RuleSet> buildRuleSet(const std::vector<Detection>& rules) {
    auto rs = std::make_shared<RuleSet>();
    rs->rules = rules;
    // Index pointers point into rs->rules, which is never resized or
    // reassigned after this point, so they stay valid for the set's life.
    for (auto& rule : rs->rules) {
        // Safety net for hand-built rules (tests): the loader compiles at
        // load time, so this is a no-op for everything it produced.
        if (!rule.compiled) compileDetection(rule);
        // Sigma spells it image_load; normalizeCategory folds the
        // image_loaded alias into it.
        rule.logsource_category = normalizeCategory(rule.logsource_category);
    }
    const std::string here = hostSigmaProduct();
    std::vector<std::string> foreign;
    for (const auto& rule : rs->rules) {
        rs->byId[rule.id] = &rule;
        if (!rule.enabled) continue;
        // A rule for another operating system can only produce false
        // positives here (a Linux execve rule run against Windows logons).
        const std::string& prod = rule.logsource_product;
        if (!prod.empty() && prod != here && (prod == kProdWindows || prod == kProdLinux)) {
            foreign.push_back(rule.id + " (" + prod + ")");
            continue;
        }
        bool hasService = !rule.log_sources.empty();
        bool hasCategory = !rule.logsource_category.empty();
        if (!hasService && !hasCategory) {
            // No logsource constraints → applies to every event.
            rs->catchAll.push_back(&rule);
        } else if (!hasService && hasCategory) {
            // Category-only rule: indexed by category when the engine can
            // classify events into it; otherwise it only ever applies to
            // events the engine cannot classify either.
            if (isKnownCategory(rule.logsource_category)) {
                rs->byCategory[rule.logsource_category].push_back(&rule);
            } else {
                rs->unmappedCategory.push_back(&rule);
            }
        } else {
            // Has a service → index by the channels this service maps to.
            // If the service is unknown to sigmaServiceChannelMap(),
            // serviceMatchesChannel() falls back to a substring match at
            // eval time, so we can't pre-index those. Put them in a
            // "service-unknown" bucket that we check against every event
            // (via serviceMatchesChannel). This is rare and still much
            // cheaper than full matchEvent.
            bool indexed = false;
            for (const auto& svc : rule.log_sources) {
                std::string svcLower = svc;
                std::transform(svcLower.begin(), svcLower.end(), svcLower.begin(),
                    [](unsigned char c) { return static_cast<char>(::tolower(c)); });
                for (const auto& [knownSvc, channels] : sigmaServiceChannelMap()) {
                    if (knownSvc != svcLower) continue;
                    for (const auto& ch : channels) {
                        // The map stores canonical Windows channel case
                        // (e.g. "Security"); lowercase it here so the
                        // channel-keyed index matches the lowercased event
                        // channel extracted at eval time.
                        std::string chLower = ch;
                        std::transform(chLower.begin(), chLower.end(),
                            chLower.begin(),
                            [](unsigned char c) {
                                return static_cast<char>(::tolower(c));
                            });
                        // Strip wildcard patterns; they're matched at eval
                        // time, not indexed.
                        if (chLower.find('*') != std::string::npos) continue;
                        rs->channel[chLower].push_back(&rule);
                        indexed = true;
                    }
                }
            }
            if (!indexed) {
                // Service not in the known map (or only wildcard channels).
                // Checked against every event via serviceMatchesChannel
                // (ruleAppliesToEvent handles both the category and the
                // service check).
                rs->unknownService.push_back(&rule);
            }
        }
    }
    if (!foreign.empty()) {
        std::string ids;
        for (size_t i = 0; i < foreign.size() && i < 20; ++i) {
            if (!ids.empty()) ids += ", ";
            ids += foreign[i];
        }
        if (foreign.size() > 20) ids += ", ...";
        logInfo("[RuleEngine] " + std::to_string(foreign.size()) +
                " rule(s) target another operating system and are not evaluated on this " +
                here + " host: " + ids);
    }
    if (!rs->unmappedCategory.empty()) {
        std::string ids;
        size_t shown = 0;
        for (const auto* r : rs->unmappedCategory) {
            if (shown++ >= 20) { ids += ", ..."; break; }
            if (!ids.empty()) ids += ", ";
            ids += r->id + " (" + r->logsource_category + ")";
        }
        logInfo("[RuleEngine] " + std::to_string(rs->unmappedCategory.size()) +
                " rule(s) use a logsource.category the engine cannot map to host "
                "events; they are evaluated only against unclassified events: " + ids);
    }
    return rs;
}

void RuleEngine::reload(const std::vector<Detection>& rules) {
    auto rs = buildRuleSet(rules);
    {
        std::lock_guard<std::mutex> lock(m_rulesMutex);
        m_ruleSet = std::move(rs);
    }
    // NOTE: we intentionally do NOT reset m_evaluatedAbsolute or m_states here.
    // The agent's poll thread calls reload() on every successful poll (every
    // poll_interval_seconds). Resetting the cursor would re-evaluate every
    // buffered event, and clearing the per-rule state would discard the
    // threshold/sequence dedup sets, so a single event could be counted again
    // after each poll and hit a threshold of 2 from one real event. The
    // cursor tracks absolute buffer position (independent of the ruleset and
    // of front pops), the per-rule dedup sets track events (independent of
    // the ruleset), and new rules simply get a fresh default-constructed
    // RuleState on first use. State for rules that were REMOVED is dropped
    // by the periodic prune (pruneStates), not here.
}

size_t RuleEngine::ruleCount() const {
    auto rs = currentRuleSet();
    return rs ? rs->rules.size() : 0;
}

// What the destinations need to know about a rule (see OutputFormat.h).
static RuleMeta ruleMetaOf(const Detection& rule) {
    RuleMeta m;
    m.id = rule.id;
    m.name = rule.name;
    m.level = rule.level;
    m.category = rule.logsource_category;
    m.description = rule.description;
    m.tags = rule.tags;
    return m;
}

// Run forward_event actions immediately (continuous forwarding).
static void runForwardEventActions(const Detection& rule, const BufferedEvent& evt,
                                    Forwarder& fwd) {
    RuleMeta meta;
    bool built = false;
    for (const auto& a : rule.actions) {
        if (a.type == "forward_event") {
            if (!built) { meta = ruleMetaOf(rule); built = true; }
            fwd.forwardEvent(evt, a.destination, meta);
        }
    }
}

// Forward declarations: deriveChannelQueries() (below) uses these helpers
// that are defined later in this file. They derive a rule's EventID set
// from its compiled condition, and map a Sigma logsource category to the
// Windows channels (and EventIDs per channel) it covers.
static std::optional<std::set<int>> ruleEventIds(const Detection& rule);
static const std::unordered_map<std::string, std::vector<std::string>>& categoryChannelMap(const std::string& product);
static std::vector<int> categoryEventIds(const std::string& category,
                                         const std::string& channelCanonical);

// Derive the per-channel XPath subscription filter from the loaded ruleset.
// Walks every enabled rule, determines which Windows channels it can match
// (from logsource.service via sigmaServiceChannelMap, or from
// logsource.category via categoryChannelMap), and unions the rule's EventIDs
// into each channel's set. Channels with no explicit EventID (from a rule
// that has no EventID field, or from a catch-all rule) get an empty set,
// meaning "subscribe to all events on this channel".
//
// Returns an empty vector when catch-all rules are present (rules with no
// logsource constraints), because a catch-all rule can match ANY event on
// ANY channel: we can't pre-filter, so the caller must fall back to
// subscribeAll(). This is the correctness guard: XPath filtering never drops
// an event a rule could match.
//
// Thread-safety: takes the rules lock and copies the ruleset pointers, so
// it's safe to call from the reload path while the eval thread is running.
std::vector<std::pair<std::string, std::vector<int>>>
RuleEngine::deriveChannelQueries() const {
    // Hold our own reference to the set for the whole walk (see RuleSet).
    auto rs = currentRuleSet();
    std::vector<const Detection*> rules;
    const std::string here = hostSigmaProduct();
    if (rs) {
        for (const auto& r : rs->rules) {
            if (!r.enabled) continue;
            // Rules for another operating system are not evaluated here
            // (see buildRuleSet), so they subscribe to nothing either.
            const std::string& prod = r.logsource_product;
            if (!prod.empty() && prod != here && (prod == kProdWindows || prod == kProdLinux)) continue;
            rules.push_back(&r);
        }
    }

    // If any catch-all rule exists, we can't pre-filter; return empty so
    // the caller falls back to subscribeAll().
    for (const auto* r : rules) {
        if (r->log_sources.empty() && r->logsource_category.empty()) {
            logInfo("[RuleEngine] Catch-all rule present (" + r->id +
                    "); XPath subscription filtering disabled (subscribing to all channels).");
            return {};
        }
    }

    // channel → EventID set. We use a map for deterministic ordering (so the
    // resulting query list is stable across runs and testable). A channel
    // with an empty EventID set means "subscribe to all events" (the rule
    // has no explicit EventID, so we can't pre-filter it).
    std::map<std::string, std::set<int>> channelIds;
    // Channels that have at least one rule with no explicit EventID. These
    // must subscribe to all events (empty set), even if other rules on the
    // same channel contributed EventIDs.
    std::set<std::string> channelNeedsAll;
    // Rules that forced a channel to "*", for the operator (capped).
    std::vector<std::string> forcedAll;
    size_t forcedTotal = 0;

    for (const auto* r : rules) {
        // EventIDs the rule can match, derived from its compiled condition:
        // `a and b` with EventID only in `a` is still restricted to a's ids,
        // but `a or b` is NOT (b can match anything); a flat field walk
        // that trusts any EventID found anywhere would silently filter b out.
        std::optional<std::set<int>> ids = ruleEventIds(*r);
        const std::string& cat = r->logsource_category;

        // Determine the channels this rule applies to.
        std::vector<std::string> channels;
        if (!r->log_sources.empty()) {
            // Service-based: map each service to its channels.
            for (const auto& svc : r->log_sources) {
                std::string svcLower = svc;
                std::transform(svcLower.begin(), svcLower.end(), svcLower.begin(),
                    [](unsigned char c) { return static_cast<char>(::tolower(c)); });
                for (const auto& [knownSvc, chans] : sigmaServiceChannelMap()) {
                    if (knownSvc != svcLower) continue;
                    for (const auto& ch : chans) {
                        if (ch == "*") {
                            // The whole host log: an unfiltered subscription
                            // the source expands (every journal entry).
                            channelNeedsAll.insert(ch);
                            continue;
                        }
                        if (ch.find('*') != std::string::npos) continue;  // skip wildcards
                        channels.push_back(ch);
                    }
                }
            }
        }
        if (!cat.empty()) {
            // Category-based: map the category to its channels on the
            // rule's platform.
            const auto& catMap = categoryChannelMap(r->logsource_product);
            auto it = catMap.find(cat);
            if (it != catMap.end()) {
                for (const auto& ch : it->second) channels.push_back(ch);
            }
        }

        for (const auto& ch : channels) {
            // Preserve the canonical channel case from the map. EvtSubscribe
            // is case-sensitive on the channel path and rejects lowercase
            // names (e.g. "security") with ERROR_INVALID_PARAMETER (87),
            // so we must NOT lowercase here. The map already stores the
            // canonical Windows names ("Security", "System", ...).
            if (ids) {
                for (int id : *ids) channelIds[ch].insert(id);
                continue;
            }
            // No explicit EventID. A category rule still implies a known
            // set of EventIDs on each channel (process_creation → Security
            // 4688 / Sysmon 1), which is what keeps the Security filter
            // selective for a SigmaHQ import where almost no rule names an
            // EventID. Only a rule with no derivable ids forces "*".
            std::vector<int> catIds = cat.empty() ? std::vector<int>{} : categoryEventIds(cat, ch);
            if (!catIds.empty()) {
                for (int id : catIds) channelIds[ch].insert(id);
            } else {
                // A syslog identifier (Linux) has no event ids to filter
                // on, so "*" is its normal state, not worth a notice.
                const bool noteworthy = r->logsource_product != kProdLinux || ch == "audit";
                if (channelNeedsAll.insert(ch).second && noteworthy) {
                    ++forcedTotal;
                    if (forcedAll.size() < 20) forcedAll.push_back(r->id + " -> " + ch);
                }
            }
        }
    }
    if (!forcedAll.empty()) {
        std::string list;
        for (const auto& s : forcedAll) { if (!list.empty()) list += ", "; list += s; }
        logInfo("[RuleEngine] Rules forcing an unfiltered (*) channel subscription "
                "(no derivable EventID): " + list +
                (forcedTotal > forcedAll.size() ? ", ..." : ""));
    }

    // Build the result. Channels in channelNeedsAll get an empty EventID
    // set (→ "*" query). Other channels get their unioned EventID set.
    std::vector<std::pair<std::string, std::vector<int>>> result;
    // Start with channels that have EventIDs.
    for (auto& [ch, ids] : channelIds) {
        std::vector<int> v;
        if (channelNeedsAll.count(ch)) {
            // This channel also has a no-EventID rule → must subscribe to all.
            v.clear();
        } else {
            v.assign(ids.begin(), ids.end());
        }
        result.emplace_back(ch, std::move(v));
    }
    // Add channels that only appeared in channelNeedsAll (no EventID rules).
    for (const auto& ch : channelNeedsAll) {
        if (channelIds.find(ch) == channelIds.end()) {
            result.emplace_back(ch, std::vector<int>{});
        }
    }
    return result;
}

// --- Sigma category table ---
//
// One table maps (Windows channel, EventID) → Sigma `logsource.category`.
// Everything category-related derives from it: classifying an event (own
// category + parent, e.g. Sysmon 13 is registry_set AND registry_event),
// the channels a category rule can fire on (for the subscription filter),
// and the EventIDs a category implies on each channel (so a category rule
// with no explicit EventID still yields a selective XPath).
//
// It is keyed by channel on purpose: classifying by EventID alone would
// make a System-log EventID 7 (disk error) "image_load" and an Application
// EventID 1 "process_creation".
//
// Reference: Sigma Windows logsource categories vs. Security / Sysmon /
// PowerShell provider EventIDs.
namespace {

constexpr const char* kChSecurity   = "security";
constexpr const char* kChSysmon     = "microsoft-windows-sysmon/operational";
constexpr const char* kChPowerShell = "microsoft-windows-powershell/operational";
constexpr const char* kChPsClassic  = "windows powershell";
// Linux: the kernel audit records as journald stores them (channel
// "audit", EventID = audit record type).
constexpr const char* kChAudit      = "audit";

// `product` is the Sigma logsource.product the row belongs to, so a
// category rule only subscribes to the channels of its own platform.
struct CatMapEntry { const char* channelLower; int eventId; const char* category; const char* product; };

const CatMapEntry kCategoryTable[] = {
    // Sysmon
    {kChSysmon, 1,  "process_creation", kProdWindows},
    {kChSysmon, 2,  "file_change", kProdWindows},
    {kChSysmon, 3,  "network_connection", kProdWindows},
    {kChSysmon, 5,  "process_termination", kProdWindows},
    {kChSysmon, 6,  "driver_load", kProdWindows},
    {kChSysmon, 7,  "image_load", kProdWindows},
    {kChSysmon, 8,  "create_remote_thread", kProdWindows},
    {kChSysmon, 9,  "raw_access_thread", kProdWindows},
    {kChSysmon, 10, "process_access", kProdWindows},
    {kChSysmon, 11, "file_event", kProdWindows},
    {kChSysmon, 12, "registry_add", kProdWindows},
    {kChSysmon, 12, "registry_delete", kProdWindows},
    {kChSysmon, 13, "registry_set", kProdWindows},
    {kChSysmon, 14, "registry_rename", kProdWindows},
    {kChSysmon, 15, "create_stream_hash", kProdWindows},
    {kChSysmon, 17, "pipe_created", kProdWindows},
    {kChSysmon, 18, "pipe_created", kProdWindows},
    {kChSysmon, 19, "wmi_event", kProdWindows},
    {kChSysmon, 20, "wmi_event", kProdWindows},
    {kChSysmon, 21, "wmi_event", kProdWindows},
    {kChSysmon, 22, "dns_query", kProdWindows},
    {kChSysmon, 23, "file_delete", kProdWindows},
    {kChSysmon, 25, "process_tampering", kProdWindows},
    {kChSysmon, 26, "file_delete_detected", kProdWindows},
    {kChSysmon, 27, "file_block_executable", kProdWindows},
    {kChSysmon, 28, "file_block_shredding", kProdWindows},
    {kChSysmon, 29, "file_executable_detected", kProdWindows},
    // Security
    {kChSecurity, 4688, "process_creation", kProdWindows},
    {kChSecurity, 4689, "process_termination", kProdWindows},
    {kChSecurity, 5154, "network_connection", kProdWindows},
    {kChSecurity, 5156, "network_connection", kProdWindows},
    {kChSecurity, 5157, "network_connection", kProdWindows},
    {kChSecurity, 5158, "network_connection", kProdWindows},
    {kChSecurity, 4657, "registry_set", kProdWindows},
    // PowerShell
    {kChPowerShell, 4103, "ps_module", kProdWindows},
    {kChPowerShell, 4104, "ps_script", kProdWindows},
    {kChPsClassic,  400,  "ps_classic_start", kProdWindows},
    {kChPsClassic,  600,  "ps_classic_provider_start", kProdWindows},
    {kChPsClassic,  800,  "ps_classic_script", kProdWindows},
    // Linux audit: EXECVE (1309) carries argv and, after the collector's
    // join, the SYSCALL record's exe/comm/uid/key.
    {kChAudit, 1309, "process_creation", kProdLinux},
};

// Canonical Windows channel names (EvtSubscribe is case-sensitive).
const std::unordered_map<std::string, std::string>& canonicalChannelNames() {
    static const std::unordered_map<std::string, std::string> m = {
        {kChSecurity,   "Security"},
        {kChSysmon,     "Microsoft-Windows-Sysmon/Operational"},
        {kChPowerShell, "Microsoft-Windows-PowerShell/Operational"},
        {kChPsClassic,  "Windows PowerShell"},
        {kChAudit,      "audit"},
    };
    return m;
}

// Sigma parent categories: a rule on the parent matches every child.
const char* parentCategory(const std::string& cat) {
    if (cat == "registry_add" || cat == "registry_set" ||
        cat == "registry_delete" || cat == "registry_rename") {
        return "registry_event";
    }
    return nullptr;
}

const std::unordered_set<std::string>& knownCategories() {
    static const std::unordered_set<std::string> s = [] {
        std::unordered_set<std::string> out;
        for (const auto& e : kCategoryTable) {
            out.insert(e.category);
            if (const char* p = parentCategory(e.category)) out.insert(p);
        }
        return out;
    }();
    return s;
}

} // namespace

// Lowercase + alias normalization for a rule's logsource.category.
static std::string normalizeCategory(std::string cat) {
    std::transform(cat.begin(), cat.end(), cat.begin(),
        [](unsigned char c) { return static_cast<char>(::tolower(c)); });
    if (cat == "image_loaded") return "image_load";
    return cat;
}

static bool isKnownCategory(const std::string& cat) {
    return knownCategories().count(cat) > 0;
}

// Categories an event belongs to (own + parent). Empty when the engine
// cannot classify the (channel, EventID) pair, e.g. a 4624 logon, which has
// no Sigma category. Computed ONCE per event by evaluateOnce.
static std::vector<std::string> eventSigmaCategories(const std::string& channelLower, int eid) {
    std::vector<std::string> out;
    for (const auto& e : kCategoryTable) {
        if (e.eventId != eid || channelLower != e.channelLower) continue;
        out.emplace_back(e.category);
        if (const char* p = parentCategory(e.category)) {
            if (std::find(out.begin(), out.end(), p) == out.end()) out.emplace_back(p);
        }
    }
    return out;
}

std::vector<std::string> sigmaCategoriesFor(const std::string& channelLower, int eventId) {
    return eventSigmaCategories(channelLower, eventId);
}

// EventIDs a category implies on one (canonical) channel. A parent category
// unions its children. Empty when the category is unknown or not produced
// on that channel.
static std::vector<int> categoryEventIds(const std::string& category,
                                         const std::string& channelCanonical) {
    std::string chLower = channelCanonical;
    std::transform(chLower.begin(), chLower.end(), chLower.begin(),
        [](unsigned char c) { return static_cast<char>(::tolower(c)); });
    std::set<int> ids;
    for (const auto& e : kCategoryTable) {
        if (chLower != e.channelLower) continue;
        const char* p = parentCategory(e.category);
        if (category == e.category || (p && category == p)) ids.insert(e.eventId);
    }
    return std::vector<int>(ids.begin(), ids.end());
}

// Map a Sigma `logsource.service` short name to the Windows event channel(s)
// it refers to. Sigma uses short aliases (e.g. "security", "system",
// "capi2") while Windows channels are verbose (e.g. "Security", "System",
// "Microsoft-Windows-CAPI2/Operational"). This table covers the common
// aliases; anything not listed falls through to a case-insensitive
// substring match in serviceMatchesChannel() below.
//
// Reference: Sigma spec + Microsoft Windows channel names. A single Sigma
// service may map to more than one channel (e.g. "powershell" covers both
// the classic PowerShell and the Operational channel).
static const std::vector<std::pair<std::string, std::vector<std::string>>>&
sigmaServiceChannelMap() {
    // Channel names use the CANONICAL Windows case (as returned by
    // EvtNextChannelPath). EvtSubscribe rejects lowercase channel names
    // with ERROR_INVALID_PARAMETER (87), e.g. "security" fails but
    // "Security" succeeds. The Sigma service keys remain lowercase
    // (Sigma aliases are case-insensitive); only the channel values are
    // canonical.
    static const std::vector<std::pair<std::string, std::vector<std::string>>> m = {
        {"security",            {"Security"}},
        {"system",              {"System"}},
        {"application",         {"Application"}},
        {"powershell",          {"Microsoft-Windows-PowerShell/Operational",
                                 "Windows PowerShell"}},
        {"powershell-classic",  {"Windows PowerShell"}},
        {"sysmon",              {"Microsoft-Windows-Sysmon/Operational"}},
        {"capi2",               {"Microsoft-Windows-CAPI2/Operational"}},
        {"winrm",               {"Microsoft-Windows-WinRM/Operational"}},
        {"wmi",                 {"Microsoft-Windows-WMI-Activity/Operational"}},
        {"dhcp",                {"Microsoft-Windows-Dhcp-Server/Operational",
                                 "Microsoft-Windows-Dhcp/Operational"}},
        {"dns",                 {"DNS-Server",
                                 "Microsoft-Windows-DNS-Server/Analytical"}},
        {"printservice",        {"Microsoft-Windows-PrintService/Operational",
                                 "Microsoft-Windows-PrintService/Admin"}},
        {"terminalservices",    {"Microsoft-Windows-TerminalServices-LocalSessionManager/Operational",
                                 "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational"}},
        {"firewall",             {"Microsoft-Windows-Windows Firewall With Advanced Security/Firewall"}},
        {"applocker",           {"Microsoft-Windows-AppLocker/Whitelisting"}},
        {"bits",                {"Microsoft-Windows-Bits-Client/Operational"}},
        {"driver-framework",    {"Microsoft-Windows-DriverFrameworks-UserModeDriver/Operational"}},
        {"ntfs",                {"Microsoft-Windows-Ntfs/Operational"}},
        {"msexchange",          {"Microsoft-Exchange-Managed-Availability/Monitoring"}},
        {"sharepoint",          {"Microsoft-SharePoint-Products-Shared/Operational"}},
        {"mssql",               {"MSSQLSERVER/MSSQLSERVER",
                                 "MSSQL$*/Operational"}},
        // Linux: a channel is the syslog identifier of the journal entry,
        // "audit" the kernel audit transport, "*" the whole journal.
        {"auditd",              {"audit"}},
        // OpenSSH 9.8+ logs sessions from a separate sshd-session process.
        {"sshd",                {"sshd", "sshd-session"}},
        {"sudo",                {"sudo"}},
        {"cron",                {"CRON", "crond", "cron"}},
        {"kernel",              {"kernel"}},
        {"systemd",             {"systemd"}},
        {"syslog",              {"*"}},
        {"auth",                {"*"}},
        {"authpriv",            {"*"}},
        {"messages",            {"*"}},
    };
    return m;
}

// Map a Sigma `logsource.category` to the Windows event channel(s) it can
// match (derived from the category table; parent categories union their
// children). Used by deriveChannelQueries() so a category-only rule (no
// service) still contributes its channels to the subscription filter.
// Channel names use the CANONICAL Windows case (EvtSubscribe rejects
// lowercase names with error 87).
static std::unordered_map<std::string, std::vector<std::string>>
buildCategoryChannelMap(const char* product) {
    std::unordered_map<std::string, std::set<std::string>> tmp;
    for (const auto& e : kCategoryTable) {
        if (std::strcmp(e.product, product) != 0) continue;
        const std::string canon = canonicalChannelNames().at(e.channelLower);
        tmp[e.category].insert(canon);
        if (const char* p = parentCategory(e.category)) tmp[p].insert(canon);
    }
    std::unordered_map<std::string, std::vector<std::string>> out;
    for (auto& [cat, chans] : tmp) out[cat].assign(chans.begin(), chans.end());
    return out;
}

// The map for a rule's logsource.product. A rule without a product gets
// the platform the agent runs on.
static const std::unordered_map<std::string, std::vector<std::string>>&
categoryChannelMap(const std::string& product) {
    static const std::unordered_map<std::string, std::vector<std::string>> win =
        buildCategoryChannelMap(kProdWindows);
    static const std::unordered_map<std::string, std::vector<std::string>> lin =
        buildCategoryChannelMap(kProdLinux);
    std::string p = product.empty() ? std::string(hostSigmaProduct()) : product;
    return p == kProdLinux ? lin : win;
}

// --- EventID derivation from a compiled condition ---
//
// nullopt = "unrestricted" (the rule can match any EventID on its channels).
// Rules: a selection restricts to its EventID values (an OR-of-maps
// selection only if every alternative has one); `and` intersects the
// restricted children (an unrestricted child adds nothing); `or` unions,
// but ONE unrestricted child makes the whole `or` unrestricted; `not`
// never restricts; `1 of`/`all of` behave like or/and over their scope.

static std::optional<std::set<int>> selectionEventIds(const SigmaSelection& sel) {
    if (!sel.alternatives.empty()) {
        std::set<int> out;
        for (const auto& alt : sel.alternatives) {
            auto a = selectionEventIds(alt);
            if (!a) return std::nullopt;
            out.insert(a->begin(), a->end());
        }
        return out;
    }
    for (const auto& f : sel.fields) {
        std::string fname = f.field;
        std::transform(fname.begin(), fname.end(), fname.begin(),
            [](unsigned char c) { return static_cast<char>(::tolower(c)); });
        if (fname != "eventid" || f.op != "equals" || f.values.empty()) continue;
        std::set<int> out;
        for (const auto& v : f.values) {
            try { out.insert(std::stoi(v)); } catch (...) { return std::nullopt; }
        }
        return out;
    }
    return std::nullopt;
}

static std::optional<std::set<int>> nodeEventIds(const CondNode& n,
                                                 const std::vector<SigmaSelection>& sels) {
    auto intersectAll = [&](auto&& each, size_t count) -> std::optional<std::set<int>> {
        std::optional<std::set<int>> acc;
        for (size_t i = 0; i < count; ++i) {
            auto r = each(i);
            if (!r) continue;
            if (!acc) { acc = r; continue; }
            std::set<int> both;
            for (int id : *acc) if (r->count(id)) both.insert(id);
            acc = both;
        }
        return acc;
    };
    auto unionAll = [&](auto&& each, size_t count) -> std::optional<std::set<int>> {
        std::set<int> out;
        if (count == 0) return std::nullopt;
        for (size_t i = 0; i < count; ++i) {
            auto r = each(i);
            if (!r) return std::nullopt;
            out.insert(r->begin(), r->end());
        }
        return out;
    };
    switch (n.kind) {
        case CondNode::Kind::Sel:
            return n.sels.empty() ? std::nullopt : selectionEventIds(sels[n.sels[0]]);
        case CondNode::Kind::And:
            return intersectAll([&](size_t i) { return nodeEventIds(*n.kids[i], sels); }, n.kids.size());
        case CondNode::Kind::Or:
            return unionAll([&](size_t i) { return nodeEventIds(*n.kids[i], sels); }, n.kids.size());
        case CondNode::Kind::AllOf:
            return intersectAll([&](size_t i) { return selectionEventIds(sels[n.sels[i]]); }, n.sels.size());
        case CondNode::Kind::OneOf:
            return unionAll([&](size_t i) { return selectionEventIds(sels[n.sels[i]]); }, n.sels.size());
        case CondNode::Kind::Not:
        case CondNode::Kind::False:
        default:
            return std::nullopt;
    }
}

// EventIDs a rule can match, or nullopt when it cannot be pre-filtered by
// EventID. Sequence rules: the union over stages (every stage must be
// restricted). An uncompiled or unparseable condition is unrestricted.
static std::optional<std::set<int>> ruleEventIds(const Detection& rule) {
    if (rule.type == Detection::Type::Sequence) {
        std::set<int> out;
        if (rule.sequence.empty()) return std::nullopt;
        for (const auto& stage : rule.sequence) {
            if (!stage.condAst) return std::nullopt;
            auto r = nodeEventIds(*stage.condAst, stage.selections);
            if (!r) return std::nullopt;
            out.insert(r->begin(), r->end());
        }
        return out;
    }
    if (!rule.condAst) return std::nullopt;
    return nodeEventIds(*rule.condAst, rule.selections);
}

// Rank a Sigma severity level for cross-rule alert selection. Higher = more
// severe. Matches the Sigma spec ordering: critical > high > medium > low >
// informational. Unknown/empty levels rank lowest (0) so a rule with no level
// never suppresses a rule with a real level.
//
// Used by evaluateOnce() to pick the single highest-severity alert when
// multiple Simple rules match the same event (one alert per event, highest
// severity wins). Threshold/sequence rules are NOT subject to this; they
// fire on correlation, not on a single event.
static int severityRank(const std::string& level) {
    std::string l = level;
    std::transform(l.begin(), l.end(), l.begin(),
        [](unsigned char c) { return static_cast<char>(::tolower(c)); });
    if (l == "critical")     return 5;
    if (l == "high")         return 4;
    if (l == "medium")       return 3;
    if (l == "low")          return 2;
    if (l == "informational") return 1;
    return 0;  // unknown / empty
}

// Decide whether a Sigma `logsource.service` name matches the Windows event
// channel of an event. Both sides are compared case-insensitively.
//
// Matching strategy (in order):
//   1. If the service has a known channel mapping, the event channel must
//      equal (or, for wildcarded mappings like "mssql$*/operational",
//      pattern-match) one of the mapped channels.
//   2. Otherwise, fall back to a case-insensitive substring match: the
//      service name must appear somewhere in the channel name. This lets a
//      rule with `service: capi2` match `Microsoft-Windows-CAPI2/Operational`
//      even if the mapping table is incomplete, while still rejecting a
//      channel like `Microsoft-Windows-ServerManager-MgmtProvider/Operational`
//      (which does not contain "capi2").
static bool serviceMatchesChannel(const std::string& sigmaService,
                                  const std::string& eventChannelLower) {
    if (sigmaService.empty() || eventChannelLower.empty()) return false;

    // Look up the service in the known mapping table.
    std::string svcLower = sigmaService;
    std::transform(svcLower.begin(), svcLower.end(), svcLower.begin(),
        [](unsigned char c) { return static_cast<char>(::tolower(c)); });

    for (const auto& [svc, channels] : sigmaServiceChannelMap()) {
        if (svc != svcLower) continue;
        for (const auto& ch : channels) {
            // The map stores canonical Windows channel case (e.g. "Security"),
            // but eventChannelLower is lowercased by the caller. Lowercase
            // the map's channel so the comparison is case-insensitive.
            std::string chLower = ch;
            std::transform(chLower.begin(), chLower.end(), chLower.begin(),
                [](unsigned char c) { return static_cast<char>(::tolower(c)); });
            // Support wildcard mappings (e.g. "mssql$*/operational").
            if (chLower.find('*') != std::string::npos) {
                // Simple single-wildcard pattern: prefix*suffix.
                auto star = chLower.find('*');
                std::string prefix = chLower.substr(0, star);
                std::string suffix = chLower.substr(star + 1);
                if (eventChannelLower.size() >= prefix.size() + suffix.size() &&
                    eventChannelLower.compare(0, prefix.size(), prefix) == 0 &&
                    eventChannelLower.compare(eventChannelLower.size() - suffix.size(),
                                              suffix.size(), suffix) == 0) {
                    return true;
                }
            } else if (eventChannelLower == chLower) {
                return true;
            }
        }
        return false;  // service is known but no channel matched
    }

    // Unknown service: fall back to case-insensitive substring match. This
    // is permissive but still rejects clearly unrelated channels (e.g.
    // "capi2" is not a substring of
    // "microsoft-windows-servermanager-mgmtprovider/operational").
    return eventChannelLower.find(svcLower) != std::string::npos;
}

// Decide whether a rule applies to an event based on its Sigma logsource.
// Two filters are applied, both must pass:
//
//   1. Category filter (logsource.category): if the rule declares a Sigma
//      category (e.g. process_creation), the event must map to that same
//      category. This prevents a process_creation rule from being evaluated
//      against a 5158 WFP network event, where a filter selection
//      (CommandLine: '') would match the empty CommandLine of an unrelated
//      event type and produce a false positive.
//
//   2. Service/channel filter (logsource.service): if the rule declares a
//      service (e.g. "security", "capi2"), the event's Windows channel must
//      match that service. This prevents a rule with `service: capi2` from
//      firing on an event from
//      `Microsoft-Windows-ServerManager-MgmtProvider/Operational`, which is
//      an unrelated channel. Without this check, a rule that only declares
//      a service (no category) would apply to every event.
//
// If the rule declares neither, it applies to all events (backward-
// compatible with rules that have no logsource constraints).
//
// `channelLower` is the event's Windows channel, lowercased, and `cats` the
// event's Sigma categories (own + parent), both computed ONCE per event by
// evaluateOnce so nothing is re-parsed per rule.
//
// Category semantics: a rule whose category the engine knows applies only
// to events classified into it. An event the engine cannot classify (empty
// `cats`, e.g. a 4624 logon) is NOT evaluated against known-category rules:
// a process_creation rule run against a logon is exactly the
// `CommandLine: ''`-filter false positive this check exists to prevent. A
// rule with a category the engine does NOT know can only be meant for
// events the engine cannot classify either, so it applies to those.
static bool ruleAppliesToEvent(const Detection& rule, const BufferedEvent& evt,
                               const std::string& channelLower,
                               const std::vector<std::string>& cats) {
    // Category filter.
    if (!rule.logsource_category.empty()) {
        const std::string& rc = rule.logsource_category;
        if (isKnownCategory(rc)) {
            if (std::find(cats.begin(), cats.end(), rc) == cats.end()) return false;
        } else if (!cats.empty()) {
            return false;
        }
    }

    // Service/channel filter.
    if (!rule.log_sources.empty()) {
        bool matched = false;
        for (const auto& svc : rule.log_sources) {
            if (serviceMatchesChannel(svc, channelLower)) { matched = true; break; }
        }
        if (!matched) return false;
    }

    (void)evt;
    return true;
}

// Pick the console tag for a rule fire. Rules whose only fire-type action is
// forward_event are continuous forwarders and print [FORWARD]; rules with an
// alert (or forward_buffer) action print [ALERT].
static const char* fireTag(const Detection& rule) {
    for (const auto& a : rule.actions) {
        if (a.type == "alert" || a.type == "forward_buffer") {
            return "[ALERT]";
        }
    }
    return "[FORWARD]";
}

// Build the m_states key for a rule + event. For threshold rules the key is
// composite: rule.id + "\x1f" (Unit Separator) + the resolved group-by field
// values, so each distinct group value gets its own independent RuleState
// (sliding window + dedup sets). group_by is mandatory for threshold rules
// (the loader refuses to load a threshold rule without it), so this always
// produces a composite key for them. For simple/sequence rules the key is
// just rule.id (unchanged behavior: one shared state per rule).
//
// If a group-by field is absent from the event, it maps to a "<missing>"
// sentinel so the event still counts into a bucket rather than being
// silently dropped (a rule grouped by TargetUserName should still catch
// events that lack TargetUserName, not go blind to them).
static std::string stateKeyFor(const Detection& rule, const BufferedEvent& evt) {
    if (rule.type != Detection::Type::Threshold) {
        return rule.id;
    }
    std::string key = rule.id;
    for (const auto& field : rule.group_by) {
        key.push_back('\x1f');
        std::wstring wv = resolveFieldCached(evt, field);
        if (wv.empty()) {
            key += "<missing>";
        } else {
            // Group keys are field values (usernames, hostnames): ASCII-safe
            // narrowing. Non-ASCII characters are truncated to their low byte,
            // which is acceptable for grouping (collisions only merge groups,
            // they don't drop events).
            key.append(wv.begin(), wv.end());
        }
    }
    return key;
}

// Threshold fire condition. Empty/absent threshold_op = "gte" (the default).
// Unrecognized values fall back to "gte" for safety (the server validates at
// save time, but a hand-edited rule file could have anything).
static bool thresholdMet(int count, const Detection& rule) {
    const std::string& op = rule.threshold_op;
    if (op == "gt")  return count >  rule.threshold;
    if (op == "eq")  return count == rule.threshold;
    // "gte" or empty or unrecognized → gte (the default).
    return count >= rule.threshold;
}

// Run alert + forward_buffer actions on rule fire. Returns true if a
// forward_buffer action was executed. Threads the rule's Sigma `level`
// through to the server so alerts can be sorted/colored by severity.
// `evidenceEvents` carries the correlation evidence so the alert payload
// includes the full picture, not just the trigger: for sequence rules, the
// events that formed the sequence (the attack chain); for threshold rules,
// the events that filled the sliding window (all counted events, or one
// representative per unique value for `distinct` rules). Empty for simple
// rules. `evidenceIsSequence` tells the transport which payload key to use:
// `sequence_events` for sequence chains, `window_events` for threshold
// windows, so the server UI can label the items correctly (Stage N vs
// Event N). `alsoMatched` lists the Simple rules suppressed by severity
// selection for this event.
//
// forward_buffer: sends the buffer events this rule has not sent before
// (tracked by a per-rule absolute cursor) and does NOT clear the buffer.
// Clearing it would silently discard the rest of the pass for every other
// rule (their alerts, threshold counts and sequence stages for those
// events would simply never be evaluated). The per-rule
// cursor gives the same "don't re-send what I already sent" result for
// this rule while leaving the events in place for everyone else.
//
// Memory: the buffer is snapshotted only when a forward_buffer action
// actually fires (rare), never on an ordinary evaluation pass.
bool RuleEngine::runFireActions(const Detection& rule, const BufferedEvent& trigger,
                                const std::vector<BufferedEvent>& evidenceEvents,
                                bool evidenceIsSequence,
                                const std::vector<std::string>& alsoMatched) {
    bool forwardedBuffer = false;
    // The alert message is the Sigma rule's `description` line, not the
    // action's `message` field. The description is the human-readable
    // explanation of what the rule detects.
    const std::string& alertMessage = rule.description.empty() ? rule.name : rule.description;
    // Track whether an `alert` action already fired for this rule on this
    // event. When a rule has BOTH `alert` AND `forward_buffer` actions, the
    // `alert` action already sends a POST /alerts to the server. The
    // `forward_buffer` action's reportLogs() ALSO sends a POST /alerts as a
    // "forward_buffer fired" notification; without this flag that would
    // produce a duplicate alert (same EventRecordID, ~20ms apart) on the
    // server. When an `alert` action already fired, we tell forwardBuffer to
    // skip its notification alert so only ONE alert reaches the server.
    // forward_buffer-only rules (no `alert` action) still get their
    // notification alert because alertAlreadyFired stays false.
    bool alertAlreadyFired = false;
    const RuleMeta meta = ruleMetaOf(rule);
    const std::string alertId = newAlertId();
    for (const auto& a : rule.actions) {
        if (a.type == "alert") {
            m_forwarder.forwardAlert(trigger, a.destination, meta, alertMessage,
                                     evidenceEvents, evidenceIsSequence, alsoMatched,
                                     alertId);
            alertAlreadyFired = true;
        } else if (a.type == "forward_buffer") {
            uint64_t& cursor = m_forwardBufferCursor[rule.id];
            uint64_t absEnd = 0;
            // Not an evaluation cursor: events popped before this rule's
            // cursor are not "unevaluated", so don't count them as such.
            auto snapshot = m_buffer.snapshotFromAbsolute(cursor, absEnd,
                                                          /*trackEvicted=*/false);
            cursor = absEnd;
            // Always call forwardBuffer, even with an empty snapshot: the
            // file write is skipped for an empty buffer, but the server
            // notification for a forward_buffer-only rule must still go.
            m_forwarder.forwardBuffer(trigger, alertMessage, snapshot, a.destination,
                                      meta, evidenceEvents,
                                      /*skipAlertNotification=*/alertAlreadyFired,
                                      /*evidenceIsSequence=*/evidenceIsSequence,
                                      alsoMatched, alertId);
            forwardedBuffer = true;
        }
    }
    return forwardedBuffer;
}

bool RuleEngine::evaluateRule(const Detection& rule, BufferedEvent& evt, uint64_t key,
                              const Detection** simpleCandidate) {
    if (simpleCandidate) *simpleCandidate = nullptr;
    // forward_event actions run on every matching event (continuous), regardless
    // of whether the rule "fires" (for threshold/sequence). For simple rules,
    // a match IS a fire.
    bool matched = false;

    // `key` is the content-based dedup key: a hash of (channel,
    // EventRecordID). Robust against the deque shifting when cleanup pops
    // front events and, unlike the bare record id, unique across channels.
    // 0 means the event has no record id and is never deduplicated. The
    // sets are per-rule so one rule firing on an event does not suppress a
    // different rule.

    if (rule.type == Detection::Type::Simple) {
        matched = matchEvent(rule, evt);
        if (!matched) return false;
        RuleState& state = m_states[rule.id];

        // Continuous forwarding of every matching event. This is NOT subject
        // to severity selection; every matching Simple rule forwards its
        // event stream regardless of which rule wins the alert. Dedup so a
        // re-evaluated event (e.g. after the buffer shrinks) is not
        // re-forwarded, which would produce duplicate streams in
        // SIEM/data_lake. Per-rule so different rules can each forward the
        // same event to their own destinations.
        if (key != 0 && state.forwardedRecordIds.count(key)) {
            // Already forwarded this exact event for this rule; skip the
            // forward_event action but continue (the alert dedup below still
            // runs).
        } else {
            runForwardEventActions(rule, evt, m_forwarder);
            if (key != 0) state.forwardedRecordIds[key] = evt.receivedAt;
        }

        // Dedup. When deduped, return false (not true) so the caller doesn't
        // count this as a fire or log "Rule fired"; no alert was actually
        // sent. Returning true on dedup caused noisy duplicate "Rule fired"
        // console lines (one per re-evaluation) even though only one alert
        // packet was ever forwarded.
        if (key != 0 && state.alertedRecordIds.count(key)) return false;
        if (key != 0) state.alertedRecordIds[key] = evt.receivedAt;

        // Severity-based selection: do NOT fire alert/forward_buffer here.
        // Report this rule as a candidate; the caller (evaluateOnce) collects
        // all Simple-rule candidates for this event and fires only the
        // highest-severity one. This prevents alert storms when several
        // Simple rules match the same event (e.g. a generic "process created"
        // rule and a specific "suspicious process" rule both fire on one
        // 4688). Threshold/Sequence rules are NOT subject to this; they fire
        // independently below.
        if (simpleCandidate) *simpleCandidate = &rule;
        return true;
    }

    if (rule.type == Detection::Type::Threshold) {
        matched = matchEvent(rule, evt);
        if (!matched) return false;
        RuleState& state = m_states[stateKeyFor(rule, evt)];

        // Continuous forwarding of every matching event. Dedup so a
        // re-evaluated event is not re-forwarded (same guard as the Simple
        // path). Per-rule so different rules can each forward the same event.
        if (key != 0 && state.forwardedRecordIds.count(key)) {
            // Already forwarded; skip.
        } else {
            runForwardEventActions(rule, evt, m_forwarder);
            if (key != 0) state.forwardedRecordIds[key] = evt.receivedAt;
        }

        // Sliding window: record this match, drop expired entries. Dedup so a
        // re-evaluated event (e.g. after the buffer shrinks and the evaluation
        // cursor resets) is not counted twice toward the threshold; that
        // would make the rule fire on a single real event. Events already in
        // alertedRecordIds already contributed to a prior fire and must NOT
        // be re-counted (they would re-trigger the window).
        auto now = evt.receivedAt;
        bool alreadyCounted = (key != 0 && state.thresholdRecordIds.count(key));
        bool alreadyAlerted = (key != 0 && state.alertedRecordIds.count(key));
        if (alreadyCounted || alreadyAlerted) {
            // Already counted or already fired on this exact event; do not
            // add it to the window again.
        } else {
            state.matchTimes.push_back(now);
            state.matchRecordIds.push_back(key);
            if (key != 0) state.thresholdRecordIds.insert(key);
            // distinct: track unique resolved field values instead of raw
            // events. Insert-or-refresh: a repeated value updates its
            // last-seen time (sliding-window semantics: a value stays in
            // the window while it keeps being seen within the timeframe).
            if (!rule.distinct_by.empty()) {
                std::string dkey;
                for (const auto& field : rule.distinct_by) {
                    dkey.push_back('\x1f');
                    std::wstring wv = resolveFieldCached(evt, field);
                    if (wv.empty()) {
                        dkey += "<missing>";
                    } else {
                        // Same ASCII-safe narrowing as stateKeyFor;
                        // collisions only merge distinct values, they
                        // never drop events.
                        dkey.append(wv.begin(), wv.end());
                    }
                }
                state.distinctValues[dkey] = now;
                // Fire-time evidence: keep ONE representative (most
                // recently seen) event per unique value, insert-or-replace
                // mirroring distinctValues above: a value repeated
                // hundreds of times contributes exactly ONE evidence
                // event, so the evidence set stays bounded by the number
                // of unique values in the window.
                state.distinctValueEvents[dkey] = evt.stripped();
            } else {
                // Fire-time evidence for non-distinct rules: remember
                // every counted event, parallel to matchTimes, so the
                // alert can carry all events that filled the window.
                // Evidence copies carry only time + XML (no field cache):
                // a window of hundreds of events would otherwise hold
                // hundreds of parsed field maps.
                state.windowEvents.push_back(evt.stripped());
            }
        }
        auto window = std::chrono::seconds(rule.time_window_seconds);
        while (!state.matchTimes.empty() &&
               now - state.matchTimes.front() > window) {
            state.matchTimes.pop_front();
            // The expired event leaves the dedup set too; otherwise a
            // group that keeps matching without ever reaching the
            // threshold accumulates every key it has ever seen.
            uint64_t expired = state.matchRecordIds.front();
            state.matchRecordIds.pop_front();
            if (expired != 0) state.thresholdRecordIds.erase(expired);
            // Keep the evidence deque in sync with the window (non-distinct
            // rules only; distinct rules use distinctValueEvents).
            if (!state.windowEvents.empty()) state.windowEvents.pop_front();
        }
        // Expire distinct values not refreshed within the window. O(unique
        // values in window) per matching event, bounded by how many
        // distinct values can arrive within one timeframe.
        if (!rule.distinct_by.empty()) {
            for (auto it = state.distinctValues.begin();
                 it != state.distinctValues.end();) {
                if (now - it->second > window) {
                    // Drop the expired value's evidence event too (keyed by
                    // the same composite key).
                    state.distinctValueEvents.erase(it->first);
                    it = state.distinctValues.erase(it);
                } else {
                    ++it;
                }
            }
        }

        // Fire condition: with `distinct`, count unique field values in
        // the window instead of raw matching events: `ping -n 10
        // <onehost>` is 10 events but 1 unique destination and must NOT
        // fire a threshold-5 distinct rule. Without `distinct`, unchanged
        // per-event counting.
        int fireCount = rule.distinct_by.empty()
                            ? static_cast<int>(state.matchTimes.size())
                            : static_cast<int>(state.distinctValues.size());
        if (thresholdMet(fireCount, rule)) {
            // Fire alert + forward_buffer on the triggering event. Mark ALL
            // events that contributed to this window as already-fired so a
            // later re-evaluation (after the buffer shrinks and the cursor
            // resets to 0) does not re-count any of them toward a new window
            // and re-fire on the same burst.
            if (alreadyAlerted) {
                // This event already contributed to a prior fire. Suppress
                // the re-fire and clear the window. Return false: no alert is
                // actually sent, so this must not count as a fire.
                state.matchTimes.clear();
                state.matchRecordIds.clear();
                state.thresholdRecordIds.clear();
                state.distinctValues.clear();
                state.windowEvents.clear();
                state.distinctValueEvents.clear();
                return false;
            }
            if (key != 0) state.alertedRecordIds[key] = evt.receivedAt;
            for (uint64_t wkey : state.matchRecordIds) {
                if (wkey != 0) state.alertedRecordIds[wkey] = evt.receivedAt;
            }
            // Fire-time evidence: copy the window's contributing events
            // (all counted events for non-distinct rules, one representative
            // per unique value for distinct rules) so the alert payload can
            // carry the full picture, not just the trigger. The state
            // containers are cleared below after the call, so copy first
            // (same pattern as the sequence path's seqCopy).
            std::vector<BufferedEvent> winCopy;
            if (!rule.distinct_by.empty()) {
                winCopy.reserve(state.distinctValueEvents.size());
                for (const auto& kv : state.distinctValueEvents) {
                    winCopy.push_back(kv.second);
                }
            } else {
                winCopy.assign(state.windowEvents.begin(), state.windowEvents.end());
            }
            runFireActions(rule, evt, winCopy);
            // Reset the window after firing so the rule can fire again on a
            // fresh burst.
            state.matchTimes.clear();
            state.matchRecordIds.clear();
            state.thresholdRecordIds.clear();
            state.distinctValues.clear();
            state.windowEvents.clear();
            state.distinctValueEvents.clear();
            return true;
        }
        return false;
    }

    if (rule.type == Detection::Type::Sequence) {
        if (rule.sequence.empty()) return false;
        RuleState& state = m_states[rule.id];
        if (state.nextStage >= rule.sequence.size()) return false;
        auto window = std::chrono::seconds(rule.time_window_seconds);

        // A partial chain whose window has already run out can never
        // complete. Forget it BEFORE matching, so this event is free to start
        // a new chain. (Matching first against the stale chain's next stage
        // and only then noticing the expiry would drop a real stage-N event
        // that arrives just after an old window lapsed.)
        if (state.nextStage > 0 && evt.receivedAt - state.windowStart > window) {
            state.nextStage = 0;
            state.sequenceEvents.clear();
        }

        size_t stageIdx = state.nextStage;
        matched = matchStage(rule.sequence[stageIdx], evt);
        if (!matched && stageIdx > 0 && matchStage(rule.sequence[0], evt)) {
            // Waiting for a later stage, but this is a fresh stage-0 event:
            // the attacker started over (or a second attempt began). Restart
            // the chain here so the window is anchored to the most recent
            // start, instead of ignoring the event and letting the stale
            // window expire underneath the real continuation.
            stageIdx = 0;
            state.nextStage = 0;
            state.sequenceEvents.clear();
            matched = true;
        }
        if (!matched) return false;

        // Continuous forwarding of every matching event (any stage match).
        // Dedup so a re-evaluated event is not re-forwarded (same guard as
        // the Simple/Threshold paths). Per-rule.
        if (key != 0 && state.forwardedRecordIds.count(key)) {
            // Already forwarded; skip.
        } else {
            runForwardEventActions(rule, evt, m_forwarder);
            if (key != 0) state.forwardedRecordIds[key] = evt.receivedAt;
        }

        if (stageIdx == 0) {
            // Start of a new sequence window.
            state.windowStart = evt.receivedAt;
            state.sequenceEvents.clear();
        }
        state.sequenceEvents.push_back(evt.stripped());
        state.nextStage = stageIdx + 1;

        // Did we complete the sequence?
        if (state.nextStage == rule.sequence.size()) {
            // Fire on the last triggering event (dedup by event key).
            // When deduped, return false (not true) so the caller doesn't log
            // "Rule fired"; no alert was actually sent (same as the
            // Simple-rule path).
            if (key != 0 && state.alertedRecordIds.count(key)) {
                state.nextStage = 0;
                state.sequenceEvents.clear();
                return false;
            }
            if (key != 0) state.alertedRecordIds[key] = evt.receivedAt;
            // Pass the sequence events (all stages that formed the sequence)
            // so the alert payload includes the full attack chain, not just
            // the trigger. state.sequenceEvents is cleared below after the
            // call, so copy it first.
            auto seqCopy = state.sequenceEvents;
            runFireActions(rule, evt, seqCopy, /*evidenceIsSequence=*/true);
            // Reset for the next sequence.
            state.nextStage = 0;
            state.sequenceEvents.clear();
            return true;
        }
        return false;
    }

    return false;
}

std::shared_ptr<const RuleSet> RuleEngine::currentRuleSet() const {
    std::lock_guard<std::mutex> lock(m_rulesMutex);
    return m_ruleSet;
}

void RuleEngine::pruneStates(const RuleSet& rs,
                             std::chrono::system_clock::time_point now) {
    for (auto it = m_states.begin(); it != m_states.end();) {
        auto& state = it->second;
        const std::string& stateKey = it->first;
        // Threshold states are keyed rule.id + '\x1f' + group values; simple
        // and sequence states by rule.id alone.
        auto sep = stateKey.find('\x1f');
        bool grouped = sep != std::string::npos;
        std::string ruleId = grouped ? stateKey.substr(0, sep) : stateKey;

        // State for a rule that is no longer loaded can never fire again;
        // keeping it would leak one entry per deleted rule (and per group)
        // for the life of the process.
        auto rIt = rs.byId.find(ruleId);
        if (rIt == rs.byId.end()) {
            it = m_states.erase(it);
            continue;
        }
        const Detection& rule = *rIt->second;

        // Prune stale alertedRecordIds (older than ALERT_DEDUP_TTL).
        for (auto aIt = state.alertedRecordIds.begin();
             aIt != state.alertedRecordIds.end();) {
            if (now - aIt->second > ALERT_DEDUP_TTL)
                aIt = state.alertedRecordIds.erase(aIt);
            else
                ++aIt;
        }
        // Prune stale forwardedRecordIds (older than ALERT_DEDUP_TTL).
        // These guard forward_event dedup; without pruning they would
        // grow unbounded on a long-running agent that forwards many
        // events. Same TTL as alertedRecordIds for simplicity.
        for (auto fIt = state.forwardedRecordIds.begin();
             fIt != state.forwardedRecordIds.end();) {
            if (now - fIt->second > ALERT_DEDUP_TTL)
                fIt = state.forwardedRecordIds.erase(fIt);
            else
                ++fIt;
        }

        // Expire a threshold window against the wall clock. Window expiry
        // otherwise only runs when a NEW matching event arrives, so a
        // group that goes quiet keeps its last window (and the evidence
        // event copies in it) forever.
        if (rule.type == Detection::Type::Threshold) {
            auto window = std::chrono::seconds(rule.time_window_seconds);
            while (!state.matchTimes.empty() &&
                   now - state.matchTimes.front() > window) {
                state.matchTimes.pop_front();
                uint64_t expired = state.matchRecordIds.front();
                state.matchRecordIds.pop_front();
                if (expired != 0) state.thresholdRecordIds.erase(expired);
                if (!state.windowEvents.empty()) state.windowEvents.pop_front();
            }
            for (auto dIt = state.distinctValues.begin();
                 dIt != state.distinctValues.end();) {
                if (now - dIt->second > window) {
                    state.distinctValueEvents.erase(dIt->first);
                    dIt = state.distinctValues.erase(dIt);
                } else {
                    ++dIt;
                }
            }
        }

        // Evict idle per-group threshold states to bound memory. A grouped
        // state with no active window and no recent dedup entries will
        // never fire again and can be dropped. This bounds memory under
        // group-cardinality explosion (a noisy host with many distinct
        // users). Never evict simple/sequence states (keys without '\x1f')
        // since those are keyed by rule.id and losing them would discard their
        // dedup state.
        if (grouped && state.matchTimes.empty() && state.distinctValues.empty() &&
            state.alertedRecordIds.empty() && state.forwardedRecordIds.empty()) {
            it = m_states.erase(it);
            continue;
        }
        ++it;
    }
    for (auto cIt = m_forwardBufferCursor.begin(); cIt != m_forwardBufferCursor.end();) {
        if (rs.byId.count(cIt->first) == 0) cIt = m_forwardBufferCursor.erase(cIt);
        else ++cIt;
    }
}

void RuleEngine::pruneNow() {
    auto rs = currentRuleSet();
    if (!rs) return;
    m_lastDedupPrune = std::chrono::system_clock::now();
    pruneStates(*rs, m_lastDedupPrune);
}

EngineStats RuleEngine::stats() const {
    EngineStats s;
    s.states = m_states.size();
    for (const auto& kv : m_states) {
        s.thresholdIds += kv.second.thresholdRecordIds.size();
        s.alertedIds += kv.second.alertedRecordIds.size();
    }
    s.forwardBufferCursors = m_forwardBufferCursor.size();
    return s;
}

size_t RuleEngine::evaluateOnce() {
    // Take our own reference to the current ruleset. A concurrent reload()
    // swaps the engine's pointer but cannot free or modify the set this
    // pass is reading; the old set is released when the last pass holding
    // it finishes.
    auto rs = currentRuleSet();

    // No rules loaded → nothing to evaluate or forward. Skip the pass
    // entirely (no snapshot, no cursor advance) so a no-rules agent is
    // idle. This is the defensive guard behind the subscription guard in
    // main.cpp: even if events somehow reach the buffer, they are never
    // forwarded without a rule that explicitly forwards them.
    if (!rs || rs->empty()) {
        return 0;
    }

    // Periodically prune stale dedup entries / idle states to bound memory.
    auto now = std::chrono::system_clock::now();
    if (now - m_lastDedupPrune > DEDUP_PRUNE_INTERVAL) {
        m_lastDedupPrune = now;
        pruneStates(*rs, now);
    }

    // Only process events that arrived since the last pass. This prevents
    // threshold/sequence state from being inflated by re-scanning the whole
    // buffer every pass, and prevents simple rules from re-firing on events
    // they already fired on.
    //
    // The cursor is an ABSOLUTE stream index (offset from the start of the
    // stream), not a live deque index. snapshotFromAbsolute converts it
    // using EventBuffer::frontPopped() and hands back `absEnd`, the absolute
    // index just past the newest snapshotted event, computed under the same
    // lock as the snapshot. That is the next cursor value. (Computing it
    // after the pass as frontPopped() + size would move the cursor past
    // every event the cleanup thread pops DURING the pass, skipping that
    // many brand-new events on a busy host, every pass.)
    uint64_t absEnd = 0;
    auto newEvents = m_buffer.snapshotFromAbsolute(m_evaluatedAbsolute, absEnd);
    const uint64_t absStart = absEnd - newEvents.size();

    size_t fires = 0;
    bool dbg = debugEnabled();
    for (size_t i = 0; i < newEvents.size(); ++i) {
        BufferedEvent& evt = newEvents[i];
        // Absolute stream index of this event (for debug logging only).
        uint64_t absIndex = absStart + i;
        // Warm the field cache ONCE per event. This parses the XML a single
        // time into a flat field map; all subsequent resolveFieldCached
        // calls (from every rule's evalSigmaField, stateKeyFor, etc.) are
        // O(1) hash lookups. This is the key to scaling to 1000+ rules:
        // the XML is parsed once per event, not once per field per rule.
        populateFieldCache(evt);
        // Extract the event's channel ONCE per event (from the cache) to
        // look up only the rules that could possibly match this channel.
        const CachedField* chanField = lookupField(evt, "channel");
        const std::string channel = chanField ? chanField->lower : std::string();
        const int eid = extractEventIdCached(evt);
        // Dedup identity, once per event (it hashes the channel + record id).
        const uint64_t dedupKey = eventDedupKey(evt);
        // Sigma categories of this event (own + parent), computed once and
        // used to pick the category bucket(s) below.
        const std::vector<std::string> cats = eventSigmaCategories(channel, eid);
        if (dbg) {
            std::string catList;
            for (const auto& c : cats) { if (!catList.empty()) catList += ","; catList += c; }
            logInfo("[DEBUG] eval event idx=" + std::to_string(absIndex) +
                    " EventID=" + std::to_string(eid) + " Channel=" + channel +
                    " categories=" + (catList.empty() ? "<none>" : catList));
        }

        // Build the candidate rule list for this event from the index:
        //   1. catch-all rules (no service/category): always evaluated.
        //   2. channel-indexed rules for this event's channel.
        //   3. category/unknown-service rules: need a per-event check.
        // This avoids iterating the full ruleset for every event.
        //
        // Severity-based selection (Simple rules): evaluateRule reports each
        // matching Simple rule as a candidate (instead of firing its alert
        // immediately). We collect all candidates across the three buckets
        // for this event, then fire only the highest-severity one (first
        // wins ties). Threshold/Sequence rules fire independently inside
        // evaluateRule and are not collected here.
        //
        // Every bucket is always walked in full. A forward_buffer fire no
        // longer stops the pass or clears the buffer, so one rule's action
        // can never hide the event from another rule.
        std::vector<const Detection*> simpleCandidates;
        auto evalRulePtr = [&](const Detection* rulePtr) {
            const Detection& rule = *rulePtr;
            const Detection* candidate = nullptr;
            bool fired = false;
            // One bad rule (or one pathological event) must not take the
            // whole pass down: an exception escaping here would kill the
            // engine thread, and because the cursor never advances past the
            // event, a restart would throw on the same event again. Contain
            // it to this rule, log it once, and keep evaluating the others.
            try {
                fired = evaluateRule(rule, evt, dedupKey, &candidate);
            } catch (const std::exception& e) {
                if (m_loggedThrowingRules.insert(rule.id).second) {
                    logError("[RuleEngine] rule '" + rule.id + "' threw on event idx " +
                             std::to_string(absIndex) + ": " + e.what() +
                             " (further throws by this rule are not logged)");
                }
                return;
            } catch (...) {
                if (m_loggedThrowingRules.insert(rule.id).second) {
                    logError("[RuleEngine] rule '" + rule.id +
                             "' threw a non-std exception on event idx " +
                             std::to_string(absIndex));
                }
                return;
            }
            if (fired && !candidate) {
                // Only count/log a fire for threshold/sequence rules (which
                // fire their alert inside evaluateRule). Simple rules report
                // a candidate here; their fire is counted/logged only if they
                // win the severity race below. This keeps the `fires` return
                // value and the "Rule fired" log accurate (an actual alert
                // was sent), not inflated by suppressed Simple matches.
                ++fires;
                const char* tag = fireTag(rule);
                if (tag[1] == 'A') {  // "[ALERT]" vs "[FORWARD]"
                    logNotice(std::string(tag) + " Rule fired: " + rule.id +
                              " (" + rule.name + ")");
                }
            }
            if (candidate) simpleCandidates.push_back(candidate);
        };

        // 1. Catch-all rules (no logsource constraints).
        for (const auto* rulePtr : rs->catchAll) {
            evalRulePtr(rulePtr);
        }

        // 2. Channel-indexed rules for this event's channel. These rules'
        // service already matches the channel (that's why they're indexed
        // here), but a rule may ALSO declare a category; if so, still
        // apply the category check using the pre-extracted channel (no
        // re-parse). Rules indexed here with a category are rare (most
        // Sigma rules use service OR category, not both), so the extra
        // check is cheap.
        auto chIt = rs->channel.find(channel);
        if (chIt != rs->channel.end()) {
            for (const auto* rulePtr : chIt->second) {
                const Detection& rule = *rulePtr;
                if (!rule.logsource_category.empty() &&
                    !ruleAppliesToEvent(rule, evt, channel, cats)) {
                    continue;
                }
                evalRulePtr(rulePtr);
            }
        }

        // 3. Category rules: only the bucket(s) for this event's categories
        // (a rule has one category, an event's categories are distinct, so
        // no rule is visited twice). An unclassified event sees the rules
        // whose category the engine does not know either (see
        // ruleAppliesToEvent for why known-category rules are skipped).
        if (!cats.empty()) {
            for (const auto& cat : cats) {
                auto catIt = rs->byCategory.find(cat);
                if (catIt == rs->byCategory.end()) continue;
                for (const auto* rulePtr : catIt->second) evalRulePtr(rulePtr);
            }
        } else {
            for (const auto* rulePtr : rs->unmappedCategory) evalRulePtr(rulePtr);
        }

        // 4. Unknown-service rules: per-event substring check of the
        // service against the channel (plus their category, if any).
        for (const auto* rulePtr : rs->unknownService) {
            const Detection& rule = *rulePtr;
            if (!ruleAppliesToEvent(rule, evt, channel, cats)) continue;
            evalRulePtr(rulePtr);
        }

        // 5. Severity-based selection: among all Simple rules that matched
        // this event, fire only the highest-severity one. Ties are broken by
        // rule order (the first candidate wins), which matches the order the
        // rules were evaluated above (catch-all → channel → category) and
        // the order within each bucket (file load order). This prevents
        // alert storms when several Simple rules match the same event.
        // The losers are not forgotten: their ids ride along on the winning
        // alert as `also_matched` so the analyst still sees every rule that
        // detected the event. Threshold/Sequence rules already fired
        // independently inside evaluateRule and are not in simpleCandidates.
        if (!simpleCandidates.empty()) {
            const Detection* winner = simpleCandidates[0];
            int winnerRank = severityRank(winner->level);
            for (size_t ci = 1; ci < simpleCandidates.size(); ++ci) {
                int r = severityRank(simpleCandidates[ci]->level);
                // Strictly greater: first match wins ties (rule order).
                if (r > winnerRank) {
                    winner = simpleCandidates[ci];
                    winnerRank = r;
                }
            }
            std::vector<std::string> alsoMatched;
            for (const auto* c : simpleCandidates) {
                if (c != winner) alsoMatched.push_back(c->id);
            }
            runFireActions(*winner, evt, {}, false, alsoMatched);
            // Count and log the winning Simple rule's fire now (it was
            // deferred from evalRulePtr above). This keeps the `fires`
            // return value and the "Rule fired" log accurate: one fire per
            // actual alert sent.
            ++fires;
            const char* tag = fireTag(*winner);
            if (tag[1] == 'A') {  // "[ALERT]" vs "[FORWARD]"
                logNotice(std::string(tag) + " Rule fired: " + winner->id +
                          " (" + winner->name + ")" +
                          (alsoMatched.empty() ? "" :
                           " [also matched: " + std::to_string(alsoMatched.size()) + "]"));
            }
        }
    }

    // Advance the cursor past the events we just processed.
    m_evaluatedAbsolute = absEnd;
    return fires;
}

} // namespace elf
