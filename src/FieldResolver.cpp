#include "FieldResolver.h"
#include "BufferedEvent.h"
#include <algorithm>
#include <cctype>
#include <cwctype>
#include <unordered_map>
#include <utility>
#include <vector>

namespace elf {

// --- Small wide-string helpers (no external XML dep) ---

static std::wstring toLower(std::wstring s) {
    std::transform(s.begin(), s.end(), s.begin(), ::towlower);
    return s;
}

static std::wstring toWide(const std::string& s) {
    if (s.empty()) return std::wstring();
    return std::wstring(s.begin(), s.end());
}

static std::string toNarrow(const std::wstring& s) {
    if (s.empty()) return std::string();
    return std::string(s.begin(), s.end());
}

// Case-insensitive find of `needle` in `haystack`.
static size_t ifind(const std::wstring& haystack, const std::wstring& needle, size_t pos = 0) {
    if (needle.empty()) return std::wstring::npos;
    if (pos >= haystack.size()) return std::wstring::npos;
    auto h = toLower(haystack);
    auto n = toLower(needle);
    return h.find(n, pos);
}

// Extract the text between <tag ...> and </tag>. `startPos` is where to begin
// searching for the opening tag. Returns the inner text and advances `startPos`
// to just after the closing tag. Returns empty string if not found.
static std::wstring extractElementText(const std::wstring& xml,
                                       const std::wstring& tag,
                                       size_t& startPos) {
    std::wstring open = L"<" + tag;
    size_t s = ifind(xml, open, startPos);
    if (s == std::wstring::npos) return L"";

    // Skip attributes to the closing '>' of the opening tag.
    size_t gt = xml.find(L'>', s + open.size());
    if (gt == std::wstring::npos) return L"";

    // Self-closing tag like <EventID Qualifiers="..."/> has no inner text.
    if (gt > 0 && xml[gt - 1] == L'/') {
        startPos = gt + 1;
        return L"";
    }

    size_t textStart = gt + 1;
    std::wstring close = L"</" + tag + L">";
    size_t e = ifind(xml, close, textStart);
    if (e == std::wstring::npos) return L"";

    startPos = e + close.size();
    return xml.substr(textStart, e - textStart);
}

// Extract the value of an attribute named `attr` from the opening tag that
// begins at `tagStart`. Returns empty string if not found. Handles both
// single- and double-quoted attribute values (EvtRender uses single quotes).
static std::wstring extractAttribute(const std::wstring& xml, size_t tagStart,
                                     const std::wstring& attr) {
    // Find end of opening tag.
    size_t gt = xml.find(L'>', tagStart);
    if (gt == std::wstring::npos) return L"";
    std::wstring tagContent = xml.substr(tagStart, gt - tagStart);

    // Try double quotes first, then single quotes (EvtRender uses single).
    const wchar_t quotes[2] = {L'"', L'\''};
    for (int qi = 0; qi < 2; ++qi) {
        wchar_t q = quotes[qi];
        std::wstring needle = attr + L"=" + q;
        size_t s = ifind(tagContent, needle);
        if (s == std::wstring::npos) continue;
        size_t valStart = s + needle.size();
        size_t valEnd = tagContent.find(q, valStart);
        if (valEnd == std::wstring::npos) continue;
        return tagContent.substr(valStart, valEnd - valStart);
    }
    return L"";
}

// Find the start of the nth occurrence of <tag (used to index EventData/Data).
static size_t findElement(const std::wstring& xml, const std::wstring& tag, size_t startPos) {
    std::wstring open = L"<" + tag;
    return ifind(xml, open, startPos);
}

std::wstring resolveField(const std::wstring& xml, const std::string& field) {
    if (field.empty()) return L"";

    // Support dotted names like "EventData.CommandLine": use the last segment
    // as the Data Name, but only search within the named parent element.
    std::string leaf = field;
    size_t dot = field.rfind('.');
    if (dot != std::string::npos) leaf = field.substr(dot + 1);

    // --- Sigma field-name aliases ---
    // Sigma rules use generic field names (Image, CommandLine, User, etc.)
    // that map to Windows EventData fields. Map common Sigma names to their
    // Windows equivalents so Sigma rules work against Windows events without
    // per-rule rewriting. The mapping is case-insensitive.
    //
    // Reference: Sigma Windows logsource field names vs. Windows Security
    // / Sysmon EventData names.
    static const std::vector<std::pair<std::string, std::string>> kSigmaAliases = {
        // Process creation (4688 / Sysmon 1)
        {"Image",            "NewProcessName"},
        {"ParentImage",      "ParentProcessName"},
        {"CommandLine",      "CommandLine"},
        {"ParentCommandLine","ParentCommandLine"},
        {"ProcessId",       "ProcessId"},
        {"ParentProcessId", "ParentProcessId"},
        // Logon (4624/4625)
        {"TargetUserName",  "TargetUserName"},
        {"TargetDomainName", "TargetDomainName"},
        {"LogonType",       "LogonType"},
        {"SubjectUserName", "SubjectUserName"},
        {"SubjectDomainName","SubjectDomainName"},
        {"WorkstationName", "WorkstationName"},
        {"IpAddress",       "IpAddress"},
        {"SourceIpAddress", "IpAddress"},
        // Service / task / misc
        {"ServiceName",     "ServiceName"},
        {"ServiceFileName", "ImagePath"},
        {"TaskName",        "TaskName"},
        {"ScriptBlockText", "ScriptBlockText"},
    };
    std::string leafLower = toNarrow(toLower(toWide(leaf)));
    for (const auto& kv : kSigmaAliases) {
        std::string k = toNarrow(toLower(toWide(kv.first)));
        if (k == leafLower) { leaf = kv.second; break; }
    }

    // System fields.
    if (leaf == "EventID" || leaf == "event_id") {
        size_t pos = 0;
        return extractElementText(xml, L"EventID", pos);
    }
    if (leaf == "EventRecordID" || leaf == "event_record_id") {
        size_t pos = 0;
        return extractElementText(xml, L"EventRecordID", pos);
    }
    if (leaf == "Channel" || leaf == "channel") {
        size_t pos = 0;
        return extractElementText(xml, L"Channel", pos);
    }
    if (leaf == "Computer" || leaf == "computer") {
        size_t pos = 0;
        return extractElementText(xml, L"Computer", pos);
    }
    if (leaf == "Provider" || leaf == "provider") {
        size_t s = findElement(xml, L"Provider", 0);
        if (s == std::wstring::npos) return L"";
        return extractAttribute(xml, s, L"Name");
    }
    if (leaf == "TimeCreated" || leaf == "time_created") {
        size_t s = findElement(xml, L"TimeCreated", 0);
        if (s == std::wstring::npos) return L"";
        return extractAttribute(xml, s, L"SystemTime");
    }

    // Otherwise: look in <EventData><Data Name="LEAF">text</Data>.
    // Iterate over all <Data ...> elements and match by Name attribute.
    std::wstring wleaf = toWide(leaf);
    size_t searchPos = 0;
    // First find the EventData block to bound the search.
    size_t edStart = findElement(xml, L"EventData", 0);
    size_t edEnd = std::wstring::npos;
    if (edStart != std::wstring::npos) {
        std::wstring edClose = L"</EventData>";
        edEnd = ifind(xml, edClose, edStart);
        searchPos = edStart;
    }

    while (true) {
        size_t ds = findElement(xml, L"Data", searchPos);
        if (ds == std::wstring::npos) break;
        // If we're bounded by EventData, stop when we leave the block.
        if (edEnd != std::wstring::npos && ds > edEnd) break;

        std::wstring name = extractAttribute(xml, ds, L"Name");
        if (toLower(name) == toLower(wleaf)) {
            size_t gt = xml.find(L'>', ds);
            if (gt == std::wstring::npos) return L"";
            // Self-closing <Data Name="X"/> -> empty value.
            if (gt > 0 && xml[gt - 1] == L'/') return L"";
            size_t textStart = gt + 1;
            std::wstring close = L"</Data>";
            size_t e = ifind(xml, close, textStart);
            if (e == std::wstring::npos) return L"";
            return xml.substr(textStart, e - textStart);
        }
        searchPos = ds + 1;
    }
    return L"";
}

int extractEventId(const std::wstring& xml) {
    std::wstring v = resolveField(xml, "EventID");
    if (v.empty()) return -1;
    try { return std::stoi(v); }
    catch (...) { return -1; }
}

// Extract the EventRecordID (a monotonically increasing per-channel sequence
// number assigned by Windows). Used as a stable content-based key to track
// which events have already been alerted, independent of buffer index.
long long extractRecordId(const std::wstring& xml) {
    std::wstring v = resolveField(xml, "EventRecordID");
    if (v.empty()) return -1;
    try { return std::stoll(v); }
    catch (...) { return -1; }
}

std::wstring extractChannel(const std::wstring& xml) {
    return resolveField(xml, "Channel");
}

// --- Sigma field-name alias resolution (shared by both paths) ---
// Returns the Windows field name for a Sigma field name, or the input
// unchanged if no alias applies. Case-insensitive on the input. The table is
// keyed lowercase and built once, so a lookup lowercases only the input,
// never the alias keys.
static std::string resolveSigmaAlias(const std::string& field) {
    static const std::unordered_map<std::string, std::string> kSigmaAliases = [] {
        std::unordered_map<std::string, std::string> m;
        const std::pair<const char*, const char*> pairs[] = {
            {"image",            "NewProcessName"},
            {"parentimage",      "ParentProcessName"},
            {"commandline",      "CommandLine"},
            {"parentcommandline","ParentCommandLine"},
            {"processid",        "ProcessId"},
            {"parentprocessid",  "ParentProcessId"},
            {"targetusername",   "TargetUserName"},
            {"targetdomainname", "TargetDomainName"},
            {"logontype",        "LogonType"},
            {"subjectusername",  "SubjectUserName"},
            {"subjectdomainname","SubjectDomainName"},
            {"workstationname",  "WorkstationName"},
            {"ipaddress",        "IpAddress"},
            {"sourceipaddress",  "IpAddress"},
            {"servicename",      "ServiceName"},
            {"servicefilename",  "ImagePath"},
            {"taskname",         "TaskName"},
            {"scriptblocktext",  "ScriptBlockText"},
        };
        for (const auto& p : pairs) m.emplace(p.first, p.second);
        return m;
    }();
    std::string lower = field;
    std::transform(lower.begin(), lower.end(), lower.begin(),
        [](unsigned char c) { return static_cast<char>(::tolower(c)); });
    auto it = kSigmaAliases.find(lower);
    return it == kSigmaAliases.end() ? field : it->second;
}

std::string canonicalFieldKey(const std::string& field) {
    if (field.empty()) return "";
    // Dotted names: use the last segment.
    std::string leaf = field;
    size_t dot = field.rfind('.');
    if (dot != std::string::npos) leaf = field.substr(dot + 1);
    leaf = resolveSigmaAlias(leaf);
    std::transform(leaf.begin(), leaf.end(), leaf.begin(),
        [](unsigned char c) { return static_cast<char>(::tolower(c)); });
    // System field aliases (canonical names, lowercased).
    if (leaf == "event_id") return "eventid";
    if (leaf == "event_record_id") return "eventrecordid";
    if (leaf == "time_created") return "timecreated";
    return leaf;
}

// Same narrowing as toNarrowLower in Rule.cpp: towlower, then truncate to
// char. Kept byte-identical so cached and uncached comparisons treat
// non-ASCII content the same way.
static std::string narrowLower(const std::wstring& s) {
    std::string out;
    out.reserve(s.size());
    for (wchar_t c : s) out += static_cast<char>(::towlower(c));
    return out;
}

const CachedField* lookupField(const BufferedEvent& evt, const std::string& cacheKey) {
    populateFieldCache(evt);
    auto it = evt.fieldCache.find(cacheKey);
    return it == evt.fieldCache.end() ? nullptr : &it->second;
}

const std::string& eventXmlLower(const BufferedEvent& evt) {
    if (!evt.xmlLowerDone) {
        evt.xmlLowerDone = true;
        evt.xmlLower = narrowLower(evt.xml);
    }
    return evt.xmlLower;
}

// --- Field cache: parse all fields from an event's XML once ---
//
// The cache stores lowercased field names → values for every EventData
// <Data Name="..."> entry plus the common System fields. This turns rule
// evaluation from O(rules × fields × XML-size) into O(XML-size) once +
// O(rules × fields) for hash lookups.
void populateFieldCache(const BufferedEvent& evt) {
    if (evt.fieldCacheParsed) return;
    evt.fieldCacheParsed = true;
    const std::wstring& xml = evt.xml;
    if (xml.empty()) return;

    auto store = [&](const char* key, std::wstring v) {
        CachedField cf;
        cf.lower = narrowLower(v);
        cf.value = std::move(v);
        evt.fieldCache[key] = std::move(cf);
    };

    // System fields.
    {
        size_t pos = 0;
        std::wstring v = extractElementText(xml, L"EventID", pos);
        if (!v.empty()) store("eventid", std::move(v));
    }
    {
        size_t pos = 0;
        std::wstring v = extractElementText(xml, L"EventRecordID", pos);
        if (!v.empty()) store("eventrecordid", std::move(v));
    }
    {
        size_t pos = 0;
        std::wstring v = extractElementText(xml, L"Channel", pos);
        if (!v.empty()) store("channel", std::move(v));
    }
    {
        size_t pos = 0;
        std::wstring v = extractElementText(xml, L"Computer", pos);
        if (!v.empty()) store("computer", std::move(v));
    }
    {
        size_t s = findElement(xml, L"Provider", 0);
        if (s != std::wstring::npos) {
            std::wstring v = extractAttribute(xml, s, L"Name");
            if (!v.empty()) store("provider", std::move(v));
        }
    }
    {
        size_t s = findElement(xml, L"TimeCreated", 0);
        if (s != std::wstring::npos) {
            std::wstring v = extractAttribute(xml, s, L"SystemTime");
            if (!v.empty()) store("timecreated", std::move(v));
        }
    }

    // EventData <Data Name="..."> entries, stored by lowercased Name. A
    // field present but empty is stored as an empty string so
    // "exists"/"null" semantics work correctly (absent vs empty).
    forEachEventData(xml, [&](const std::wstring& name, const std::wstring& value) {
        std::string nameNarrow = toNarrow(toLower(name));
        CachedField cf;
        cf.lower = narrowLower(value);
        cf.value = value;
        evt.fieldCache[std::move(nameNarrow)] = std::move(cf);
    });
}

void forEachEventData(const std::wstring& xml,
                      const std::function<void(const std::wstring&, const std::wstring&)>& fn) {
    if (xml.empty()) return;
    // Iterate all <Data> elements within the EventData block.
    size_t edStart = findElement(xml, L"EventData", 0);
    size_t edEnd = std::wstring::npos;
    if (edStart != std::wstring::npos) {
        std::wstring edClose = L"</EventData>";
        edEnd = ifind(xml, edClose, edStart);
    }
    size_t searchPos = (edStart != std::wstring::npos) ? edStart : 0;
    int unnamed = 0;
    while (true) {
        size_t ds = findElement(xml, L"Data", searchPos);
        if (ds == std::wstring::npos) break;
        if (edEnd != std::wstring::npos && ds > edEnd) break;

        std::wstring name = extractAttribute(xml, ds, L"Name");
        size_t gt = xml.find(L'>', ds);
        if (gt == std::wstring::npos) { searchPos = ds + 1; continue; }

        std::wstring value;
        if (gt > 0 && xml[gt - 1] == L'/') {
            // Self-closing <Data Name="X"/> -> empty value.
            value.clear();
        } else {
            size_t textStart = gt + 1;
            std::wstring close = L"</Data>";
            size_t e = ifind(xml, close, textStart);
            if (e != std::wstring::npos) {
                value = xml.substr(textStart, e - textStart);
            }
        }
        if (name.empty()) name = L"param" + std::to_wstring(++unnamed);
        fn(name, value);
        searchPos = ds + 1;
    }
}

// Fast field resolution via the cache. Applies Sigma aliases, then looks up
// the lowercased field name in the cache. Returns empty string if not found
// (same semantics as resolveField).
std::wstring resolveFieldCached(const BufferedEvent& evt, const std::string& field) {
    if (field.empty()) return L"";
    const CachedField* cf = lookupField(evt, canonicalFieldKey(field));
    return cf ? cf->value : L"";
}

// Parse a non-negative decimal from a narrow string without exceptions.
// Returns -1 when empty or not a plain number.
static long long parseDecimal(const std::string& s) {
    if (s.empty() || s.size() > 18) return -1;
    long long v = 0;
    for (char c : s) {
        if (c < '0' || c > '9') return -1;
        v = v * 10 + (c - '0');
    }
    return v;
}

int extractEventIdCached(const BufferedEvent& evt) {
    const CachedField* cf = lookupField(evt, "eventid");
    if (!cf) return -1;
    long long v = parseDecimal(cf->lower);
    return (v < 0 || v > 0x7fffffffLL) ? -1 : static_cast<int>(v);
}

long long extractRecordIdCached(const BufferedEvent& evt) {
    const CachedField* cf = lookupField(evt, "eventrecordid");
    if (!cf) return -1;
    return parseDecimal(cf->lower);
}

std::wstring extractChannelCached(const BufferedEvent& evt) {
    const CachedField* cf = lookupField(evt, "channel");
    return cf ? cf->value : L"";
}

uint64_t eventDedupKey(const BufferedEvent& evt) {
    long long rid = extractRecordIdCached(evt);
    if (rid <= 0) return 0;
    // FNV-1a over the lowercased channel, then mix in the record id. The
    // cache already holds the lowercased (narrowed) channel.
    uint64_t h = 1469598103934665603ULL;
    const CachedField* ch = lookupField(evt, "channel");
    if (ch) {
        for (unsigned char c : ch->lower) {
            h ^= static_cast<uint64_t>(c);
            h *= 1099511628211ULL;
        }
    }
    h ^= static_cast<uint64_t>(rid) + 0x9e3779b97f4a7c15ULL + (h << 6) + (h >> 2);
    // Reserve 0 for "no id" so a (vanishingly unlikely) zero hash can't be
    // mistaken for an event without a record id.
    return h == 0 ? 1 : h;
}

} // namespace elf
