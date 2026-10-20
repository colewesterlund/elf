#include "Rule.h"
#include "FieldResolver.h"
#include "Console.h"
#include <regex>
#include <algorithm>
#include <iostream>
#include <cstdlib>
#include <string>
#include <cctype>
#include <cwctype>
#include <cstring>
#include <cstdint>
#include <mutex>
#include <unordered_set>

namespace elf {

// Debug helper: log condition evaluation details when ELF_DEBUG is set.
static bool debugEnabled() {
    static bool v = [] {
        const char* e = std::getenv("ELF_DEBUG");
        return e && (std::string(e) == "1" || std::string(e) == "true");
    }();
    return v;
}

// --- Wide/narrow helpers ---

static std::string toNarrowLower(const std::wstring& s) {
    std::string out;
    out.reserve(s.size());
    for (wchar_t c : s) out += static_cast<char>(::towlower(c));
    return out;
}

static std::string toLower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(),
        [](unsigned char c) { return static_cast<char>(::tolower(c)); });
    return s;
}

// --- CIDR / IP matching (IPv4 + IPv6) ---
//
// Sigma's `field|cidr: <range>` matches when the field's value is an IP
// address that falls inside the given CIDR network (e.g. `172.16.0.0/12`
// matches 172.16.0.0 – 172.31.255.255). We support both IPv4 and IPv6.
// Matching is mixed-family-aware: an IPv4 address is matched against an
// IPv4 CIDR and vice-versa; cross-family comparisons never match (an IPv6
// address is not in an IPv4 /24, etc.).
//
// We parse addresses into 128-bit unsigned integers (16 bytes, network byte
// order) so a single comparison path handles both families. IPv4 addresses
// are stored as IPv4-mapped IPv6 (::ffff:a.b.c.d) so the same containment
// math works, but we track the family separately to avoid a v4 address
// spuriously matching a v6 CIDR (and vice-versa).

namespace {

struct ParsedAddr {
    bool v6 = false;            // true = IPv6, false = IPv4
    uint8_t bytes[16] = {0};     // 128-bit address, network byte order
};

// Parse a dotted-quad IPv4 address. Returns false on malformed input.
bool parseIpv4(const std::string& s, uint8_t out[4]) {
    unsigned int parts[4] = {0};
    int dots = 0;
    size_t i = 0;
    for (int p = 0; p < 4; ++p) {
        if (i >= s.size()) return false;
        unsigned int val = 0;
        int digits = 0;
        while (i < s.size() && s[i] >= '0' && s[i] <= '9') {
            val = val * 10 + (s[i] - '0');
            if (val > 255) return false;
            ++digits;
            ++i;
        }
        if (digits == 0) return false;
        parts[p] = val;
        if (p < 3) {
            if (i >= s.size() || s[i] != '.') return false;
            ++i;
            ++dots;
        }
    }
    if (i != s.size() || dots != 3) return false;
    out[0] = (uint8_t)parts[0]; out[1] = (uint8_t)parts[1];
    out[2] = (uint8_t)parts[2]; out[3] = (uint8_t)parts[3];
    return true;
}

// Parse a colon-separated IPv6 address (with optional :: shorthand and
// optional embedded IPv4 in the last 32 bits). Returns false on malformed
// input. Produces 16 bytes in network byte order.
bool parseIpv6(const std::string& s, uint8_t out[16]) {
    // Split on "::" if present (at most one allowed).
    auto doubleColon = s.find("::");
    std::string head, tail;
    bool hasShorthand = (doubleColon != std::string::npos);
    if (hasShorthand) {
        // Reject multiple "::".
        if (s.find("::", doubleColon + 2) != std::string::npos) return false;
        head = s.substr(0, doubleColon);
        tail = s.substr(doubleColon + 2);
    } else {
        head = s;
    }

    auto splitColons = [](const std::string& str, std::vector<std::string>& parts) {
        if (str.empty()) return;
        std::string cur;
        for (char c : str) {
            if (c == ':') { parts.push_back(cur); cur.clear(); }
            else cur += c;
        }
        parts.push_back(cur);
    };

    std::vector<std::string> headParts, tailParts;
    splitColons(head, headParts);
    splitColons(tail, tailParts);

    // Each part is a 1-4 hex digit group, except the LAST part of the whole
    // address may be a dotted-quad IPv4 (e.g. ::ffff:1.2.3.4).
    auto isHexGroup = [](const std::string& p) {
        if (p.empty() || p.size() > 4) return false;
        for (char c : p) {
            if (!std::isxdigit((unsigned char)c)) return false;
        }
        return true;
    };

    // Count groups (an IPv4 tail counts as 2 groups).
    int headCount = 0, tailCount = 0;
    bool tailIsV4 = false;
    for (const auto& p : headParts) {
        if (!isHexGroup(p)) return false;
        ++headCount;
    }
    if (!tail.empty()) {
        // Check if tail's last segment is a dotted quad.
        auto lastColon = tail.rfind(':');
        std::string lastSeg = (lastColon == std::string::npos) ? tail : tail.substr(lastColon + 1);
        uint8_t v4[4];
        if (parseIpv4(lastSeg, v4)) {
            // The whole tail must be either just the v4 (no colons) or
            // "groups...:v4".
            tailIsV4 = true;
            // Recount tail groups excluding the v4 segment.
            std::string beforeV4 = (lastColon == std::string::npos) ? "" : tail.substr(0, lastColon);
            std::vector<std::string> tp;
            splitColons(beforeV4, tp);
            for (const auto& p : tp) {
                if (!isHexGroup(p)) return false;
                ++tailCount;
            }
            tailCount += 2;  // v4 counts as 2 groups
        } else {
            for (const auto& p : tailParts) {
                if (!isHexGroup(p)) return false;
                ++tailCount;
            }
        }
    }

    int totalGroups = headCount + tailCount;
    if (hasShorthand) {
        // "::" expands to fill up to 8 groups.
        if (totalGroups > 7) return false;
    } else {
        if (totalGroups != 8) return false;
    }

    // Build the 16-byte address.
    std::memset(out, 0, 16);
    int pos = 0;  // byte position
    auto writeGroup = [&](const std::string& g) {
        unsigned int v = (unsigned int)std::stoul(g, nullptr, 16);
        out[pos++] = (uint8_t)(v >> 8);
        out[pos++] = (uint8_t)(v & 0xff);
    };
    for (const auto& p : headParts) writeGroup(p);
    if (hasShorthand) {
        // Skip the zero-filled middle.
        int skipGroups = 8 - totalGroups;
        pos += skipGroups * 2;
    }
    if (!tail.empty()) {
        if (tailIsV4) {
            // Write the hex groups before the v4, then the v4 bytes.
            auto lastColon = tail.rfind(':');
            std::string beforeV4 = (lastColon == std::string::npos) ? "" : tail.substr(0, lastColon);
            std::vector<std::string> tp;
            splitColons(beforeV4, tp);
            for (const auto& p : tp) writeGroup(p);
            std::string v4str = (lastColon == std::string::npos) ? tail : tail.substr(lastColon + 1);
            uint8_t v4[4];
            parseIpv4(v4str, v4);
            out[pos++] = v4[0]; out[pos++] = v4[1];
            out[pos++] = v4[2]; out[pos++] = v4[3];
        } else {
            for (const auto& p : tailParts) writeGroup(p);
        }
    }
    return pos == 16;
}

// Parse a bare IP address (no prefix). Returns false on failure.
bool parseIp(const std::string& s, ParsedAddr& out) {
    uint8_t v4[4];
    if (s.find(':') != std::string::npos) {
        out.v6 = true;
        return parseIpv6(s, out.bytes);
    }
    if (parseIpv4(s, v4)) {
        out.v6 = false;
        // Store as IPv4-mapped IPv6 for uniform math, but keep v6=false so
        // we don't cross-match families.
        std::memset(out.bytes, 0, 16);
        out.bytes[10] = 0xff; out.bytes[11] = 0xff;
        out.bytes[12] = v4[0]; out.bytes[13] = v4[1];
        out.bytes[14] = v4[2]; out.bytes[15] = v4[3];
        return true;
    }
    return false;
}

// Parse a CIDR string "addr/prefix". Returns false on failure. For IPv4 the
// prefix is 0-32; for IPv6 it is 0-128. The network address is masked to
// the prefix length so the stored bytes are the network base.
bool parseCidr(const std::string& s, ParsedAddr& out, int& prefix) {
    auto slash = s.find('/');
    if (slash == std::string::npos) return false;
    std::string addrStr = s.substr(0, slash);
    std::string prefStr = s.substr(slash + 1);
    // A valid prefix is at most 3 digits (0-128). Reject longer strings
    // BEFORE stoi: "10.0.0.0/99999999999" would throw std::out_of_range on
    // the rule-engine thread.
    if (prefStr.empty() || prefStr.size() > 3) return false;
    for (char c : prefStr) {
        if (c < '0' || c > '9') return false;
    }
    prefix = std::stoi(prefStr);
    if (!parseIp(addrStr, out)) return false;
    int maxPrefix = out.v6 ? 128 : 32;
    if (prefix < 0 || prefix > maxPrefix) return false;
    // Mask the address to the network. For IPv4 (stored as IPv4-mapped IPv6
    // in bytes 12-15), the prefix applies to the 32-bit IPv4 portion, so we
    // offset the bit position by 96 (128 - 32). For IPv6 the prefix applies
    // to the full 128 bits directly.
    int bits = out.v6 ? prefix : (prefix + 96);
    for (int i = 0; i < 16; ++i) {
        if (bits >= 8) { /* keep byte */ }
        else if (bits <= 0) { out.bytes[i] = 0; }
        else { out.bytes[i] &= (uint8_t)(0xff << (8 - bits)); }
        bits -= 8;
    }
    return true;
}

// True if `addr` is inside the network described by (net, prefix). Both
// must be the same family. The net address should already be masked.
bool ipInCidr(const ParsedAddr& addr, const ParsedAddr& net, int prefix) {
    if (addr.v6 != net.v6) return false;
    // For IPv4 (stored as IPv4-mapped IPv6 in bytes 12-15), the prefix
    // applies to the 32-bit IPv4 portion, so offset by 96. For IPv6 the
    // prefix applies to the full 128 bits.
    int bits = addr.v6 ? prefix : (prefix + 96);
    for (int i = 0; i < 16; ++i) {
        if (bits >= 8) {
            if (addr.bytes[i] != net.bytes[i]) return false;
        } else if (bits > 0) {
            uint8_t mask = (uint8_t)(0xff << (8 - bits));
            if ((addr.bytes[i] & mask) != (net.bytes[i] & mask)) return false;
            return true;  // remaining bytes don't matter
        } else {
            return true;  // /0 matches everything of the same family
        }
        bits -= 8;
    }
    return true;  // full prefix matched
}

}  // namespace

// Match a field value (as a wide string from the event) against a CIDR
// range string. Returns true if the field is an IP inside the CIDR. Handles
// the Sigma convention that an absent/empty IP or "-" (unknown) never
// matches a CIDR filter (so it doesn't get excluded by a filter).
static bool fieldInCidr(const std::wstring& fieldValue, const std::string& cidr) {
    std::string ip = toNarrowLower(fieldValue);
    // Sigma events often use "-" for "no IP". Don't treat that as an address.
    if (ip.empty() || ip == "-") return false;
    ParsedAddr addr, net;
    int prefix = 0;
    if (!parseIp(ip, addr)) return false;
    if (!parseCidr(cidr, net, prefix)) return false;
    return ipInCidr(addr, net, prefix);
}

// --- Sigma field evaluation ---

// MSVC's std::regex is a backtracking matcher that recurses per character;
// a pathological pattern on a 1 MB ScriptBlockText can exhaust the stack
// (and that is a hard crash, not an exception). Searching only the first
// 64 KB bounds the recursion; Sigma patterns target command lines and
// script fragments, which fit comfortably.
static constexpr size_t kRegexHaystackCap = 64 * 1024;

static bool regexSearchCapped(const std::string& hay, const std::regex& re) {
    const char* b = hay.data();
    const char* e = b + (std::min)(hay.size(), kRegexHaystackCap);
    try {
        return std::regex_search(b, e, re);
    } catch (...) {
        // error_complexity / error_stack: treat as no match.
        return false;
    }
}

// Evaluate one SigmaField against the event. Returns true if it holds.
// Reads the event's field cache directly (one hash lookup, no copies) and
// compares against the values lowercased at load time, so the common ops
// (equals/contains/startswith/endswith) allocate nothing per comparison.
// A field that was never compiled (hand-built Detection) takes the slow
// path: key computed and values lowercased on the spot.
static bool evalSigmaField(const SigmaField& f, const BufferedEvent& evt) {
    const CachedField* cf = f.cacheKey.empty()
        ? lookupField(evt, canonicalFieldKey(f.field))
        : lookupField(evt, f.cacheKey);
    const bool present = cf && !cf->value.empty();

    if (f.op == "exists") return present;
    if (f.op == "null") {
        // Sigma `field: null` matches when the field is absent or empty.
        // This is the negation of `exists` and is used in filter selections
        // to exclude events that lack a field.
        return !present;
    }

    static const std::string kEmpty;
    const std::string& hay = cf ? cf->lower : kEmpty;
    if (debugEnabled()) {
        logInfo("[DEBUG-SIGMA] field='" + f.field + "' op='" + f.op +
                "' all=" + (f.all ? "1" : "0") +
                " nvalues=" + std::to_string(f.values.size()) +
                " resolved='" + hay + "'" + (hay.empty() ? " (EMPTY)" : ""));
    }

    if (f.values.empty()) {
        // No values. Two cases:
        //  - A `@@list` reference that resolved to nothing (missing/empty
        //    list): the field must match NOTHING so a typo in the list name
        //    doesn't silently over-match. `referencedList` distinguishes
        //    this from the "exists" case below.
        //  - A plain field with no value (e.g. `EventID:` with null value):
        //    treat as "exists" (field present) for backward compatibility.
        if (f.referencedList) return false;
        return present;
    }

    const bool compiledValues = f.valuesLower.size() == f.values.size();
    // Compute per-value match results, then combine with OR (default) or AND
    // (when `all` is set).
    auto matchOne = [&](size_t i) -> bool {
        const std::string& needle = compiledValues ? f.valuesLower[i] : toLower(f.values[i]);
        if (f.op == "equals") {
            return hay == needle;
        }
        if (f.op == "contains") {
            return hay.find(needle) != std::string::npos;
        }
        if (f.op == "startswith") {
            return hay.size() >= needle.size() &&
                   hay.compare(0, needle.size(), needle) == 0;
        }
        if (f.op == "endswith") {
            return hay.size() >= needle.size() &&
                   hay.compare(hay.size() - needle.size(), needle.size(), needle) == 0;
        }
        if (f.op == "re") {
            if (f.compiled.size() == f.values.size()) {
                const auto& re = f.compiled[i];
                return re && regexSearchCapped(hay, *re);
            }
            try {   // uncompiled fallback (hand-built rule)
                std::regex re(f.values[i], std::regex::ECMAScript | std::regex::icase);
                return regexSearchCapped(hay, re);
            } catch (...) {
                return false;
            }
        }
        if (f.op == "cidr") {
            return cf && fieldInCidr(cf->value, f.values[i]);
        }
        return false;
    };

    if (f.all) {
        for (size_t i = 0; i < f.values.size(); ++i) {
            if (!matchOne(i)) return false;
        }
        return true;
    }
    for (size_t i = 0; i < f.values.size(); ++i) {
        if (matchOne(i)) return true;
    }
    return false;
}

// Evaluate a Sigma selection against an event. All fields are ANDed.
// A keywords selection matches if any keyword appears in the raw XML.
// When `alternatives` is non-empty (the Sigma "OR of maps" pattern), the
// selection matches if ANY alternative matches; the top-level fields are
// ignored in that case.
bool matchSelection(const SigmaSelection& sel, const BufferedEvent& evt) {
    if (!sel.alternatives.empty()) {
        for (const auto& alt : sel.alternatives) {
            if (matchSelection(alt, evt)) return true;
        }
        return false;
    }
    if (sel.keywords) {
        // One lowercase copy of the XML per event (cached), one lowercase
        // keyword per rule (compiled), not one of each per keyword.
        const std::string& xmlLower = eventXmlLower(evt);
        if (sel.keywordValuesLower.size() == sel.keywordValues.size()) {
            for (const auto& kw : sel.keywordValuesLower) {
                if (xmlLower.find(kw) != std::string::npos) return true;
            }
        } else {
            for (const auto& kw : sel.keywordValues) {
                if (xmlLower.find(toLower(kw)) != std::string::npos) return true;
            }
        }
        return false;
    }
    for (const auto& f : sel.fields) {
        if (!evalSigmaField(f, evt)) return false;
    }
    return true;
}

// --- Compile-time preparation ---

static void compileSelection(SigmaSelection& sel, const std::string& ruleId) {
    for (auto& f : sel.fields) {
        f.cacheKey = canonicalFieldKey(f.field);
        f.valuesLower.clear();
        f.valuesLower.reserve(f.values.size());
        for (const auto& v : f.values) f.valuesLower.push_back(toLower(v));
        f.compiled.clear();
        if (f.op == "re") {
            f.compiled.reserve(f.values.size());
            for (const auto& v : f.values) {
                try {
                    f.compiled.push_back(std::make_shared<const std::regex>(
                        v, std::regex::ECMAScript | std::regex::icase | std::regex::nosubs));
                } catch (const std::regex_error& e) {
                    logError("[Rule] rule '" + ruleId + "' field '" + f.field +
                             "': regex '" + v + "' failed to compile (" + e.what() +
                             "); this value will never match.");
                    f.compiled.push_back(nullptr);
                }
            }
        }
    }
    sel.keywordValuesLower.clear();
    for (const auto& kw : sel.keywordValues) sel.keywordValuesLower.push_back(toLower(kw));
    for (auto& alt : sel.alternatives) compileSelection(alt, ruleId);
}

// --- Sigma condition expression evaluator ---
//
// Grammar (case-insensitive keywords):
//   expr      := term (('and' | 'or') term)*       // right-associative-ish
//   term      := 'not' term | '(' expr ')' | quant | selection
//   quant     := ('1' | 'all') 'of' (glob | 'them')
//   glob      := selection name with optional trailing '*'
//   selection := identifier
//
// Precedence: not > and > or (Sigma spec). We implement a standard
// recursive-descent parser with explicit precedence climbing.

class ConditionParser {
public:
    ConditionParser(const std::string& s,
                    const std::vector<SigmaSelection>& sels,
                    const BufferedEvent& evt)
        : src_(s), p_(0), sels_(sels), evt_(evt) {}

    bool parse() {
        skipWs();
        bool v = parseExpr();
        skipWs();
        ok_ = (p_ == src_.size());
        return v;
    }
    bool ok() const { return ok_; }

private:
    const std::string& src_;
    size_t p_;
    const std::vector<SigmaSelection>& sels_;
    const BufferedEvent& evt_;
    bool ok_ = false;

    void skipWs() {
        while (p_ < src_.size() && std::isspace((unsigned char)src_[p_])) ++p_;
    }

    // Peek next token (case-insensitive compare against `kw`).
    bool peekKw(const std::string& kw) {
        skipWs();
        if (p_ + kw.size() > src_.size()) return false;
        for (size_t i = 0; i < kw.size(); ++i) {
            if (std::tolower((unsigned char)src_[p_ + i]) != kw[i]) return false;
        }
        // Must be followed by a non-identifier char so "and" doesn't match
        // "android".
        char nxt = (p_ + kw.size() < src_.size()) ? src_[p_ + kw.size()] : ' ';
        return !std::isalnum((unsigned char)nxt) && nxt != '_';
    }

    bool consumeKw(const std::string& kw) {
        if (!peekKw(kw)) return false;
        p_ += kw.size();
        return true;
    }

    // Parse a selection name (identifier, may contain dots/underscores/
    // hyphens, and a trailing '*' for glob patterns like 'filter_main_*').
    // Returns the name and advances p_. The '*' is only consumed when it
    // appears at the end of the identifier (so 'selection*' is a glob, but
    // '*foo' is not a valid identifier).
    std::string parseIdent() {
        skipWs();
        size_t start = p_;
        while (p_ < src_.size() &&
               (std::isalnum((unsigned char)src_[p_]) || src_[p_] == '_' ||
                src_[p_] == '-' || src_[p_] == '.')) {
            ++p_;
        }
        // Consume a trailing '*' as part of the identifier (glob pattern).
        if (p_ < src_.size() && src_[p_] == '*') ++p_;
        return src_.substr(start, p_ - start);
    }

    // Find a selection by name.
    const SigmaSelection* findSel(const std::string& name) const {
        for (const auto& s : sels_) {
            if (s.name == name) return &s;
        }
        return nullptr;
    }

    // Evaluate a selection reference (possibly with trailing '*').
    bool evalSelectionRef(const std::string& name) {
        // Trailing '*' means "all selections matching this prefix", but a
        // bare selection name with no '*' is a single selection.
        if (!name.empty() && name.back() == '*') {
            std::string prefix = name.substr(0, name.size() - 1);
            // "selection*" matches any selection whose name starts with prefix.
            // In a non-quantified context this is unusual; Sigma treats it as
            // an implicit "1 of selection*". We'll treat a bare glob as
            // "1 of glob" (matches if any matching selection matches).
            for (const auto& s : sels_) {
                if (s.name.rfind(prefix, 0) == 0) {
                    if (matchSelection(s, evt_)) return true;
                }
            }
            return false;
        }
        const SigmaSelection* s = findSel(name);
        if (!s) return false;
        return matchSelection(*s, evt_);
    }

    // Parse a quantifier: "1 of X" or "all of X" where X is a glob or "them".
    bool parseQuant() {
        // Current position is at the number/word ("1" or "all").
        skipWs();
        bool all = false;
        if (consumeKw("all")) {
            all = true;
        } else if (p_ < src_.size() && src_[p_] == '1' &&
                   (p_ + 1 >= src_.size() ||
                    !std::isalnum((unsigned char)src_[p_ + 1]))) {
            ++p_;  // consume the '1'
        } else {
            ok_ = false;
            return false;
        }
        if (!consumeKw("of")) {
            ok_ = false;
            return false;
        }
        skipWs();
        // "them" = all selections.
        if (consumeKw("them")) {
            // "1 of them" = any; "all of them" = every.
            for (const auto& s : sels_) {
                bool m = matchSelection(s, evt_);
                if (all && !m) return false;
                if (!all && m) return true;
            }
            return all;  // all=true and all matched; or all=false and none matched
        }
        // Otherwise a glob (selection name with optional trailing '*').
        std::string name = parseIdent();
        if (name.empty()) { ok_ = false; return false; }
        std::string prefix = name;
        bool hasGlob = false;
        if (!name.empty() && name.back() == '*') {
            prefix = name.substr(0, name.size() - 1);
            hasGlob = true;
        }
        // Match selections whose name starts with prefix (glob) or equals
        // name (no glob; Sigma still treats "1 of selection" as that single
        // selection).
        int matched = 0, total = 0;
        for (const auto& s : sels_) {
            bool inScope = hasGlob ? (s.name.rfind(prefix, 0) == 0)
                                   : (s.name == name);
            if (!inScope) continue;
            ++total;
            bool m = matchSelection(s, evt_);
            if (m) ++matched;
            if (all && !m) return false;
        }
        if (total == 0) return false;
        return all ? true : (matched >= 1);
    }

    // term := 'not' term | '(' expr ')' | quant | selection
    bool parseTerm() {
        skipWs();
        if (consumeKw("not")) {
            return !parseTerm();
        }
        if (p_ < src_.size() && src_[p_] == '(') {
            ++p_;  // consume '('
            bool v = parseExpr();
            skipWs();
            if (p_ < src_.size() && src_[p_] == ')') ++p_;
            else ok_ = false;
            return v;
        }
        // Quantifier? "1 of" or "all of".
        if (peekKw("all") || (p_ < src_.size() && src_[p_] == '1' &&
                              (p_ + 1 >= src_.size() ||
                               !std::isalnum((unsigned char)src_[p_ + 1])))) {
            return parseQuant();
        }
        // Otherwise a selection reference.
        std::string name = parseIdent();
        if (name.empty()) { ok_ = false; return false; }
        return evalSelectionRef(name);
    }

    // and-term := term ('and' term)*
    bool parseAnd() {
        bool v = parseTerm();
        while (true) {
            skipWs();
            if (consumeKw("and")) {
                bool r = parseTerm();
                v = v && r;
            } else break;
        }
        return v;
    }

    // expr := and-term ('or' and-term)*
    bool parseExpr() {
        bool v = parseAnd();
        while (true) {
            skipWs();
            if (consumeKw("or")) {
                bool r = parseAnd();
                v = v || r;
            } else break;
        }
        return v;
    }
};

bool evalCondition(const std::string& expr,
                   const std::vector<SigmaSelection>& selections,
                   const BufferedEvent& evt) {
    if (expr.empty()) {
        // No condition: match if any selection matches (Sigma default when
        // condition is omitted is unusual; treat as "any").
        for (const auto& s : selections) {
            if (matchSelection(s, evt)) return true;
        }
        return false;
    }
    ConditionParser p(expr, selections, evt);
    bool result = p.parse();
    if (!p.ok()) {
        // A parse failure means the condition is malformed. Falling back to
        // "match if ANY selection matches" would be dangerous: a rule like
        // `selection and not 1 of filter_*` with an unparseable glob would
        // match whenever a *filter* selection matched, firing on exactly
        // the events the rule is meant to exclude. Fail closed (no match)
        // instead and log the error so the
        // rule author can fix the condition. This prevents silent false
        // positives from filter selections being treated as matchers.
        // Logged once per distinct expression: this runs per event per
        // rule, and a bad imported rule otherwise writes a line for every
        // event on the host.
        static std::mutex loggedMutex;
        static std::unordered_set<std::string> logged;
        bool first = false;
        {
            std::lock_guard<std::mutex> lock(loggedMutex);
            first = logged.insert(expr).second;
        }
        if (first) {
            logError("[Rule] condition parse failed: '" + expr +
                     "'; the rule will not match any events until the condition is "
                     "fixed.");
        }
        return false;
    }
    return result;
}

// --- Condition compiler: the same grammar as ConditionParser, but it emits a
// CondNode tree once instead of evaluating the string on every event. ---

namespace {

class ConditionCompiler {
public:
    ConditionCompiler(const std::string& s, const std::vector<SigmaSelection>& sels)
        : src_(s), p_(0), sels_(sels) {}

    std::shared_ptr<const CondNode> compile() {
        skipWs();
        auto n = parseExpr();
        skipWs();
        ok_ = ok_ && (p_ == src_.size());
        return ok_ ? n : nullptr;
    }
    bool ok() const { return ok_; }

private:
    const std::string& src_;
    size_t p_;
    const std::vector<SigmaSelection>& sels_;
    bool ok_ = true;

    using NodePtr = std::shared_ptr<const CondNode>;

    static NodePtr make(CondNode::Kind k) {
        auto n = std::make_shared<CondNode>();
        n->kind = k;
        return n;
    }
    static NodePtr makeSel(size_t idx) {
        auto n = std::make_shared<CondNode>();
        n->kind = CondNode::Kind::Sel;
        n->sels.push_back(idx);
        return n;
    }
    static NodePtr makeScope(CondNode::Kind k, std::vector<size_t> scope) {
        if (scope.empty()) return make(CondNode::Kind::False);
        auto n = std::make_shared<CondNode>();
        n->kind = k;
        n->sels = std::move(scope);
        return n;
    }
    static NodePtr makeBinary(CondNode::Kind k, NodePtr a, NodePtr b) {
        auto n = std::make_shared<CondNode>();
        n->kind = k;
        n->kids.push_back(std::move(a));
        n->kids.push_back(std::move(b));
        return n;
    }

    void skipWs() {
        while (p_ < src_.size() && std::isspace((unsigned char)src_[p_])) ++p_;
    }
    bool peekKw(const std::string& kw) {
        skipWs();
        if (p_ + kw.size() > src_.size()) return false;
        for (size_t i = 0; i < kw.size(); ++i) {
            if (std::tolower((unsigned char)src_[p_ + i]) != kw[i]) return false;
        }
        char nxt = (p_ + kw.size() < src_.size()) ? src_[p_ + kw.size()] : ' ';
        return !std::isalnum((unsigned char)nxt) && nxt != '_';
    }
    bool consumeKw(const std::string& kw) {
        if (!peekKw(kw)) return false;
        p_ += kw.size();
        return true;
    }
    std::string parseIdent() {
        skipWs();
        size_t start = p_;
        while (p_ < src_.size() &&
               (std::isalnum((unsigned char)src_[p_]) || src_[p_] == '_' ||
                src_[p_] == '-' || src_[p_] == '.')) {
            ++p_;
        }
        if (p_ < src_.size() && src_[p_] == '*') ++p_;
        return src_.substr(start, p_ - start);
    }
    // Indices of the selections a (possibly globbed) name refers to.
    std::vector<size_t> scopeOf(const std::string& name) const {
        std::vector<size_t> out;
        if (!name.empty() && name.back() == '*') {
            std::string prefix = name.substr(0, name.size() - 1);
            for (size_t i = 0; i < sels_.size(); ++i) {
                if (sels_[i].name.rfind(prefix, 0) == 0) out.push_back(i);
            }
        } else {
            for (size_t i = 0; i < sels_.size(); ++i) {
                if (sels_[i].name == name) { out.push_back(i); break; }
            }
        }
        return out;
    }
    NodePtr parseQuant() {
        skipWs();
        bool all = false;
        if (consumeKw("all")) {
            all = true;
        } else if (p_ < src_.size() && src_[p_] == '1' &&
                   (p_ + 1 >= src_.size() || !std::isalnum((unsigned char)src_[p_ + 1]))) {
            ++p_;
        } else {
            ok_ = false;
            return make(CondNode::Kind::False);
        }
        if (!consumeKw("of")) { ok_ = false; return make(CondNode::Kind::False); }
        skipWs();
        CondNode::Kind k = all ? CondNode::Kind::AllOf : CondNode::Kind::OneOf;
        if (consumeKw("them")) {
            std::vector<size_t> scope;
            for (size_t i = 0; i < sels_.size(); ++i) scope.push_back(i);
            // "all of them" with zero selections is true in the interpreter
            // (vacuous); keep that by returning AllOf over an empty scope
            // only when `all`; makeScope() turns an empty OneOf into False.
            if (scope.empty() && all) return make(CondNode::Kind::AllOf);
            return makeScope(k, std::move(scope));
        }
        std::string name = parseIdent();
        if (name.empty()) { ok_ = false; return make(CondNode::Kind::False); }
        return makeScope(k, scopeOf(name));   // empty scope → False (total == 0)
    }
    NodePtr parseTerm() {
        skipWs();
        if (consumeKw("not")) {
            auto kid = parseTerm();
            auto n = std::make_shared<CondNode>();
            n->kind = CondNode::Kind::Not;
            n->kids.push_back(std::move(kid));
            return n;
        }
        if (p_ < src_.size() && src_[p_] == '(') {
            ++p_;
            auto v = parseExpr();
            skipWs();
            if (p_ < src_.size() && src_[p_] == ')') ++p_;
            else ok_ = false;
            return v;
        }
        if (peekKw("all") || (p_ < src_.size() && src_[p_] == '1' &&
                              (p_ + 1 >= src_.size() ||
                               !std::isalnum((unsigned char)src_[p_ + 1])))) {
            return parseQuant();
        }
        std::string name = parseIdent();
        if (name.empty()) { ok_ = false; return make(CondNode::Kind::False); }
        if (name.back() == '*') {
            // Bare glob = implicit "1 of glob" (interpreter semantics).
            return makeScope(CondNode::Kind::OneOf, scopeOf(name));
        }
        auto scope = scopeOf(name);
        if (scope.empty()) return make(CondNode::Kind::False);   // unknown selection
        return makeSel(scope[0]);
    }
    NodePtr parseAnd() {
        auto v = parseTerm();
        while (true) {
            skipWs();
            if (consumeKw("and")) {
                v = makeBinary(CondNode::Kind::And, v, parseTerm());
            } else break;
        }
        return v;
    }
    NodePtr parseExpr() {
        auto v = parseAnd();
        while (true) {
            skipWs();
            if (consumeKw("or")) {
                v = makeBinary(CondNode::Kind::Or, v, parseAnd());
            } else break;
        }
        return v;
    }
};

// Evaluate a compiled condition with short-circuiting. `memo` caches each
// selection's result for this event so a selection referenced twice (e.g.
// in `selection and not 1 of filter_*` plus a bare `filter_x`) is matched
// once. -1 = not yet evaluated.
bool evalNode(const CondNode& n, const std::vector<SigmaSelection>& sels,
              const BufferedEvent& evt, int8_t* memo) {
    auto selMatch = [&](size_t i) -> bool {
        if (memo[i] < 0) memo[i] = matchSelection(sels[i], evt) ? 1 : 0;
        return memo[i] == 1;
    };
    switch (n.kind) {
        case CondNode::Kind::And:
            for (const auto& k : n.kids) if (!evalNode(*k, sels, evt, memo)) return false;
            return true;
        case CondNode::Kind::Or:
            for (const auto& k : n.kids) if (evalNode(*k, sels, evt, memo)) return true;
            return false;
        case CondNode::Kind::Not:
            return n.kids.empty() ? false : !evalNode(*n.kids[0], sels, evt, memo);
        case CondNode::Kind::Sel:
            return !n.sels.empty() && selMatch(n.sels[0]);
        case CondNode::Kind::OneOf:
            for (size_t i : n.sels) if (selMatch(i)) return true;
            return false;
        case CondNode::Kind::AllOf:
            for (size_t i : n.sels) if (!selMatch(i)) return false;
            return true;
        case CondNode::Kind::False:
        default:
            return false;
    }
}

std::shared_ptr<const CondNode> compileCondition(const std::string& expr,
                                                 const std::vector<SigmaSelection>& sels,
                                                 const std::string& ruleId,
                                                 bool& failed) {
    failed = false;
    if (expr.empty()) {
        // No condition: "any selection matches" (interpreter semantics).
        std::vector<size_t> scope;
        for (size_t i = 0; i < sels.size(); ++i) scope.push_back(i);
        auto n = std::make_shared<CondNode>();
        n->kind = CondNode::Kind::OneOf;
        n->sels = std::move(scope);
        return n;
    }
    ConditionCompiler c(expr, sels);
    auto ast = c.compile();
    if (!c.ok() || !ast) {
        failed = true;
        logError("[Rule] rule '" + ruleId + "': condition parse failed: '" + expr +
                 "'; the rule will not match any events until the condition is fixed.");
        return nullptr;
    }
    return ast;
}

} // namespace

void compileDetection(Detection& rule) {
    for (auto& sel : rule.selections) compileSelection(sel, rule.id);
    rule.condAst = compileCondition(rule.condition, rule.selections, rule.id,
                                    rule.condParseFailed);
    for (auto& stage : rule.sequence) {
        for (auto& sel : stage.selections) compileSelection(sel, rule.id);
        stage.condAst = compileCondition(stage.condition, stage.selections, rule.id,
                                         stage.condParseFailed);
    }
    rule.compiled = true;
}

// Per-call selection memo without a heap allocation: a rule has a handful
// of selections, so a stack buffer covers it; the vector is the fallback.
static bool evalCompiled(const CondNode& ast, const std::vector<SigmaSelection>& sels,
                         const BufferedEvent& evt) {
    constexpr size_t kStackMemo = 32;
    if (sels.size() <= kStackMemo) {
        int8_t buf[kStackMemo];
        std::fill(buf, buf + sels.size(), int8_t(-1));
        return evalNode(ast, sels, evt, buf);
    }
    std::vector<int8_t> memo(sels.size(), -1);
    return evalNode(ast, sels, evt, memo.data());
}

bool matchEvent(const Detection& rule, const BufferedEvent& evt) {
    if (rule.condAst) return evalCompiled(*rule.condAst, rule.selections, evt);
    if (rule.condParseFailed) return false;   // logged once at compile
    // Hand-built, never-compiled Detection (tests): interpret the string.
    return evalCondition(rule.condition, rule.selections, evt);
}

bool matchStage(const Detection::SequenceStage& stage, const BufferedEvent& evt) {
    if (stage.condAst) return evalCompiled(*stage.condAst, stage.selections, evt);
    if (stage.condParseFailed) return false;
    return evalCondition(stage.condition, stage.selections, evt);
}

} // namespace elf
