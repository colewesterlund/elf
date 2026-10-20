#pragma once

#include <string>
#include <chrono>
#include <unordered_map>

namespace elf {

// One cached field value. `lower` is the narrowed, lowercased form that
// every string comparison uses (equals/contains/startswith/endswith/re all
// compare case-insensitively), computed once when the cache is built so the
// hot path does zero per-comparison allocations. The narrowing is the same
// char-truncating towlower that Rule.cpp's toNarrowLower applies, so cached
// and uncached comparisons treat non-ASCII content identically.
struct CachedField {
    std::wstring value;
    std::string  lower;
};

// A single buffered Windows event. The XML is the rendered event XML from
// EvtRender. `receivedAt` is the agent-side arrival time (used for retention
// and correlation windows).
//
// Performance: with 1000+ rules, each event is checked against many rules,
// and each rule resolves several fields from the XML. Re-parsing the XML
// (case-insensitive substring search with full-XML toLower copies) per field
// per rule is the dominant cost. To eliminate it, the event carries a
// lazily-populated field cache: the first call to resolveField (or
// populateFieldCache) parses ALL EventData <Data Name="..."> entries plus
// the common System fields into a flat map, and subsequent lookups are O(1).
// The cache is mutable so it can be populated through a const reference
// (events are often held by const& in the eval loop).
struct BufferedEvent {
    std::chrono::system_clock::time_point receivedAt;
    std::wstring xml;

    // --- Lazily-populated field cache (performance) ---
    // Lowercased field name → value. Populated once on first access by
    // populateFieldCache() / resolveFieldCached(). System fields use their
    // canonical names ("EventID", "Channel", "Computer", "Provider",
    // "TimeCreated", "EventRecordID"); EventData fields use the Data Name
    // attribute value. Sigma aliases (Image→NewProcessName, etc.) are NOT
    // applied here; callers resolve aliases before lookup.
    mutable std::unordered_map<std::string, CachedField> fieldCache;
    mutable bool fieldCacheParsed = false;

    // Lowercased narrow copy of the whole XML, built on first use by a
    // `keywords:` selection (the only matcher that scans the raw XML).
    mutable std::string xmlLower;
    mutable bool xmlLowerDone = false;

    // A copy carrying only what an alert payload needs (time + XML), used
    // for correlation evidence kept in rule state so hundreds of evidence
    // copies don't each drag a full field cache along.
    BufferedEvent stripped() const {
        BufferedEvent e;
        e.receivedAt = receivedAt;
        e.xml = xml;
        return e;
    }
};

} // namespace elf
