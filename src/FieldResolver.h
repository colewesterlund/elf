#pragma once

#include <cstdint>
#include <functional>
#include <string>

namespace elf {

struct BufferedEvent;

// Resolves a logical field name (e.g. "EventID", "CommandLine",
// "ScriptBlockText") against a rendered Windows event XML.
//
// Windows events render to XML with a structure like:
//   <Event>
//     <System>
//       <Provider Name="..."/>
//       <EventID>4688</EventID>
//       <TimeCreated SystemTime="..."/>
//       <Channel>Security</Channel>
//       <Computer>HOST</Computer>
//     </System>
//     <EventData>
//       <Data Name="CommandLine">calc.exe</Data>
//       ...
//     </EventData>
//   </Event>
//
// Field resolution strategy:
//   - "EventID"            -> <System><EventID> text
//   - "Channel"            -> <System><Channel> text
//   - "Computer"           -> <System><Computer> text
//   - "Provider"            -> <System><Provider Name="..."> attribute
//   - "TimeCreated"        -> <System><TimeCreated SystemTime="..."> attribute
//   - any other name       -> <EventData><Data Name="NAME"> text (the common
//                            case for Sysmon/Security event data fields like
//                            CommandLine, ScriptBlockText, Image, etc.)
//
// The resolver is intentionally small and tolerant: it tries the common paths
// and returns the first match. A dotted XPath-like name (e.g.
// "EventData.CommandLine") is also supported by splitting on '.' and using the
// last segment as the Data Name.
std::wstring resolveField(const std::wstring& xml, const std::string& field);

// Fast path: resolve a field against a BufferedEvent's lazily-populated
// field cache. The first call parses ALL EventData + System fields into the
// cache; subsequent calls (for the same event, any field) are O(1) map
// lookups. This is the function rule evaluation should use; it avoids
// re-parsing the XML for every field of every rule.
//
// Sigma field-name aliases (Image→NewProcessName, etc.) are applied here
// before cache lookup, so callers pass the raw Sigma field name.
std::wstring resolveFieldCached(const BufferedEvent& evt, const std::string& field);

// Populate the field cache for an event (parses the XML once). Safe to call
// multiple times; no-ops if already parsed. Exposed so the eval loop can
// warm the cache once per event before iterating rules.
void populateFieldCache(const BufferedEvent& evt);

// The cache key a Sigma field name resolves to: last dotted segment, Sigma
// alias applied (Image → NewProcessName), system-field spelling
// canonicalized (event_id → eventid), lowercased. Computed ONCE per rule
// field at load time (SigmaField::cacheKey); doing it per comparison was
// several allocations per field per rule per event.
std::string canonicalFieldKey(const std::string& field);

// O(1) lookup of a canonical key in the event's cache (populates it on first
// use). Returns nullptr when the event has no such field. No copies.
struct CachedField;
const CachedField* lookupField(const BufferedEvent& evt, const std::string& cacheKey);

// Lowercased narrow copy of the whole event XML (built once per event).
const std::string& eventXmlLower(const BufferedEvent& evt);

// Walk every <Data> element inside <EventData> with its ORIGINAL-case Name
// attribute (the field cache lowercases keys). Unnamed <Data> elements get
// "param1", "param2", ... (the winlogbeat convention; classic PowerShell
// 400/600/800 events use them). Used by the SIEM output formatters, which
// must preserve the vendor field names.
void forEachEventData(const std::wstring& xml,
                      const std::function<void(const std::wstring& name,
                                               const std::wstring& value)>& fn);

// Convenience: extract EventID as an integer. Returns -1 if not found / not
// numeric.
int extractEventId(const std::wstring& xml);

// Fast EventID extraction using the field cache.
int extractEventIdCached(const BufferedEvent& evt);

// Extract the EventRecordID as a 64-bit integer. Returns -1 if not found.
// Used as a stable content-based key for deduplication.
long long extractRecordId(const std::wstring& xml);

// Fast EventRecordID extraction using the field cache.
long long extractRecordIdCached(const BufferedEvent& evt);

// Extract the channel name (e.g. "Security", "Microsoft-Windows-Sysmon/Operational").
std::wstring extractChannel(const std::wstring& xml);

// Fast channel extraction using the field cache.
std::wstring extractChannelCached(const BufferedEvent& evt);

// Stable identity of an event for deduplication: a 64-bit hash of the
// (channel, EventRecordID) pair. EventRecordIDs are only unique WITHIN a
// channel (Security and System both start at 1), so keying dedup sets on
// the bare record id let a rule that spans channels suppress a legitimate
// second event that merely shared an id. Returns 0 when the event has no
// usable EventRecordID; callers must treat 0 as "never deduplicate".
uint64_t eventDedupKey(const BufferedEvent& evt);

} // namespace elf
