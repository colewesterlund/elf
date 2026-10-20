#pragma once

#include "BufferedEvent.h"
#include "Config.h"
#include <nlohmann/json.hpp>
#include <chrono>
#include <string>
#include <utility>
#include <vector>

namespace elf {

// What a destination needs to know about the rule that fired. Built by the
// RuleEngine from the Detection at the three fire sites.
struct RuleMeta {
    std::string id;
    std::string name;
    std::string level;        // Sigma level: critical|high|medium|low|informational
    std::string category;     // Sigma logsource.category
    std::string description;
    std::vector<std::string> tags;   // e.g. attack.execution, attack.t1059.001
};

// One write to a file destination or one POST to an HTTP destination.
struct FormattedPayload {
    std::string body;
    std::string contentType = "application/json";
    std::vector<std::pair<std::string, std::string>> headers;   // e.g. Authorization
};

// Everything a formatted document may reference.
struct FormatContext {
    const Destination* dest = nullptr;
    const RuleMeta* rule = nullptr;
    std::string agentId;
    std::string action;       // forward_event | alert | forward_buffer
    std::string message;      // alert message (the rule description)
    // Id of the rule fire this document belongs to: the same value on the
    // alert and on every event of the batch it forwarded, so an analyst can
    // group an investigation in the SIEM. Empty for forward_event streams.
    std::string alertId;
    const std::vector<BufferedEvent>* evidence = nullptr;   // correlation evidence (alerts)
    bool evidenceIsSequence = false;
    const std::vector<std::string>* alsoMatched = nullptr;
};

// Output formats. `raw` is the default (Windows event XML one per line;
// alerts as a plain-text header + pretty XML) and returns exactly one
// payload. Structured formats return one payload per chunk:
//   json:     ELF's flat document, NDJSON, ≤1,000 docs / 2 MB per POST
//   ecs:      Elastic Common Schema (winlogbeat shape), NDJSON, same chunking
//   hec:      Splunk HEC envelopes concatenated, ≤1,000 per POST,
//               `Authorization: Splunk <token>`
//   gelf:     Graylog GELF 1.1, one message per POST (GELF HTTP inputs
//               accept a single message per request)
//   sentinel: Azure Monitor Logs Ingestion rows as a JSON array, ≤1,000
//               rows / 1 MB per POST (the API limit); auth is applied by the
//               destination worker (OAuth2 client credentials)
std::vector<FormattedPayload> formatEvents(const std::vector<BufferedEvent>& events,
                                           const FormatContext& ctx);
std::vector<FormattedPayload> formatAlert(const BufferedEvent& trigger,
                                          const FormatContext& ctx);

// Document builders (exposed for unit tests).
nlohmann::json buildJsonDoc(const BufferedEvent& evt, const FormatContext& ctx, bool isAlert);
nlohmann::json buildEcsDoc(const BufferedEvent& evt, const FormatContext& ctx, bool isAlert);
nlohmann::json wrapHec(nlohmann::json doc, const BufferedEvent& evt, const FormatContext& ctx,
                       bool isAlert);
nlohmann::json buildGelf(const BufferedEvent& evt, const FormatContext& ctx, bool isAlert);
nlohmann::json buildSentinelRow(const BufferedEvent& evt, const FormatContext& ctx, bool isAlert);

// Raw helpers (the default `raw` payloads).
std::string rawXmlLines(const std::vector<BufferedEvent>& events);
std::string alertToRawPretty(const BufferedEvent& evt, const std::string& ruleId,
                             const std::string& message,
                             const std::vector<BufferedEvent>& evidenceEvents,
                             const std::string& evidenceLabel,
                             const std::vector<std::string>& alsoMatched,
                             const std::string& alertId = std::string());

// ISO-8601 UTC timestamp (seconds) from a system_clock time_point.
std::string isoTime(std::chrono::system_clock::time_point tp);

// The event's own time (System/TimeCreated) as epoch seconds with
// fractional part; falls back to the agent-side arrival time.
double eventEpochSeconds(const BufferedEvent& evt);

// The event's own time as an ISO-8601 string (TimeCreated verbatim, else
// the arrival time).
std::string eventTimestampIso(const BufferedEvent& evt);

} // namespace elf
