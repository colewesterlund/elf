#pragma once

#include "BufferedEvent.h"
#include "Config.h"
#include <string>
#include <vector>
#include <chrono>
#include <memory>
#include <regex>

namespace elf {

// Sigma field modifiers. The default (no modifier) is "equals".
// Supported modifiers (subset of the Sigma spec):
//   equals     - field equals value (case-insensitive)
//   contains   - field contains value (substring, case-insensitive)
//   startswith - field starts with value (case-insensitive)
//   endswith   - field ends with value (case-insensitive)
//   re         - field matches regex (case-insensitive, ECMAScript)
//   exists     - field is present (value is ignored; true if non-empty)
//   cidr       - field is an IP address that falls inside the CIDR range
//                given by value (IPv4 and IPv6 supported). Used by Sigma
//                `field|cidr:` to match IP-in-network.
//   all        - modifier flag: every value in the list must match (AND);
//                default is OR (any value matches)
//
// A field may chain modifiers with '|', e.g. "Image|endswith|all".
// The last token that isn't a known modifier is treated as the operator;
// "all" is a flag that flips the list semantics from OR to AND.
struct SigmaField {
    std::string field;          // logical field name (e.g. "EventID", "Image")
    std::string op;             // equals|contains|startswith|endswith|re|exists|cidr
    std::vector<std::string> values;
    bool all = false;           // |all: AND all values; default OR
    // True if any value in `values` came from a `@@list` reference. Used to
    // distinguish "no values because the referenced list was missing/empty"
    // from "no values because the field is an exists check". When a referenced
    // list resolves to zero values, the field must match NOTHING (not "field
    // exists") so a typo in the list name doesn't silently over-match.
    bool referencedList = false;

    // --- Filled by compileDetection() at load time ---
    // The hot path compares a field against thousands of rules per event;
    // anything that can be computed once per rule must not be computed per
    // comparison. `cacheKey` is the event-cache key the field resolves to
    // (alias + canonicalization + lowercase); `valuesLower` the lowercased
    // values (parallel to `values`); `compiled` the regex objects for
    // op=="re" (parallel to `values`, nullptr where the pattern failed to
    // compile; that value then never matches). Empty when the Detection
    // was hand-built and never compiled; the evaluator falls back to the
    // slow path in that case.
    std::string cacheKey;
    std::vector<std::string> valuesLower;
    std::vector<std::shared_ptr<const std::regex>> compiled;
};

// Compiled form of a Sigma `condition` expression. Built once per rule by
// compileDetection() and evaluated with short-circuiting, so no event
// pays for re-tokenizing the condition string or for evaluating both
// sides of an and/or whose result is already decided.
struct CondNode {
    enum class Kind { And, Or, Not, Sel, OneOf, AllOf, False };
    Kind kind = Kind::False;
    std::vector<std::shared_ptr<const CondNode>> kids;  // And/Or/Not
    std::vector<size_t> sels;   // Sel: the one selection; OneOf/AllOf: the scope
};

// A named Sigma selection. All SigmaFields in a selection are ANDed.
// A `keywords:` block sets `keywords=true` and stores the keyword strings in
// `keywordValues`; it matches if any keyword appears (substring) in the raw
// event XML.
//
// `alternatives` models the Sigma "OR of maps" pattern, where a selection's
// value is a YAML sequence of maps:
//   selection_image:
//     - Image|endswith: '\sqlps.exe'
//     - OriginalFileName: 'sqlps.exe'
// Here the selection matches if ANY of the maps matches (logical OR). Each
// map becomes one SigmaSelection in `alternatives`, each with its own
// `fields` (ANDed within the map). When `alternatives` is non-empty, the
// engine ORs them and ignores the top-level `fields`/`keywords`.
struct SigmaSelection {
    std::string name;
    std::vector<SigmaField> fields;
    bool keywords = false;
    std::vector<std::string> keywordValues;
    std::vector<std::string> keywordValuesLower;   // compiled
    std::vector<SigmaSelection> alternatives;  // OR of sub-selections
};

// An action to take when a rule matches/fires. Exactly three types:
//   forward_event  - forward every matching event (continuous)
//   alert          - on rule fire, forward the single triggering event
//                    annotated as an alert (with `message`)
//   forward_buffer - on rule fire, forward the whole current buffer
struct Action {
    std::string type;            // forward_event | alert | forward_buffer
    std::string destination;     // named target resolved from config.ini [destinations]
    std::string message;         // alert annotation message (alert only)
};

// A Sigma rule loaded from a YAML file. The Sigma `detection` section is
// parsed into `selections` (named maps) plus a `condition` expression string
// that is evaluated at runtime.
//
// Rule type is determined by the presence of ELF-specific extension keys
// (kept under a top-level `elf:` block so the rule stays valid Sigma):
//   simple    - no `elf.threshold` / `elf.sequence` (fires on first match)
//   threshold - `elf.threshold` + `elf.timeframe` (sliding window count)
//   sequence  - `elf.sequence` (ordered stages) + `elf.timeframe`
struct Detection {
    // Sigma top-level metadata.
    std::string title;           // Sigma `title` (also used as display name)
    std::string id;              // Sigma `id` (UUID or short slug)
    std::string status;          // Sigma `status` (stable|test|experimental|deprecated|unsupported)
    std::string description;
    std::string level;           // Sigma `level` (critical|high|medium|low|informational)
    std::vector<std::string> tags;
    std::vector<std::string> references;
    std::vector<std::string> falsepositives;

    // Derived convenience fields (kept for compatibility with existing
    // engine/UI code).
    std::string name;            // == title
    std::string severity;        // == level
    bool enabled = true;         // false if status is deprecated/unsupported
    std::vector<std::string> platforms;     // from logsource.product
    std::vector<std::string> log_sources;   // from logsource.service (channel names)
    std::string logsource_category;         // from logsource.category (e.g. process_creation)
    std::string logsource_product;          // from logsource.product (first value, lowercase)

    // Sigma detection section.
    std::vector<SigmaSelection> selections;
    std::string condition;        // raw condition expression string
    // Compiled condition (compileDetection). condParseFailed=true means the
    // condition could not be parsed: the rule fails closed (never matches)
    // and the error was logged once at load.
    std::shared_ptr<const CondNode> condAst;
    bool condParseFailed = false;
    bool compiled = false;        // compileDetection() has run

    // ELF extension: correlation layer.
    enum class Type { Simple, Threshold, Sequence };
    Type type = Type::Simple;
    int threshold = 0;            // for threshold rules
    int time_window_seconds = 0;  // for threshold + sequence (Sigma `timeframe`)
    // Threshold rules: scope the sliding-window count per group. MANDATORY
    // for threshold rules; the server rejects and the loader refuses to load
    // a threshold rule without group_by. Each entry is a field name resolved
    // against the event via the same FieldResolver used by `detection`
    // (e.g. "TargetUserName", "Computer"). Multiple fields form a composite
    // group key (per (user, host) pair). An unresolved field maps to a
    // "<missing>" sentinel so the event still counts into a bucket rather
    // than being dropped. Currently only honored by threshold rules;
    // sequence-rule grouping is future work.
    std::vector<std::string> group_by;
    // Threshold rules (optional): count unique resolved values of these
    // field(s) within the window instead of raw matching events. Use when N
    // repeats of ONE value must not fire (e.g. a ping-sweep rule: threshold 5
    // on distinct DestAddress fires on 5 unique destination IPs; `ping -n 10
    // <onehost>` is 10 events but 1 unique value and must NOT fire). Each
    // new matching event insert-or-refreshes its value's last-seen timestamp
    // (sliding-window semantics); values not seen within the timeframe
    // expire. Multiple fields form a composite distinct key. An unresolved
    // field maps to a "<missing>" sentinel (one shared value), mirroring
    // group_by. Empty (default) = classic per-event counting.
    std::vector<std::string> distinct_by;
    // Threshold rules: comparison operator for the fire condition. Empty
    // (default) = "gte" (count >= threshold). Allowed: "gte", "gt", "eq".
    // "lt"/"lte"/"neq" are not supported; under the fire-then-reset model
    // they would fire on every matching event after a reset (count resets to
    // 1, which is < N), which is useless; the meaningful version needs
    // window-expiry evaluation the arrival-driven engine doesn't have.
    std::string threshold_op;
    // For sequence rules: each stage is itself a mini Sigma detection (its own
    // selections + condition). We reuse the same structures.
    struct SequenceStage {
        std::vector<SigmaSelection> selections;
        std::string condition;
        std::shared_ptr<const CondNode> condAst;   // compiled
        bool condParseFailed = false;
    };
    std::vector<SequenceStage> sequence;

    // ELF extension: actions.
    std::vector<Action> actions;
};

// Precompute everything the matcher needs per rule: field cache keys,
// lowercased values, regex objects, and the condition AST (top-level and
// per sequence stage). Idempotent. Logs each problem (bad regex,
// unparseable condition) ONCE with the rule id. Called by the YAML loader
// and, as a safety net, by RuleEngine::reload for hand-built rules.
void compileDetection(Detection& rule);

// Evaluate a single Sigma selection against an event. Returns true if the
// event matches the selection (all fields ANDed; list values ORed unless
// `all` is set; keywords match against raw XML).
bool matchSelection(const SigmaSelection& sel, const BufferedEvent& evt);

// Evaluate a Sigma `condition` expression against an event. `selections` is
// the rule's named selections; the expression references them by name (with
// and/or/not/parens, `1 of`/`all of` with `*` glob or `them`). Returns true if
// the condition holds for this event.
bool evalCondition(const std::string& expr,
                   const std::vector<SigmaSelection>& selections,
                   const BufferedEvent& evt);

// Convenience: evaluate the whole Sigma detection (selections + condition)
// for an event. Returns true if the rule's detection matches.
bool matchEvent(const Detection& rule, const BufferedEvent& evt);

// Evaluate a sequence stage's detection against an event.
bool matchStage(const Detection::SequenceStage& stage, const BufferedEvent& evt);

} // namespace elf
