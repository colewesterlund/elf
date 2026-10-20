#pragma once

#include <cstdint>

#include "Rule.h"
#include "BufferedEvent.h"
#include "EventBuffer.h"
#include "Forwarder.h"
#include <vector>
#include <deque>
#include <string>
#include <chrono>
#include <map>
#include <memory>
#include <random>
#include <mutex>
#include <unordered_map>
#include <unordered_set>

namespace elf {

// Per-rule runtime state used by the correlation engine.
//
// Event identity: every dedup container below is keyed by eventDedupKey()
// (FieldResolver.h), a hash of (channel, EventRecordID), NOT by the bare
// EventRecordID. Record IDs are per channel, so two different events on
// Security and System can share an ID; keying by ID alone would make a rule
// that spans channels (catch-all, powershell, process_creation on Security +
// Sysmon) silently suppress the second event. Key 0 means "no record id";
// such events are never deduplicated.
struct RuleState {
    // Threshold rules: sliding window of matching-event timestamps. We also
    // track the set of event keys that contributed a match so a re-evaluated
    // event (e.g. after the buffer shrinks and the cursor resets) is not
    // counted twice toward the threshold. Entries leave thresholdRecordIds
    // when their window entry expires (not only on a fire), so a group that
    // keeps matching without ever firing does not grow it forever.
    std::deque<std::chrono::system_clock::time_point> matchTimes;
    std::unordered_set<uint64_t> thresholdRecordIds;
    // Keys of the events currently in the sliding window, in the same order
    // as matchTimes. On a threshold fire we mark ALL of these as "already
    // fired" so a later re-evaluation (after the buffer shrinks and the
    // cursor resets) does not re-count any of them toward a new window.
    std::deque<uint64_t> matchRecordIds;

    // Threshold rules with `distinct`: unique resolved field values
    // (composite key, same encoding as stateKeyFor) -> last-seen time.
    // Each new matching event insert-or-refreshes its value's timestamp
    // (a repeated value stays in the window while it keeps being seen
    // within the timeframe); entries not refreshed within the timeframe
    // expire. The fire condition counts distinctValues.size() instead of
    // matchTimes.size() when the rule has distinct_by. Cleared on fire
    // (fire-then-reset, same as the event window).
    std::map<std::string, std::chrono::system_clock::time_point> distinctValues;

    // Threshold rules: the events that contributed matches to the current
    // sliding window, kept as fire-time evidence. On a fire these ship in
    // the alert payload (window_events) so the analyst sees every event
    // that filled the window, not just the trigger.
    //  - non-distinct rules: one entry per counted event, parallel to
    //    matchTimes (pushed, expired and cleared together).
    //  - distinct rules: windowEvents stays empty; distinctValueEvents
    //    (below) holds one representative per unique value instead.
    // Bounded: cleared on every fire and drained by window expiry, so the
    // steady-state size is ~one window's worth of matching events.
    std::deque<BufferedEvent> windowEvents;

    // Threshold rules with `distinct`: the representative (most recently
    // seen) event for each unique value, keyed by the same composite key as
    // distinctValues. Insert-or-replace mirrors distinctValues, so a value
    // repeated hundreds of times contributes exactly ONE evidence event,
    // not hundreds; the evidence set is bounded by the number of unique
    // values in the window.
    std::map<std::string, BufferedEvent> distinctValueEvents;

    // Sequence rules: index of the next stage we expect, plus the timestamp
    // of the first stage match (window start).
    size_t nextStage = 0;
    std::chrono::system_clock::time_point windowStart;
    std::vector<BufferedEvent> sequenceEvents;   // events that formed the sequence so far

    // Per-rule map of event keys that have already fired an alert -> the
    // time the entry was recorded. This is a content-based (index-independent)
    // guard against duplicate alerts when the buffer's deque shifts due to
    // cleanup popping front events. It is per-rule (not global) so one rule
    // firing on an event does not suppress a different rule's threshold/
    // sequence count for that same event. Entries older than ALERT_DEDUP_TTL
    // (30 min) are pruned periodically to bound memory on long-running agents.
    std::unordered_map<uint64_t, std::chrono::system_clock::time_point> alertedRecordIds;

    // Per-rule map of event keys that have already been forwarded by a
    // forward_event action -> the time the entry was recorded. forward_event
    // is "continuous" (runs on every matching event), but it must NOT re-run
    // on an event the engine has already forwarded; otherwise a re-evaluated
    // event (e.g. after the buffer shrinks) would be re-forwarded, producing
    // duplicate streams in SIEM/data_lake. This is content-based (index-
    // independent) so it survives deque front pops. Per-rule so one rule's
    // forward does not suppress another rule's forward of the same event
    // (different rules may legitimately forward the same event to different
    // destinations). Pruned alongside alertedRecordIds in the dedup prune loop.
    std::unordered_map<uint64_t, std::chrono::system_clock::time_point> forwardedRecordIds;
};

// An immutable, fully-indexed ruleset. Built once per reload() and shared
// with evaluation passes through a shared_ptr: a pass takes its own
// reference, so a concurrent reload can never free or overwrite rules the
// pass is still reading (raw Detection pointers into a vector that
// reload() reassigns would be a use-after-free, surfacing as sporadic
// crashes on busy hosts). The index pointers point
// into this struct's own `rules` vector, which is never mutated after
// build, so they stay valid for the struct's lifetime.
struct RuleSet {
    std::vector<Detection> rules;   // owns every rule (enabled + disabled)

    // --- Rule index for fast event→rule filtering ---
    // With 1000+ rules, iterating every rule against every event is the
    // dominant cost (each rule does several XML field resolutions). Most
    // Sigma rules declare a `logsource.service` (e.g. "powershell",
    // "security") that maps to a specific Windows channel. By indexing
    // rules by the channels they apply to, we can skip the majority of
    // rules for any given event; a PowerShell event only needs to be
    // checked against PowerShell rules + the catch-all rules, not all 1000.
    //
    // Buckets (a rule appears in exactly one):
    //   catchAll:   no service AND no category; evaluated against every
    //     event (backward-compatible).
    //   channel:    lowercase channel name → rules whose logsource.service
    //     maps to that channel. A rule may appear under several channels
    //     (e.g. "powershell" maps to two).
    //   byCategory: Sigma category → category-only rules. Looked up with
    //     the categories computed ONCE per event (own + parent, e.g. a
    //     Sysmon 13 is both registry_set and registry_event). This is where
    //     most of a SigmaHQ import lives (process_creation & co.); the
    //     previous design scanned all of them linearly for every event and
    //     re-derived the event's category per rule.
    //   unmappedCategory: category-only rules whose category is not in the
    //     engine's table. They can only match events the table does not
    //     classify either, so they are evaluated against those only.
    //   unknownService: service not in the channel map; checked against
    //     every event via serviceMatchesChannel (substring fallback).
    std::vector<const Detection*> catchAll;
    std::unordered_map<std::string, std::vector<const Detection*>> channel;
    std::unordered_map<std::string, std::vector<const Detection*>> byCategory;
    std::vector<const Detection*> unmappedCategory;
    std::vector<const Detection*> unknownService;

    // rule id → rule, for pruning state that belongs to rules no longer
    // loaded and for looking up a rule's window when expiring quiet states.
    std::unordered_map<std::string, const Detection*> byId;

    bool empty() const {
        return catchAll.empty() && channel.empty() && byCategory.empty() &&
               unmappedCategory.empty() && unknownService.empty();
    }
};

// Sigma logsource categories a (channel, EventID) pair belongs to (own +
// parent, e.g. Sysmon 13 → registry_set, registry_event); empty when the
// engine cannot classify it. Shared with the SIEM output formatters so ECS
// event.category/type come from the same table the engine indexes on.
std::vector<std::string> sigmaCategoriesFor(const std::string& channelLower, int eventId);

// The Sigma product this host evaluates ("windows" or "linux"): rules for
// another product are not indexed, and a category rule without a product
// subscribes to this product's channels. The platform decides; the test
// harness overrides it to exercise both behaviors on either platform.
const char* hostSigmaProduct();
void setHostSigmaProductForTests(const std::string& product);

// Counters exposed for tests and the status line.
struct EngineStats {
    size_t states = 0;          // RuleState entries (rules × groups)
    size_t thresholdIds = 0;    // sum of thresholdRecordIds sizes
    size_t alertedIds = 0;      // sum of alertedRecordIds sizes
    size_t forwardBufferCursors = 0;
};

// The rule engine evaluates the loaded ruleset against the event buffer.
// It supports three rule types (simple, threshold, sequence) and dispatches
// the three action types (forward_event, alert, forward_buffer) to a
// Forwarder.
//
// Threading: the engine is driven by a worker thread that periodically scans
// the buffer. To avoid re-counting already-seen events on every pass (which
// would inflate threshold counts and re-fire simple rules), the engine tracks
// how many events it has already evaluated and only processes newly-arrived
// events each pass. Hot reload of the ruleset is supported via reload().
class RuleEngine {
public:
    RuleEngine(EventBuffer& buffer, Forwarder& forwarder);

    // Replace the current ruleset atomically. Safe to call from another
    // thread while evaluateOnce() is running (see RuleSet). Does NOT reset
    // per-rule state or the evaluated cursor; those track events, not
    // rules (see the comment in reload()).
    void reload(const std::vector<Detection>& rules);

    // Derive the per-channel XPath subscription filter from the loaded
    // ruleset. Returns one entry per channel the rules reference, with the
    // union of EventIDs the rules on that channel select. A channel with an
    // empty EventID set means "subscribe to all events on this channel"
    // (happens when a rule on that channel has no explicit EventID, or when
    // a catch-all rule exists). Returns an empty vector when catch-all
    // rules are present (meaning "subscribe to ALL channels with *"); the
    // caller falls back to subscribeAll() in that case. Used by main.cpp to
    // drive XPath subscription filtering on the EventCollector.
    //
    // Channel names are returned lowercase (matching the channel index
    // keys) so the caller can match them against Windows channel paths
    // case-insensitively.
    std::vector<std::pair<std::string, std::vector<int>>> deriveChannelQueries() const;

    // Number of currently-loaded rules (enabled + disabled). Returns 0 when
    // no ruleset is loaded yet (first install, before the first server poll
    // delivers rules). Used by main.cpp to decide whether to subscribe to
    // event channels at all; with no rules there is nothing to evaluate or
    // forward, so subscribing to all channels just wastes RAM buffering
    // events that will never be acted on.
    size_t ruleCount() const;

    // Run one evaluation pass over newly-arrived events. Called periodically
    // by the engine thread. Returns the number of rule fires this pass.
    size_t evaluateOnce();

    // Run the periodic state prune now (normally every 60 s inside
    // evaluateOnce). Exposed for tests.
    void pruneNow();

    // Snapshot of the engine's bookkeeping sizes. Exposed for tests and
    // the status line.
    EngineStats stats() const;

private:
    // Evaluate one rule against one event. Handles simple/threshold/sequence
    // logic and dispatches actions. Returns true if the rule fired (for
    // threshold/sequence) or matched (for simple).
    //
    // Severity-based selection (Simple rules): when multiple Simple rules match
    // the same event, only the highest-severity one should fire its alert. To
    // support this, the Simple branch does NOT call runFireActions itself;
    // it performs forward_event immediately, records per-rule dedup, and
    // instead reports itself via `simpleCandidate` (set to the matching rule
    // pointer). The caller (evaluateOnce) collects all candidates across all
    // rule buckets for the event, picks the highest-severity one (first wins
    // ties), and calls runFireActions on only that one. Threshold/Sequence
    // rules fire independently inside evaluateRule (Option A: they are NOT
    // subject to severity selection) and never set simpleCandidate.
    // `dedupKey` is eventDedupKey(evt), computed once per event by the
    // caller. Rule state is fetched lazily INSIDE (only once the rule has
    // matched, or for sequence rules that need their stage first): with
    // thousands of rules per event, keying and default-constructing a
    // RuleState for every non-matching rule would dominate the per-event cost.
    bool evaluateRule(const Detection& rule, BufferedEvent& evt, uint64_t dedupKey,
                      const Detection** simpleCandidate = nullptr);

    // Run alert + forward_buffer actions on rule fire. `evidenceEvents` is
    // the correlation evidence (sequence chain or threshold window),
    // `alsoMatched` the ids of Simple rules suppressed by severity
    // selection for this event. Returns true if a forward_buffer action ran.
    bool runFireActions(const Detection& rule, const BufferedEvent& trigger,
                        const std::vector<BufferedEvent>& evidenceEvents = {},
                        bool evidenceIsSequence = false,
                        const std::vector<std::string>& alsoMatched = {});

    // Grab a reference to the current ruleset (brief lock, then lock-free).
    std::shared_ptr<const RuleSet> currentRuleSet() const;

    // Walk all RuleStates: drop stale dedup entries, expire quiet threshold
    // windows, and erase states (and forward_buffer cursors) that belong to
    // rules no longer in `rs`.
    void pruneStates(const RuleSet& rs, std::chrono::system_clock::time_point now);

    EventBuffer& m_buffer;
    Forwarder& m_forwarder;
    mutable std::mutex m_rulesMutex;  // guards the m_ruleSet pointer swap only
    std::shared_ptr<const RuleSet> m_ruleSet;
    std::unordered_map<std::string, RuleState> m_states;

    // Per-rule forward_buffer cursor: the absolute buffer index just past
    // the newest event that rule's last forward_buffer fire already sent.
    // A forward_buffer fire does not clear the buffer (other rules must
    // still see every event), so this is what keeps a rule from re-sending
    // the same events when it fires again shortly after. Keyed by rule id;
    // pruned with the ruleset.
    std::unordered_map<std::string, uint64_t> m_forwardBufferCursor;
    // Source of per-fire alert ids (see newAlertId).
    std::mt19937_64 m_alertRng;
    std::string newAlertId();

    // Rules that threw during evaluation and have already been logged, so
    // a rule that throws on every event produces one error line, not one
    // per event per 2 s pass.
    std::unordered_set<std::string> m_loggedThrowingRules;

    // Absolute (pop-stable) cursor: the index, in the cumulative event stream,
    // of the newest event we have already evaluated. Only events beyond this
    // index are processed on each pass, so threshold/sequence state isn't
    // inflated by re-scanning the whole buffer every pass. This is an
    // ABSOLUTE index (offset from the start of the stream), not a live deque
    // index; it is adjusted for events popped from the front of the deque
    // by cleanup/trimTo via EventBuffer::frontPopped(), so a buffer shrink
    // never causes re-evaluation of already-processed events.
    uint64_t m_evaluatedAbsolute = 0;

    // Wall-clock time of the last dedup-set prune pass. Every ~60 s we walk
    // all RuleStates and drop alertedRecordIds entries older than 30 min to
    // bound memory.
    std::chrono::system_clock::time_point m_lastDedupPrune;
};

} // namespace elf
