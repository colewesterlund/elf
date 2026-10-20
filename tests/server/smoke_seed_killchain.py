"""Smoke test for the seeded MITRE kill-chain rules (ELF_SEED_TEST_DATA=1).

Run from the repo root with the venv python:
  .venv\\Scripts\\python.exe -I tests/server/smoke_seed_killchain.py

Uses a throwaway SQLite DB (ELF_DB_PATH) so it never touches real data.
Verifies:
  - _seed_test_data creates the uac_bypass_binaries list (4 lists total)
  - the workstations group gets 12 rules (the win_kc_* kill-chain suite)
  - every win_kc_* YAML passes the server's /rules/validate endpoint
  - severities/levels parse correctly (low -> critical spread)
  - every title names its kill-chain step (tactic) in parentheses
  - the KC-09 regex keeps literal \\b / \\s escapes (no YAML mangling)
  - re-running the seed is idempotent (still 12 rules, no duplicates)
"""
import os
import sys
import tempfile

tmp = tempfile.mkdtemp(prefix="elf_smoke_kc_")
os.environ["ELF_DB_PATH"] = os.path.join(tmp, "elf.db")
os.environ["ELF_SEED_TEST_DATA"] = "1"
os.environ["ELF_AGENT_BINARY_DIR"] = tmp
os.environ["ELF_REQUIRE_AGENT_TOKEN"] = "0"

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "server"))

from fastapi.testclient import TestClient  # noqa: E402
import db  # noqa: E402
import main  # noqa: E402

# TestClient(app) does not run startup handlers, so init + seed explicitly.
db.init_db(main.DB_PATH)
main._seed_default_rules()
main._seed_test_data()

client = TestClient(main.app)

r = client.post("/auth/login", json={"username": "admin", "password": "admin"})
assert r.status_code == 200, r.text
print("login ok")

# --- lists: 4 seeded, incl. the new uac_bypass_binaries ----------------------
r = client.get("/lists")
assert r.status_code == 200, r.text
lists = {l["name"] for l in r.json()}
expected_lists = {"sensitive_processes", "living_off_the_land",
                  "suspicious_parents", "uac_bypass_binaries"}
assert expected_lists <= lists, f"missing lists: {expected_lists - lists}"
print(f"lists ok: {sorted(expected_lists)}")

# --- groups: workstations exists ---------------------------------------------
r = client.get("/groups")
assert r.status_code == 200, r.text
ws = next(g for g in r.json() if g["name"] == "workstations")
ws_id = ws["id"]
print(f"workstations group ok: id={ws_id}")

# --- rules: 12 in workstations, all of them win_kc_* --------------------------
r = client.get("/rules", params={"group_id": ws_id})
assert r.status_code == 200, r.text
rules = r.json()
assert len(rules) == 12, f"expected 12 workstations rules, got {len(rules)}"
kc = {rule["rule_id"]: rule for rule in rules if rule["rule_id"].startswith("win_kc_")}
assert len(kc) == 12, f"expected 12 win_kc_* rules, got {len(kc)}"
print(f"rules ok: 12 total, 12 kill-chain: {sorted(kc)}")

# --- every kc rule enabled + correct severity --------------------------------
expected_severity = {
    "win_kc_01_ps_encoded": "high",
    "win_kc_02_service_install": "medium",
    "win_kc_03_uac_bypass": "medium",
    "win_kc_04_log_clear": "high",
    "win_kc_05_lsass_dump": "critical",
    "win_kc_06_password_spray": "high",
    "win_kc_07_port_scan": "medium",
    "win_kc_08_rdp_logon": "medium",
    "win_kc_09_archive_stage": "medium",
    "win_kc_10_ingress_transfer": "high",
    "win_kc_11_stage_exfil": "high",
    "win_kc_12_inhibit_recovery": "critical",
}
for rid, rule in kc.items():
    assert rule["enabled"] is True, f"{rid} should be enabled"
    assert rule["severity"] == expected_severity[rid], \
        f"{rid}: severity {rule['severity']!r} != {expected_severity[rid]!r}"
print("severities ok: low(1) medium(4) high(4) critical(2) spread")

# --- every title names its kill-chain step (tactic) --------------------------
expected_tactic = {
    "win_kc_01_ps_encoded": "Execution",
    "win_kc_02_service_install": "Persistence",
    "win_kc_03_uac_bypass": "Privilege Escalation",
    "win_kc_04_log_clear": "Defense Evasion",
    "win_kc_05_lsass_dump": "Credential Access",
    "win_kc_06_password_spray": "Credential Access",
    "win_kc_07_port_scan": "Discovery",
    "win_kc_08_rdp_logon": "Lateral Movement",
    "win_kc_09_archive_stage": "Collection",
    "win_kc_10_ingress_transfer": "Command and Control",
    "win_kc_11_stage_exfil": "Exfiltration",
    "win_kc_12_inhibit_recovery": "Impact",
}
for rid, rule in kc.items():
    tactic = expected_tactic[rid]
    assert f"({tactic})" in rule["name"], \
        f"{rid}: title {rule['name']!r} does not name its tactic {tactic!r}"
print("tactics ok: all 12 titles name their kill-chain step")

# --- every kc YAML passes the server's own validator -------------------------
for rid in sorted(kc):
    r = client.get(f"/rules/{rid}", params={"group_id": ws_id})
    assert r.status_code == 200, f"{rid}: HTTP {r.status_code} {r.text}"
    yaml_body = r.json()["yaml_body"]
    r = client.post("/rules/validate", json={"yaml_body": yaml_body})
    assert r.status_code == 200, f"{rid}: HTTP {r.status_code} {r.text}"
    body = r.json()
    assert body.get("valid") is True, f"{rid} invalid: {body.get('error')}"
print("validate ok: all 12 win_kc_* rules pass /rules/validate")

# --- KC-09 regex keeps literal backslash escapes -----------------------------
r = client.get("/rules/win_kc_09_archive_stage", params={"group_id": ws_id})
kc09 = r.json()["yaml_body"]
assert "\\b7z\\s+a\\b" in kc09, "KC-09 regex lost its \\b/\\s escapes"
import yaml  # noqa: E402
parsed09 = yaml.safe_load(kc09)
regex = parsed09["detection"]["selection"]["CommandLine|re"]
assert regex == "(Compress-Archive|\\b7z\\s+a\\b|\\brar\\s+a\\b)", repr(regex)
print(f"KC-09 regex ok: {regex!r}")

# --- structural spot checks on parsed YAML -----------------------------------
p = {}
for rid in sorted(kc):
    r = client.get(f"/rules/{rid}", params={"group_id": ws_id})
    p[rid] = yaml.safe_load(r.json()["yaml_body"])
# KC-02 is the only System-channel rule.
assert p["win_kc_02_service_install"]["logsource"]["service"] == "system"
# KC-06 threshold grouped by IpAddress; KC-07 distinct + cidr filter.
assert p["win_kc_06_password_spray"]["elf"]["group_by"] == "IpAddress"
assert p["win_kc_06_password_spray"]["elf"]["threshold"] == 5
assert p["win_kc_07_port_scan"]["elf"]["distinct"] == "DestAddress"
assert "224.0.0.0/4" in p["win_kc_07_port_scan"]["detection"]["filter_nolocal"]["DestAddress|cidr"]
# KC-08 field-value match + machine filter.
assert p["win_kc_08_rdp_logon"]["detection"]["selection_logon"]["LogonType"] == 10
assert p["win_kc_08_rdp_logon"]["detection"]["selection_client"]["EventID"] == 4688
assert "selection_client or selection_logon" in p["win_kc_08_rdp_logon"]["detection"]["condition"]
assert p["win_kc_08_rdp_logon"]["detection"]["filter_machine"]["TargetUserName|endswith"] == "$"
# KC-10 quantifier condition.
assert p["win_kc_10_ingress_transfer"]["detection"]["condition"] == "1 of sel_*"
# KC-11 sequence: two ordered stages within 300s.
seq = p["win_kc_11_stage_exfil"]["elf"]["sequence"]
assert p["win_kc_11_stage_exfil"]["elf"]["timeframe"] == "300s"
assert len(seq) == 2
assert seq[0]["selection"]["CommandLine|contains"] == "Compress-Archive"
assert seq[1]["selection"]["Image|endswith"] == "curl.exe"
# KC-03 references the new list.
assert p["win_kc_03_uac_bypass"]["detection"]["selection"]["Image|endswith"] == "@@uac_bypass_binaries"
# KC-05 |all modifier.
assert p["win_kc_05_lsass_dump"]["detection"]["selection"]["CommandLine|contains|all"] == ["comsvcs", "MiniDump"]
print("structure ok: channels, thresholds, distinct, sequence, quantifier, lists, |all")

# --- idempotency: re-seed changes nothing -------------------------------------
main._seed_test_data()
r = client.get("/rules", params={"group_id": ws_id})
assert len(r.json()) == 12, "re-seed duplicated workstations rules"
r = client.get("/lists")
assert len([l for l in r.json() if l["name"] == "uac_bypass_binaries"]) == 1
print("idempotency ok: re-seed keeps 12 rules / 1 list")

print("\nPASSED: kill-chain seed verified (4 lists, 12+3+3 rules, 12 win_kc_* valid)")

# --- Linux samples: their own group, nothing else in it ---------------------
lin_group = main.db.get_group_by_name(main.LINUX_GROUP_NAME, main.DB_PATH)
assert lin_group, "linux-servers group was not created by the seed"
lin_rules = main.db.list_rules(lin_group["id"], main.DB_PATH)
assert lin_rules and all(r["rule_id"].startswith("lin_") for r in lin_rules), \
    [r["rule_id"] for r in lin_rules]
default_group = main.db.get_group_by_name("default", main.DB_PATH)
default_rules = main.db.list_rules(default_group["id"], main.DB_PATH)
assert default_rules and not any(r["rule_id"].startswith("lin_") for r in default_rules), \
    [r["rule_id"] for r in default_rules]
# Re-seeding is idempotent and moves a sample that sits in the wrong group.
main.db.upsert_rule(rule_id="win_brute_force_logon", group_id=lin_group["id"],
                    yaml_body="title: x\nid: win_brute_force_logon\n", name="x",
                    severity="low", enabled=True, db_path=main.DB_PATH)
main._seed_default_rules()
lin_rules2 = main.db.list_rules(lin_group["id"], main.DB_PATH)
assert [r["rule_id"] for r in lin_rules2] == [r["rule_id"] for r in lin_rules], lin_rules2
assert len(main.db.list_rules(default_group["id"], main.DB_PATH)) == len(default_rules)
# KC-08 raises an alert, not only a forward.
kc08 = [r for r in main.db.list_rules(None, main.DB_PATH) if r["rule_id"] == "win_kc_08_rdp_logon"]
assert kc08 and "- type: alert" in kc08[0]["yaml_body"], kc08
print(f"linux-servers group ok: {len(lin_rules)} Linux rules, default keeps {len(default_rules)} Windows rules, KC-08 alerts")
