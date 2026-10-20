"""Smoke test for the agent<->server wire format: ruleset hashing, ingest
limits, alert-report fields, and bulk-import atomicity.

Run from the repo root with the venv python:
  .venv\\Scripts\\python.exe -I tests/server/smoke_wire_format.py

Uses FastAPI TestClient against a throwaway SQLite DB (ELF_DB_PATH) so it
never touches real data. Verifies:
  - ruleset_hash on GET /config: present, stable, content-derived
  - ?known_hash= omits rules/lists and sets ruleset_unchanged
  - POST /logs accepts 10,000 events and rejects 10,001 (422)
  - AlertReport.also_matched / *_truncated are persisted (not dropped)
  - a 3,000-rule zip import commits in ONE transaction (timed) through both
    the dry_run=false path and the preview -> commit_token path
  - a concurrent GET /config during the commit sees the old or the new
    complete ruleset, never a partial one
  - the database runs in WAL mode
  - validator alignment: no actions / zero timeframe / '| count()' / bad
    regex are rejected
"""
import io
import json
import os
import sys
import tempfile
import threading
import time
import uuid
import zipfile

tmp = tempfile.mkdtemp(prefix="elf_smoke_wire_")
os.environ["ELF_DB_PATH"] = os.path.join(tmp, "elf.db")
os.environ["ELF_AGENT_BINARY_DIR"] = tmp
os.environ["ELF_REQUIRE_AGENT_TOKEN"] = "0"

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "server"))

from fastapi.testclient import TestClient  # noqa: E402
import db  # noqa: E402
import main  # noqa: E402

db.init_db(main.DB_PATH)
main._seed_default_rules()
client = TestClient(main.app)

r = client.post("/auth/login", json={"username": "admin", "password": "admin"})
assert r.status_code == 200, r.text
print("login ok")

# --- WAL ---
with db.get_conn(main.DB_PATH) as c:
    mode = c.execute("PRAGMA journal_mode").fetchone()[0]
assert mode.lower() == "wal", mode
print("journal_mode=wal ok")

# --- register an agent in the default group ---
r = client.post("/agents/register", json={"agent_id": "wire-agent", "hostname": "wire"})
assert r.status_code == 200, r.text
tok = {"Authorization": "Bearer " + r.json()["auth_token"]}
gid = 1

# --- ruleset_hash: present + stable + content derived ---
r = client.get("/config/wire-agent", headers=tok)
assert r.status_code == 200, r.text
cfg1 = r.json()
h1 = cfg1["ruleset_hash"]
assert isinstance(h1, str) and len(h1) == 64, h1
assert "rules" in cfg1 and "lists" in cfg1
n_rules = len(cfg1["rules"])
r = client.get("/config/wire-agent", headers=tok)
assert r.json()["ruleset_hash"] == h1
print(f"ruleset_hash stable ok ({n_rules} rules, {h1[:12]}...)")

# known_hash -> short response
r = client.get("/config/wire-agent", headers=tok, params={"known_hash": h1})
assert r.status_code == 200, r.text
short = r.json()
assert short.get("ruleset_unchanged") is True, short
assert "rules" not in short and "lists" not in short, short.keys()
assert short["ruleset_hash"] == h1
assert "destinations" in short and "retention_seconds" in short
print("known_hash -> ruleset_unchanged (no rules/lists) ok")

# stale known_hash -> full payload
r = client.get("/config/wire-agent", headers=tok, params={"known_hash": "0" * 64})
assert "rules" in r.json() and "ruleset_unchanged" not in r.json()
print("stale known_hash -> full payload ok")

# a new rule changes the hash; re-saving the same yaml does not
RULE_YAML = (
    "title: Wire Smoke\nid: wire_smoke_1\nstatus: test\nlevel: low\n"
    "logsource:\n  product: windows\n  service: security\n"
    "detection:\n  selection:\n    EventID: 4688\n  condition: selection\n"
    "elf:\n  actions:\n    - type: alert\n      destination: alerts\n"
)
r = client.post("/rules", params={"group_id": gid},
                json={"rule_id": "wire_smoke_1", "name": "Wire Smoke", "yaml_body": RULE_YAML})
assert r.status_code == 200, r.text
h2 = client.get("/config/wire-agent", headers=tok).json()["ruleset_hash"]
assert h2 != h1
r = client.put("/rules/wire_smoke_1", params={"group_id": gid},
               json={"rule_id": "wire_smoke_1", "name": "Wire Smoke", "yaml_body": RULE_YAML})
assert r.status_code == 200, r.text
assert client.get("/config/wire-agent", headers=tok).json()["ruleset_hash"] == h2
# disabling the rule removes it from the agent payload and changes the hash
r = client.put("/rules/wire_smoke_1", params={"group_id": gid},
               json={"rule_id": "wire_smoke_1", "name": "Wire Smoke",
                     "yaml_body": RULE_YAML, "enabled": False})
assert r.status_code == 200, r.text
cfg3 = client.get("/config/wire-agent", headers=tok).json()
# Omitting the disabled rule yields exactly the pre-rule set again, so the
# hash returns to h1; it is content-derived, not history-derived.
assert cfg3["ruleset_hash"] == h1 and cfg3["ruleset_hash"] != h2
assert all(x["rule_id"] != "wire_smoke_1" for x in cfg3["rules"])
print("hash content-derived; disabled rule omitted ok")

# a list change invalidates every group's hash
r = client.post("/lists", json={"name": "wire_list", "content": "a\nb\n"})
assert r.status_code == 200, r.text
assert client.get("/config/wire-agent", headers=tok).json()["ruleset_hash"] != cfg3["ruleset_hash"]
print("list change changes hash ok")

# --- /logs limits ---
xml = "<Event><System><EventID>4688</EventID><EventRecordID>1</EventRecordID>" \
      "<Channel>Security</Channel></System></Event>"
r = client.post("/logs", params={"agent_id": "wire-agent"}, headers=tok,
                json={"rule_id": "x", "event_count": 10000, "events": [xml] * 10000})
assert r.status_code == 200, r.text
r = client.post("/logs", params={"agent_id": "wire-agent"}, headers=tok,
                json={"rule_id": "x", "event_count": 10001, "events": [xml] * 10001})
assert r.status_code == 422, r.status_code
print("/logs 10000 -> 200, 10001 -> 422 ok")

# --- AlertReport new fields persisted ---
r = client.post("/alerts", params={"agent_id": "wire-agent"}, headers=tok,
                json={"rule_id": "r1", "message": "m", "level": "high", "event_xml": xml,
                      "window_events": [xml, xml], "window_events_truncated": 7,
                      "also_matched": ["r2", "r3"]})
assert r.status_code == 200, r.text
aid = r.json()["id"]
r = client.get(f"/alerts/{aid}")
assert r.status_code == 200, r.text
p = json.loads(r.json()["payload"])
assert p["also_matched"] == ["r2", "r3"], p
assert p["window_events_truncated"] == 7, p
# old agents (no new fields) still accepted
r = client.post("/alerts", params={"agent_id": "wire-agent"}, headers=tok,
                json={"rule_id": "r1", "message": "m", "level": "low", "event_xml": xml})
assert r.status_code == 200, r.text
print("AlertReport.also_matched / window_events_truncated persisted ok")

# --- validator alignment ---
def validate(y):
    return client.post("/rules/validate", json={"yaml_body": y}).json()

base = ("title: V\nid: v1\nstatus: test\nlevel: low\n"
        "logsource:\n  product: windows\n  service: security\n")
assert not validate(base + "detection:\n  selection:\n    EventID: 4688\n  condition: selection\n")["valid"], "no actions must be rejected"
assert not validate(base + "detection:\n  selection:\n    EventID: 4688\n  condition: selection | count() > 5\n"
                    "elf:\n  actions:\n    - type: alert\n      destination: alerts\n")["valid"]
assert not validate(base + "detection:\n  selection:\n    EventID: 4625\n  condition: selection\n"
                    "elf:\n  threshold: 3\n  group_by: TargetUserName\n"
                    "  actions:\n    - type: alert\n      destination: alerts\n")["valid"], "threshold without timeframe"
assert validate(base + "detection:\n  selection:\n    EventID: 4625\n  condition: selection\n"
                "elf:\n  threshold: 3\n  timeframe: 5m\n  group_by: TargetUserName\n"
                "  actions:\n    - type: alert\n      destination: alerts\n")["valid"]
assert not validate(base + "detection:\n  selection:\n    CommandLine|re: '(unclosed'\n  condition: selection\n"
                    "elf:\n  actions:\n    - type: alert\n      destination: alerts\n")["valid"]
assert validate(base + "detection:\n  selection:\n    CommandLine|re: '(a|b)\\\\s+c'\n  condition: selection\n"
                "elf:\n  actions:\n    - type: alert\n      destination: alerts\n")["valid"]
print("validator: no-actions / aggregation / timeframe / bad-regex rejected ok")

# --- 3,000-rule zip import: single transaction, timed ---
def make_zip(n, prefix):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for i in range(n):
            doc = (
                f"title: {prefix} rule {i}\n"
                f"id: {uuid.uuid4()}\n"
                "status: test\nlevel: medium\n"
                "logsource:\n  product: windows\n  service: security\n"
                "detection:\n  selection:\n    EventID: 4688\n"
                f"    CommandLine|contains: marker_{prefix}_{i}\n"
                "  condition: selection\n"
            )
            zf.writestr(f"rules/windows/process_creation/{prefix}_{i}.yml", doc)
    return buf.getvalue()

r = client.post("/groups", json={"name": "wire-import", "description": ""})
assert r.status_code == 200, r.text
gid2 = r.json()["id"]
r = client.put("/agents/wire-agent/group", json={"group_id": gid2})
assert r.status_code == 200, r.text
smap = json.dumps({lvl: [{"type": "alert", "destination": "alerts"}]
                   for lvl in ("critical", "high", "medium", "low", "informational")})
params = {"group_id": gid2, "dry_run": "false", "overwrite": "true",
          "min_severity": "low", "logsource_filter": "windows", "severity_map": smap}
zdata = make_zip(3000, "a")
t0 = time.perf_counter()
r = client.post("/rules/import", params=params,
                files={"file": ("rules.zip", zdata, "application/zip")})
dt = time.perf_counter() - t0
assert r.status_code == 200, r.text
res = r.json()
assert res["written"] == 3000, res
print(f"zip import of 3000 rules: {dt:.2f}s (written={res['written']}, invalid={res.get('skipped_invalid')})")
assert dt < 60, f"import too slow: {dt:.1f}s"
cfg_full = client.get("/config/wire-agent", headers=tok).json()
assert len(cfg_full["rules"]) == 3000, len(cfg_full["rules"])

# --- duplicate rule ids are counted once ---
# The SigmaHQ packages nest (core ⊂ core+ ⊂ core++ ⊂ all), so a multi-package
# import (or a zip with the same rule under two paths) carries the same id
# several times. The plan must count each unique rule once and report the
# rest as skipped_duplicate, not inflate the preview.
def make_dup_zip(n, copies):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for i in range(n):
            rid = uuid.uuid4()
            doc = (f"title: dup rule {i}\nid: {rid}\nstatus: test\nlevel: high\n"
                   "logsource:\n  product: windows\n  service: security\n"
                   "detection:\n  selection:\n    EventID: 4688\n"
                   f"    CommandLine|contains: dup_{i}\n  condition: selection\n")
            for c in range(copies):
                zf.writestr(f"pkg{c}/rules/windows/dup_{i}.yml", doc)
    return buf.getvalue()

r = client.post("/rules/import", params=dict(params, dry_run="true"),
                files={"file": ("dups.zip", make_dup_zip(40, 4), "application/zip")})
assert r.status_code == 200, r.text
res = r.json()
assert res["planned"] == 40, res
assert res["skipped_duplicate"] == 120, res
print("duplicate rule ids across packages counted once ok (40 planned, 120 duplicates)")

# preview -> commit_token path
params2 = dict(params, dry_run="true")
r = client.post("/rules/import", params=params2,
                files={"file": ("rules2.zip", make_zip(50, "b"), "application/zip")})
assert r.status_code == 200, r.text
token = r.json().get("commit_token")
assert token, r.json()
t0 = time.perf_counter()
r = client.post("/rules/import/commit", json={"commit_token": token})
assert r.status_code == 200 and r.json()["written"] == 50, r.text
print(f"commit_token path ok ({time.perf_counter() - t0:.2f}s, 50 rules)")
assert len(client.get("/config/wire-agent", headers=tok).json()["rules"]) == 3050

# --- concurrent poll during a bulk commit sees old or new count only ---
observed = set()
stop = threading.Event()

def poller():
    while not stop.is_set():
        rr = client.get("/config/wire-agent", headers=tok)
        if rr.status_code == 200 and "rules" in rr.json():
            observed.add(len(rr.json()["rules"]))

t = threading.Thread(target=poller)
t.start()
rows = [{"rule_id": f"bulk_{i}", "yaml_body": RULE_YAML.replace("wire_smoke_1", f"bulk_{i}"),
         "name": f"bulk {i}", "description": "", "severity": "low", "enabled": True}
        for i in range(2000)]
db.upsert_rules_bulk(rows, gid2, main.DB_PATH)
main._invalidate_config_cache(gid2)
time.sleep(0.3)
stop.set()
t.join()
assert observed <= {3050, 5050}, observed
print(f"concurrent GET /config during bulk commit observed counts {sorted(observed)} ok")

# cached unchanged-hash poll is fast
hh = client.get("/config/wire-agent", headers=tok).json()["ruleset_hash"]
t0 = time.perf_counter()
for _ in range(20):
    client.get("/config/wire-agent", headers=tok, params={"known_hash": hh})
per = (time.perf_counter() - t0) / 20
print(f"unchanged-hash poll: {per * 1000:.1f} ms avg")
assert per < 0.25, per

# --- alert_id joins an alert to the batch of the same rule fire ---
fire = "0123456789abcdef"
r = client.post("/alerts?agent_id=wire-agent", headers=tok, json={
    "rule_id": "win_wire_fire", "message": "fire", "level": "high",
    "event_xml": "<Event><System><EventID>4688</EventID><EventRecordID>77</EventRecordID>"
                 "<Channel>Security</Channel><Computer>H</Computer></System></Event>",
    "alert_id": fire})
assert r.status_code == 200, r.text
aid = r.json()["id"]
detail = client.get(f"/alerts/{aid}").json()
assert json.loads(detail["payload"])["alert_id"] == fire, detail
r = client.post("/logs?agent_id=wire-agent", headers=tok, json={
    "rule_id": "win_wire_fire", "event_count": 1, "alert_id": fire,
    "events": ["<Event><System><EventID>4688</EventID><EventRecordID>78</EventRecordID>"
               "<Channel>Security</Channel><Computer>H</Computer></System></Event>"]})
assert r.status_code == 200, r.text
rows = client.get("/logs").json()
assert any(l.get("alert_id") == fire and l["rule_id"] == "win_wire_fire" for l in rows), rows[:3]
print("alert_id stored on the alert payload and the log batch ok")

print("\nALL WIRE-FORMAT SMOKE CHECKS PASSED")
