"""Smoke test for the payload-light list endpoints: alerts paging + lazy
detail, and forwarded-logs payload pruning.

Run from the repo root with the venv python:
  .venv\\Scripts\\python.exe -I tests/server/smoke_perf_round.py

Uses FastAPI TestClient against a throwaway SQLite DB (ELF_DB_PATH) so it
never touches real data. Verifies:
  - GET /alerts omits payloads by default (fast listing)
  - GET /alerts?include_payload=true attaches payloads (limit <= 200)
  - GET /alerts?include_payload=true&limit=1000 is rejected (400)
  - GET /alerts/{id} returns one alert WITH its payload; 404 for a bad id
  - GET /alerts paging via offset (page 2 differs from page 1)
  - store_logs prunes payloads older than the newest 40 batches while
    keeping event_count + payload_bytes for the timeseries
  - logs_timeseries still reports correct bytes from payload_bytes after
    pruning (never reads the pruned payload)
"""
import os
import sys
import tempfile
import time

tmp = tempfile.mkdtemp(prefix="elf_perf_smoke_")
os.environ["ELF_DB_PATH"] = os.path.join(tmp, "elf.db")
os.environ["ELF_AGENT_BINARY_DIR"] = tmp
os.environ["ELF_REQUIRE_AGENT_TOKEN"] = "0"  # legacy agents allowed (grace)

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "server"))

from fastapi.testclient import TestClient  # noqa: E402
import db  # noqa: E402
import main  # noqa: E402

# TestClient(app) does NOT run startup handlers, so init the DB explicitly.
db.init_db(main.DB_PATH)

client = TestClient(main.app)

# --- login as admin (cookie session) ---
r = client.post("/auth/login", json={"username": "admin", "password": "admin"})
assert r.status_code == 200, r.text
print("login ok:", r.json())

# --- seed 60 alerts directly through db.store_alert (agent ingest path) ---
XML = ("<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>"
       "<System><EventID>4688</EventID><Computer>SMOKE01</Computer></System>"
       "</Event>")
for i in range(60):
    rid = db.store_alert("SMOKE01", {
        "rule_id": f"rule_{i:03d}",
        "message": f"alert {i}",
        "level": "high",
        "event_xml": XML,
    }, main.DB_PATH)
    assert rid == i + 1, rid
print("seeded 60 alerts ok")

# --- GET /alerts omits payloads by default ---
r = client.get("/alerts", params={"limit": 50})
assert r.status_code == 200, r.text
rows = r.json()
assert len(rows) == 50, len(rows)
assert all("payload" not in a or a.get("payload") is None for a in rows), \
    "payload leaked into the default listing"
assert rows[0]["rule_id"] == "rule_059", rows[0]  # newest first
assert rows[0]["severity"] == "high", rows[0]
assert rows[0]["rule_name"] is not None or "rule_name" in rows[0]
print("GET /alerts default omits payloads ok (50 rows, newest first)")

# --- paging: offset 50 returns the 10 oldest, no overlap with page 1 ---
r = client.get("/alerts", params={"limit": 50, "offset": 50})
assert r.status_code == 200, r.text
page2 = r.json()
assert len(page2) == 10, len(page2)
assert page2[0]["rule_id"] == "rule_009", page2[0]
ids1 = {a["id"] for a in rows}
ids2 = {a["id"] for a in page2}
assert not (ids1 & ids2), "pages overlap"
print("GET /alerts offset paging ok (page 2 = 10 older rows, no overlap)")

# --- include_payload=true attaches payloads, but only for small limits ---
r = client.get("/alerts", params={"limit": 5, "include_payload": "true"})
assert r.status_code == 200, r.text
assert all(a.get("payload") for a in r.json()), r.json()
print("GET /alerts include_payload=true ok (5 rows with payloads)")

r = client.get("/alerts", params={"limit": 1000, "include_payload": "true"})
assert r.status_code == 400, r.status_code
print("GET /alerts include_payload=true&limit=1000 rejected (400) ok")

# --- GET /alerts/{id}: one alert WITH payload; 404 for a bad id ---
r = client.get("/alerts/60")
assert r.status_code == 200, r.text
one = r.json()
assert one["id"] == 60
assert one["payload"] and "event_xml" in one["payload"], one
assert one["severity"] == "high"
r = client.get("/alerts/99999")
assert r.status_code == 404, r.status_code
print("GET /alerts/{id} ok (payload included; 404 on bad id)")

# --- logs: seed 50 batches, payloads pruned past the newest 40 ---
for i in range(50):
    payload = {"rule_id": "fwd_rule", "event_count": 2,
               "events": [XML, XML.replace("4688", "4689")]}
    db.store_logs("SMOKE01", payload, main.DB_PATH)
print("seeded 50 log batches ok")

with db.get_conn(main.DB_PATH) as conn:
    kept = conn.execute(
        "SELECT COUNT(*) FROM forwarded_logs WHERE payload != ''"
    ).fetchone()[0]
    total = conn.execute("SELECT COUNT(*) FROM forwarded_logs").fetchone()[0]
assert total == 50, total
assert kept == db.LOGS_PAYLOAD_KEEP, (kept, db.LOGS_PAYLOAD_KEEP)
print(f"store_logs pruned payloads to newest {db.LOGS_PAYLOAD_KEEP} ok "
      f"(kept {kept}/{total})")

# --- GET /logs: metadata only, newest first, default 40 ---
r = client.get("/logs")
assert r.status_code == 200, r.text
logs = r.json()
assert len(logs) == 40, len(logs)
assert all("payload" not in l for l in logs)
assert logs[0]["event_count"] == 2
print("GET /logs default 40 metadata-only rows ok")

# --- timeseries reads payload_bytes, correct after pruning ---
now = time.time()
buckets = db.logs_timeseries(main.DB_PATH, now - 3600, now, 60)
assert buckets, "no buckets"
total_events = sum(b["event_count"] for b in buckets)
total_bytes = sum(b["bytes"] for b in buckets)
assert total_events == 100, total_events          # 50 batches x 2 events
assert total_bytes > 0, total_bytes               # sizes survive pruning
with db.get_conn(main.DB_PATH) as conn:
    raw = conn.execute(
        "SELECT SUM(LENGTH(COALESCE(payload,''))) FROM forwarded_logs"
    ).fetchone()[0]
assert total_bytes > raw, (total_bytes, raw)  # bytes counted, not payload len
print(f"logs_timeseries ok: {total_events} events, {total_bytes} bytes "
      f"from payload_bytes (pruned payload now {raw} chars)")

# --- /metrics/stats endpoint still works end-to-end ---
r = client.get("/metrics/stats", params={"start": now - 3600, "end": now, "bucket": 60})
assert r.status_code == 200, r.text
assert r.json()["total_events"] == 100, r.json()
print("GET /metrics/stats ok after pruning")

print("\nALL PERF-ROUND SMOKE CHECKS PASSED")
