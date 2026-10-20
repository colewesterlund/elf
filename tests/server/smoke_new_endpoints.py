"""Smoke test for the settings, metrics-reset, audit-clear, alert query, and
group mirror_logs endpoints.

Run from the repo root with the venv python:
  .venv\\Scripts\\python.exe -I tests/server/smoke_new_endpoints.py

Uses FastAPI TestClient against a throwaway SQLite DB (ELF_DB_PATH) so it
never touches real data. Verifies:
  - GET/PUT /settings (max_logs_text_mb round-trip + RBAC)
  - DELETE /metrics/reset (admin-only; zeroes counters, clears logs)
  - DELETE /audit (admin-only; clears + re-audits)
  - GET /alerts with q/sort params + rule_name JOIN
  - PUT /groups with mirror_logs (round-trip into GET /config)
"""
import os
import sys
import tempfile

tmp = tempfile.mkdtemp(prefix="elf_smoke_")
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

# --- login as admin (cookie-based auth: the session cookie is set on
# login and TestClient persists cookies automatically) ---
r = client.post("/auth/login", json={"username": "admin", "password": "admin"})
assert r.status_code == 200, r.text
assert r.json()["role"] == "admin", r.text
print("login ok:", r.json())

# --- settings round-trip ---
r = client.get("/settings")
assert r.status_code == 200, r.text
assert "max_logs_text_mb" in r.json(), r.text
print("GET /settings ok:", r.json())

r = client.put("/settings", json={"max_logs_text_mb": 42})
assert r.status_code == 200, r.text
r = client.get("/settings")
assert r.json()["max_logs_text_mb"] == 42, r.text
print("PUT /settings ok: max_logs_text_mb=42 round-trips")

# invalid value rejected by pydantic
r = client.put("/settings", json={"max_logs_text_mb": 99999})
assert r.status_code == 422, r.text
print("PUT /settings rejects out-of-range (422) ok")

# --- metrics reset ---
r = client.delete("/metrics/reset")
assert r.status_code == 200, r.text
assert r.json()["ok"] is True and "logs_deleted" in r.json(), r.text
print("DELETE /metrics/reset ok:", r.json())

# --- audit clear ---
r = client.delete("/audit")
assert r.status_code == 200, r.text
assert "deleted" in r.json(), r.text
r = client.get("/audit")
# the audit.clear entry itself must be present after truncation
assert any(a["action"] == "audit.clear" for a in r.json()), r.text
print("DELETE /audit ok; audit.clear re-recorded")

# --- alerts with q/sort + rule_name ---
r = client.get("/alerts")
assert r.status_code == 200, r.text
assert isinstance(r.json(), list)
r = client.get("/alerts", params={"q": "zzz-no-match", "sort": "severity"})
assert r.json() == [], r.text
print("GET /alerts q/sort params ok")

# --- group mirror_logs round-trip ---
r = client.get("/groups")
assert r.status_code == 200, r.text
gid = r.json()[0]["id"]
assert "mirror_logs" in r.json()[0], "mirror_logs missing from group dict"

r = client.put(f"/groups/{gid}", json={"mirror_logs": False})
assert r.status_code == 200, r.text
assert r.json()["mirror_logs"] in (False, 0), r.text
print("PUT /groups mirror_logs=false ok")

# register an agent + fetch its config: mirror_logs must be false.
# Registration mints an enrollment token; the agent must send it as a
# bearer header on /config (the DB stores the hash, the raw value is
# returned only here).
r = client.post("/agents/register",
                json={"agent_id": "smoke-agent", "hostname": "smoke"})
assert r.status_code == 200, r.text
agent_tok = {"Authorization": "Bearer " + r.json()["auth_token"]}
r = client.get("/config/smoke-agent", headers=agent_tok)
assert r.status_code == 200, r.text
assert r.json().get("mirror_logs") is False, r.json().get("mirror_logs")
print("GET /config carries mirror_logs=false ok")

# flip back on
r = client.put(f"/groups/{gid}", json={"mirror_logs": True})
assert r.status_code == 200, r.text
r = client.get("/config/smoke-agent", headers=agent_tok)
assert r.json().get("mirror_logs") is True
print("GET /config carries mirror_logs=true ok")

# --- counter baseline: reset must survive cumulative re-reports ---
# Simulate the agent polling with cumulative counters (as the real agent
# does via GET /config query params), then reset, then poll again with
# even bigger cumulative values. savings_report must show only the
# delta since the reset, NOT the restored pre-reset totals.
import db as _db
assert _db.touch_agent("smoke-agent", events_created=1000, bytes_created=5000,
                       events_forwarded=100, bytes_forwarded=500,
                       db_path=main.DB_PATH) is None
r = client.delete("/metrics/reset")
assert r.status_code == 200, r.text
# Agent keeps counting cumulatively: +200 events / +1000 bytes since reset.
assert _db.touch_agent("smoke-agent", events_created=1200, bytes_created=6000,
                       events_forwarded=150, bytes_forwarded=750,
                       db_path=main.DB_PATH) is None
rep = _db.savings_report(main.DB_PATH)
row = next(x for x in rep if x["agent_id"] == "smoke-agent")
assert row["events_created"] == 200, row
assert row["bytes_created"] == 1000, row
assert row["events_forwarded"] == 50, row
assert row["bytes_forwarded"] == 250, row
print("counter baseline: savings shows post-reset delta after cumulative re-report ok")

# --- RBAC: viewer cannot touch admin endpoints ---
_viewer_pw = "Pw12345678!"  # meets the policy (length, uppercase, digit, symbol)
r = client.post("/users", json={"username": "v1", "password": _viewer_pw, "role": "viewer"})
assert r.status_code in (200, 201), r.text
client.post("/auth/logout")
r = client.post("/auth/login", json={"username": "v1", "password": _viewer_pw})
assert r.status_code == 200, r.text
for method, path in (("delete", "/metrics/reset"), ("delete", "/audit"),
                     ("put", "/settings")):
    r = getattr(client, method)(path)
    assert r.status_code == 403, (method, path, r.status_code)
print("RBAC: viewer blocked from reset/audit/settings ok")

print("\nALL SMOKE CHECKS PASSED")
