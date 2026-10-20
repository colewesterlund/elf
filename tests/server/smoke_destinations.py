"""Smoke test for destination URL validation (SIEM output formats).

Run from the repo root with the venv python:
  .venv\\Scripts\\python.exe -I tests/server/smoke_destinations.py

Uses FastAPI TestClient against a throwaway SQLite DB (ELF_DB_PATH) so it
never touches real data. Verifies:
  - the documented Splunk / Graylog / Sentinel / ECS-file URLs are accepted
    and come back byte-for-byte through GET /config/{agent_id}
  - bad format, hec without token, secret over plain http, sentinel over
    http / missing tenant, bad names, duplicates and '..' paths are rejected
    with a 422 whose message names the destination
"""
import os
import sys
import tempfile

tmp = tempfile.mkdtemp(prefix="elf_smoke_")
os.environ["ELF_DB_PATH"] = os.path.join(tmp, "elf.db")
os.environ["ELF_AGENT_BINARY_DIR"] = tmp
os.environ["ELF_REQUIRE_AGENT_TOKEN"] = "0"

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "..", "..", "server"))

from fastapi.testclient import TestClient  # noqa: E402
import db  # noqa: E402
import main  # noqa: E402
from models import validate_destination  # noqa: E402

db.init_db(main.DB_PATH)
client = TestClient(main.app)

r = client.post("/auth/login", json={"username": "admin", "password": "admin"})
assert r.status_code == 200, r.text

r = client.post("/groups", json={"name": "siemtest", "description": ""})
assert r.status_code == 200, r.text
gid = r.json()["id"]

GOOD = {
    "splunk": "https://splunk.example.com:8088/services/collector/event"
              "?format=hec&token=0123-abcd&index=elf&sourcetype=elf:alert",
    "graylog": "http://graylog.example.com:12201/gelf?format=gelf",
    "sentinel": "https://elf-dce.eastus-1.ingest.monitor.azure.com/"
                "dataCollectionRules/dcr-0123/streams/Custom-ELF_CL"
                "?api-version=2023-01-01&format=sentinel&tenant=t-1"
                "&client=c-1&secret=env:ELF_SENTINEL_SECRET",
    "ecsfile": "file://output/ecs.ndjson?format=ecs",
    "lab_hec": "http://127.0.0.1:8088/services/collector/event"
               "?format=hec&token=lab&insecure=1",
    "raw": "file://output/siem.jsonl",
    "abs": "file:///C:/logs/siem.jsonl?format=json",
}

r = client.put(f"/groups/{gid}", json={
    "destinations": [{"name": k, "url": v} for k, v in GOOD.items()]})
assert r.status_code == 200, r.text
print("PUT /groups accepts the documented SIEM URLs ok")

# Round-trip through the agent config endpoint (what the agent parses).
r = client.post("/agents/register", json={
    "agent_id": "smoke-dest-agent", "hostname": "h", "group_id": gid})
assert r.status_code == 200, r.text
agent_tok = {"Authorization": "Bearer " + r.json()["auth_token"]}
r = client.get("/config/smoke-dest-agent", headers=agent_tok)
assert r.status_code == 200, r.text
dests = r.json()["destinations"]
for k, v in GOOD.items():
    assert dests.get(k) == v, (k, dests.get(k))
print("GET /config returns every URL byte-for-byte ok")

BAD = [
    ("fmt", "file://output/x.jsonl?format=xml", "unknown format"),
    ("hec", "https://splunk.example.com:8088/services/collector/event?format=hec",
     "needs token="),
    ("plain", "http://siem.example.com/ingest?format=json&token=abc",
     "insecure=1"),
    ("sent", "http://dce.example.com/streams/Custom-ELF_CL?format=sentinel"
             "&tenant=t&client=c&secret=s", "requires https"),
    ("sent2", "https://dce.example.com/streams/Custom-ELF_CL?format=sentinel"
              "&client=c&secret=s", "needs tenant="),
    ("bad name!", "file://output/x.jsonl", "destination name"),
    ("dots", "file://output/../x.jsonl", "'..'"),
    ("dir", "file://output/", "needs a file name"),
    ("scheme", "ftp://x/y", "unsupported scheme"),
    ("nohost", "http:///path", "no host"),
    ("ev", "file://output/x.jsonl?format=hec&event=xml", "event= must be"),
]
for name, url, needle in BAD:
    r = client.put(f"/groups/{gid}", json={
        "destinations": [{"name": name, "url": url}]})
    assert r.status_code == 422, (name, r.status_code, r.text)
    assert needle in r.text, (name, needle, r.text)
print(f"PUT /groups rejects {len(BAD)} bad destinations with a named 422 ok")

r = client.put(f"/groups/{gid}", json={"destinations": [
    {"name": "dup", "url": "file://output/a.jsonl"},
    {"name": "dup", "url": "file://output/b.jsonl"}]})
assert r.status_code == 422 and "twice" in r.text, r.text
print("duplicate destination name rejected ok")

# The accepted set is unchanged after the rejected saves.
r = client.get(f"/groups/{gid}")
assert [d["name"] for d in r.json()["destinations"]] == list(GOOD), r.text
print("rejected saves left the stored destinations untouched ok")

# Direct validator: names and env: secrets.
validate_destination("a.b-c_1", "https://h/p?format=json&token=env:ELF_TOKEN")
try:
    validate_destination("x", "http://h/p?format=json&token=env:ELF_TOKEN")
    raise AssertionError("env: token over http should be rejected")
except ValueError:
    pass
print("validate_destination env: handling ok")

print("ALL DESTINATION SMOKE CHECKS PASSED")
