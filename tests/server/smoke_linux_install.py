"""Smoke test for the Linux install path of the console.

Run from the repo root with the venv python:
  .venv\\Scripts\\python.exe -I tests/server/smoke_linux_install.py

Uses FastAPI TestClient against a throwaway SQLite DB and agent directory.
Verifies:
  - GET /agent/binary?os=linux serves the staged Linux binary; ?os=windows
    still serves the exe; an unknown os is rejected
  - GET /agent/binary/status?os= reports per-OS availability
  - POST /install-script with os=linux returns a bash script carrying the
    systemd unit, the registration call and the config template; the
    'existing' account mode names the account; the audit option adds the
    rule; bad usernames and Windows-only modes are rejected
  - GET /cleanup-script?os=linux returns the bash cleanup script
  - the Windows script is unchanged by the os parameter default
"""
import os
import sys
import tempfile

root = tempfile.mkdtemp(prefix="elf_smoke_linux_")
tmp = os.path.join(root, "agent")   # the binaries, apart from the DB
os.makedirs(tmp)
os.environ["ELF_DB_PATH"] = os.path.join(root, "elf.db")
os.environ["ELF_AGENT_BINARY_DIR"] = tmp
os.environ["ELF_REQUIRE_AGENT_TOKEN"] = "0"

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "server"))

from fastapi.testclient import TestClient  # noqa: E402
import db  # noqa: E402
import main  # noqa: E402

db.init_db(main.DB_PATH)
client = TestClient(main.app)

r = client.post("/auth/login", json={"username": "admin", "password": "admin"})
assert r.status_code == 200, r.text

# --- binaries per OS ---
r = client.get("/agent/binary/status?os=linux")
assert r.status_code == 200 and r.json()["available"] is False, r.text
assert r.json()["name"] == "elf-agent", r.text
r = client.get("/agent/binary?os=linux")
assert r.status_code == 404, r.text
assert "elf-agent" in r.text, r.text

with open(os.path.join(tmp, "elf-agent"), "wb") as f:
    f.write(b"\x7fELF-fake-linux-agent")
with open(os.path.join(tmp, "efficient_log_forwarder.exe"), "wb") as f:
    f.write(b"MZ-fake-windows-agent")

r = client.get("/agent/binary?os=linux")
assert r.status_code == 200 and r.content.startswith(b"\x7fELF"), r.text
assert "elf-agent" in r.headers.get("content-disposition", ""), r.headers
r = client.get("/agent/binary")
assert r.status_code == 200 and r.content.startswith(b"MZ"), r.text
r = client.get("/agent/binary?os=macos")
assert r.status_code == 400, r.text
r = client.get("/agent/binary/status?os=linux")
assert r.json()["available"] is True and r.json()["os"] == "linux", r.text
# neither binary shows up as a companion file
r = client.get("/agent/files")
assert r.status_code == 200 and r.json() == [], r.text
print("binary endpoints per OS ok")

# --- Linux install script ---
r = client.post("/install-script", json={"group": "default", "os": "linux"})
assert r.status_code == 200, r.text
sh = r.text
assert sh.startswith("#!/bin/bash"), sh[:40]
for needle in ("curl -fsSL \"$BASE/agent/binary?os=linux\"",
               "useradd --system --no-create-home",
               "usermod -aG systemd-journal",
               "/agents/register",
               "/etc/elf/config.ini",
               "SupplementaryGroups=systemd-journal",
               "ReadWritePaths=/var/lib/elf",
               "systemctl enable --now",
               "GROUP_ID=1",
               "SVC_USER='elf'"):
    assert needle in sh, needle
assert "elf-execve.rules" not in sh
assert "__BASE__" not in sh and "__USER__" not in sh and "__GROUP__" not in sh
# Pasted into an interactive shell, the text must run as one root unit and
# never `exit` the login shell: the body is a quoted heredoc fed to sudo.
assert "$ELF_SUDO bash -s <<'ELF_INSTALL'" in sh, sh[:600]
assert sh.rstrip().endswith("ELF_INSTALL"), sh[-200:]
assert sh.index("$ELF_SUDO bash -s") < sh.index("exit 1"), "the guard must be inside the heredoc"
print("linux install script (local account) ok")

r = client.post("/install-script", json={"group": "default", "os": "linux",
                                         "account_mode": "existing", "username": "svc-elf",
                                         "audit_execve": True})
assert r.status_code == 200, r.text
sh = r.text
assert "SVC_USER='svc-elf'" in sh and "useradd --system" not in sh, sh[:400]
assert "does not exist on this host" in sh
assert "-S execve,execveat -k elf_exec" in sh and "Audit=yes" in sh
print("linux install script (existing account, audit rule) ok")

r = client.post("/install-script", json={"group": "default", "os": "linux",
                                         "account_mode": "existing", "username": "Bad User"})
assert r.status_code == 400, r.text
r = client.post("/install-script", json={"group": "default", "os": "linux",
                                         "account_mode": "domain", "domain": "CORP", "username": "x"})
assert r.status_code == 400, r.text
r = client.post("/install-script", json={"group": "default", "os": "windows",
                                         "account_mode": "existing", "username": "x"})
assert r.status_code == 400, r.text
r = client.post("/install-script", json={"group": "default", "os": "plan9"})
assert r.status_code == 422, r.text
r = client.post("/install-script", json={"group": "nope", "os": "linux"})
assert r.status_code == 404, r.text
print("linux install script validation ok")

# --- Windows script untouched by the default ---
r = client.post("/install-script", json={"group": "default"})
assert r.status_code == 200 and "$svcName = 'ELFAgent'" in r.text, r.text[:200]
r = client.get("/install-script?group=default")
assert r.status_code == 200 and "sc.exe create" in r.text, r.text[:200]
print("windows install script ok")

# --- cleanup scripts ---
r = client.get("/cleanup-script?os=linux")
assert r.status_code == 200 and r.text.startswith("#!/bin/bash"), r.text[:80]
assert "systemctl disable --now elf-agent" in r.text and "userdel elf" in r.text
assert "$ELF_SUDO bash -s <<'ELF_CLEANUP'" in r.text and r.text.rstrip().endswith("ELF_CLEANUP")
r = client.get("/cleanup-script")
assert r.status_code == 200 and "$svcName = 'ELFAgent'" in r.text, r.text[:200]
print("cleanup scripts ok")

# --- audit trail names the OS ---
r = client.get("/audit")
assert r.status_code == 200, r.text
entries = r.json() if isinstance(r.json(), list) else r.json().get("entries", r.json().get("items", []))
gen = [e for e in entries if e.get("action") == "install-script.generate"]
assert gen, entries[:3]
print("audit entries:", len(gen))

print("\nALL LINUX INSTALL SMOKE TESTS PASSED")
