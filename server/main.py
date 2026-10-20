"""ELF management server: the FastAPI application.

Endpoints:
  Agents:
    POST   /agents/register          register / heartbeat an agent
    GET    /agents                    list all agents
    GET    /agents/{agent_id}         agent detail
    PUT    /agents/{agent_id}/group   assign agent to a group
    DELETE /agents/{agent_id}         delete an agent (and its alerts/logs)
  Groups:
    GET    /groups                    list groups
    POST   /groups                    create a group
    GET    /groups/{group_id}         group detail
    PUT    /groups/{group_id}         update group settings
    DELETE /groups/{group_id}         delete a group (agents reassigned to default)
  Rules:
    GET    /rules                     list rules (optional ?group_id=)
    POST   /rules                     create/upsert a rule (requires group_id)
    GET    /rules/{rule_id}           get a rule (requires ?group_id=)
    PUT    /rules/{rule_id}           update a rule
    DELETE /rules/{rule_id}           delete a rule
    POST   /rules/bulk-delete         delete many rules from one group
    POST   /rules/validate            validate a Sigma YAML rule body
    POST   /rules/import              bulk import from a .zip (multipart, ?group_id=&dry_run=&...)
    POST   /rules/import/sigmahq      bulk import from SigmaHQ release assets (?assets=&tag=...)
    GET    /rules/import/sigmahq/assets  list SigmaHQ release assets (?tag=)
    POST   /rules/import/commit        commit a previewed import (?commit_token=)
  Lists (reusable value lists, global across all groups):
    GET    /lists                     list all lists
    POST   /lists                     create a list
    GET    /lists/{name}              get a list
    PUT    /lists/{name}              update a list
    DELETE /lists/{name}              delete a list
  Agent-facing (used by the C++ agent):
    GET    /config/{agent_id}         effective config + ruleset for an agent
    POST   /alerts                    agent reports an alert
    POST   /logs                      agent forwards a log batch
  Offline install (no internet on the target host):
    GET    /agent/binary?os=          download the prebuilt agent (windows | linux)
    GET    /agent/binary/status?os=   is a binary available for download?
    GET    /agent/lsa-helper          C# LSA privilege helper (grant/revoke) for install+cleanup scripts
    GET    /agent/files               list companion files shipped alongside the agent
    POST   /agent/files               upload a companion file
    GET    /agent/files/{name}        download a companion file
    DELETE /agent/files/{name}        delete a companion file
    POST   /install-script            generate the install script (.ps1, or .sh with os=linux)
    GET    /cleanup-script?os=        the cleanup script (.ps1, or .sh with os=linux)
  Legacy (kept for backward compatibility with old bookmarks/scripts):
    GET    /install-script?group=...  same as POST but local-account mode only
  Observability:
    GET    /alerts                    list recent alerts (payloads omitted for speed)
    GET    /alerts/{id}               one alert INCLUDING its payload (detail view)
    GET    /logs                      list the newest forwarded log batches
    GET    /metrics/savings           per-agent created-vs-forwarded savings
    GET    /metrics/stats             time-bucketed events/bytes (optional ?agent_id=)
    GET    /metrics/alerts            time-bucketed alert counts (optional ?agent_id=)
    GET    /                          web UI (HTML)
"""

import hashlib
import logging
import os
import re
import threading
import time
import yaml
from typing import Any

from fastapi import FastAPI, HTTPException, Query, Request, UploadFile, File, Depends, Response
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, FileResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired

import db
import linux_install
from models import (
    AgentRegister, AgentGroupAssignment,
    GroupCreate, GroupUpdate,
    RuleUpsert, ListUpsert, BulkRuleDelete,
    AlertReport, LogReport,
    CollectRequest, CollectBatch, CollectDone,
    LoginRequest, UserCreate, UserRoleUpdate,
    InstallScriptRequest, SettingsUpdate,
)

DB_PATH = os.environ.get("ELF_DB_PATH", "/data/elf.db")

log = logging.getLogger("elf")

# Where the prebuilt agent executable is stored so new hosts can download it
# without reaching out to the internet. The binary is baked into the image
# (COPY in the Dockerfile, from server/agent/) and seeded onto the volume by
# the entrypoint on every container start.
AGENT_BINARY_DIR = os.environ.get("ELF_AGENT_BINARY_DIR", "/data/agent")
AGENT_BINARY_NAME = os.environ.get("ELF_AGENT_BINARY_NAME", "efficient_log_forwarder.exe")
# The Linux agent, served to hosts installed with the generated shell script.
AGENT_BINARY_NAME_LINUX = os.environ.get("ELF_AGENT_BINARY_NAME_LINUX", "elf-agent")
AGENT_BINARY_NAMES = {"windows": AGENT_BINARY_NAME, "linux": AGENT_BINARY_NAME_LINUX}

# Upload size limits prevent memory-exhaustion DoS. Companion files are
# small utilities. A Sigma rules zip is typically a few MB. These limits are
# generous ceilings.
MAX_FILE_UPLOAD_BYTES = int(os.environ.get("ELF_MAX_FILE_UPLOAD", 20 * 1024 * 1024))      # 20 MB
MAX_RULES_ZIP_BYTES = int(os.environ.get("ELF_MAX_RULES_ZIP", 100 * 1024 * 1024))        # 100 MB
MAX_YAML_BODY_BYTES = int(os.environ.get("ELF_MAX_YAML_BODY", 1 * 1024 * 1024))           # 1 MB per rule

# The host/port new agents should contact. Defaults to the container's own
# port; override with ELF_PUBLIC_HOST (e.g. the Docker host IP) when the
# container is behind port mapping.
AGENT_PUBLIC_HOST = os.environ.get("ELF_PUBLIC_HOST", "")
AGENT_PUBLIC_PORT = int(os.environ.get("ELF_PUBLIC_PORT", "8000"))

# Agent enrollment-token enforcement.
# When "1", every agent-facing endpoint (GET /config, POST /alerts,
# POST /logs, POST /collect/*) REQUIRES a valid `Authorization: Bearer
# <token>` header; agents without a token (or with a wrong one) get 401.
# When unset/empty (default), agents that have NO token row are allowed
# through during the re-enroll grace period (logged as auth.legacy), but
# agents that DO have a token row must send the correct token. This lets
# existing agents keep working until they're re-enrolled, then flip the
# switch to force tokens everywhere.
REQUIRE_AGENT_TOKEN = os.environ.get("ELF_REQUIRE_AGENT_TOKEN", "") == "1"

# --- Human auth -------------------------------------------------------------
#
# Session cookies are HMAC-signed via itsdangerous so the server stays
# stateless (no server-side session store). The secret is read from
# ELF_SESSION_SECRET; if unset, a random one is generated at startup (a
# restart logs everyone out, which is fine for a single-instance dev
# server). The cookie carries the user id; the user row is looked up on
# every request via _current_user.
SESSION_SECRET = os.environ.get("ELF_SESSION_SECRET") or os.urandom(32).hex()
SESSION_COOKIE_NAME = "elf_session"
SESSION_MAX_AGE = 8 * 3600  # 8 hours
_session_serializer = URLSafeTimedSerializer(SESSION_SECRET, salt="elf-session")

# Roles in order of privilege (viewer < rule_contributor < admin).
ROLES = ("viewer", "rule_contributor", "admin")
_ROLE_RANK = {r: i for i, r in enumerate(ROLES)}


def validate_password(password: str) -> str | None:
    """Enforce password complexity for newly created users. Returns None
    on success, or an error message string on failure. The seeded admin
    is exempt (it's a bootstrap credential the admin is expected to
    change)."""
    if len(password) < 8:
        return "Password must be at least 8 characters."
    if not re.search(r"[A-Z]", password):
        return "Password must contain at least one uppercase letter."
    if not re.search(r"[a-z]", password):
        return "Password must contain at least one lowercase letter."
    if not re.search(r"\d", password):
        return "Password must contain at least one digit."
    if not re.search(r"[^A-Za-z0-9]", password):
        return "Password must contain at least one symbol (e.g. !@#$%)."
    return None


def _make_session_cookie(user_id: int) -> str:
    """Sign a user id into a session cookie value."""
    return _session_serializer.dumps({"uid": user_id})


def _read_session_cookie(cookie_val: str) -> int | None:
    """Verify + decode a session cookie. Returns the user id, or None on
    bad/expired signatures."""
    if not cookie_val:
        return None
    try:
        data = _session_serializer.loads(cookie_val, max_age=SESSION_MAX_AGE)
        return data.get("uid")
    except (BadSignature, SignatureExpired):
        return None


def _current_user(request: Request) -> dict | None:
    """Read + verify the session cookie, return the user row (without
    password_hash) or None. This is the FastAPI dependency for endpoints
    that require a logged-in user."""
    cookie = request.cookies.get(SESSION_COOKIE_NAME)
    uid = _read_session_cookie(cookie)
    if uid is None:
        return None
    return db.get_user(uid, DB_PATH)


def _require_auth(user: dict | None = Depends(_current_user)) -> dict:
    """FastAPI dependency: require a logged-in user (any role)."""
    if user is None:
        raise HTTPException(401, "Not authenticated")
    return user


def _require_role(*allowed_roles: str):
    """FastAPI dependency factory: require the logged-in user to have one
    of the given roles. Usage: `Depends(_require_role("admin"))`."""
    def _dep(user: dict = Depends(_require_auth)) -> dict:
        if user["role"] not in allowed_roles:
            db.write_audit(user["username"], "auth.deny",
                           target="",
                           detail={"required": list(allowed_roles),
                                   "actual": user["role"]})
            raise HTTPException(403, "Insufficient role")
        return user
    return _dep

app = FastAPI(title="ELF Management Server", version="1.0.0")

# Compress large JSON responses (e.g. /config/{agent_id} with thousands of
# rules). The agent's WinHTTP stack advertises gzip in Accept-Encoding, and a
# 2600-rule config payload shrinks ~10x, which keeps the transfer inside the
# agent's bounded receive timeout. Minimum size avoids compressing tiny
# responses where the overhead exceeds the savings.
app.add_middleware(GZipMiddleware, minimum_size=1024)

# Serve vendored static assets (e.g. Chart.js) from server/static/ at /static/*.
# Files are baked into the image via COPY in the Dockerfile, so this works on
# air-gapped networks without any CDN dependency.
_STATIC_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")
if os.path.isdir(_STATIC_DIR):
    app.mount("/static", StaticFiles(directory=_STATIC_DIR), name="static")


# When set to "1", the server seeds three groups with sample rules, lists, and
# destinations on startup so you can test agent functionality end-to-end without
# hand-configuring everything. The default group is always seeded (see
# _seed_default_rules); the two extra groups + their rules are added on top.
# Re-runs are idempotent: existing seed rows are upserted in place.
SEED_TEST_DATA = os.environ.get("ELF_SEED_TEST_DATA", "0") == "1"
# The group that receives the Linux sample rules (created on first start).
LINUX_GROUP_NAME = "linux-servers"


@app.on_event("startup")
def _startup() -> None:
    db.init_db(DB_PATH)
    _seed_default_rules()
    if SEED_TEST_DATA:
        _seed_test_data()
    _invalidate_config_cache()


# --- Auth endpoints (human login) -------------------------------------------

@app.post("/auth/login")
def auth_login(body: LoginRequest, response: Response) -> dict:
    """Verify username/password, set a signed session cookie. Returns the
    user's role + username so the UI can adapt."""
    user = db.verify_user_password(body.username, body.password, DB_PATH)
    if user is None:
        db.write_audit(body.username, "auth.deny", target=body.username,
                       detail={"reason": "bad_credentials"}, db_path=DB_PATH)
        raise HTTPException(401, "Invalid username or password")
    db.write_audit(user["username"], "auth.login", target=user["username"],
                   db_path=DB_PATH)
    response.set_cookie(
        key=SESSION_COOKIE_NAME,
        value=_make_session_cookie(user["id"]),
        max_age=SESSION_MAX_AGE,
        httponly=True,
        samesite="lax",
        path="/",
    )
    return {"username": user["username"], "role": user["role"]}


@app.post("/auth/logout")
def auth_logout(response: Response) -> dict:
    """Clear the session cookie."""
    response.delete_cookie(SESSION_COOKIE_NAME, path="/")
    return {"ok": True}


@app.get("/auth/me")
def auth_me(user: dict | None = Depends(_current_user)) -> dict:
    """Return the current user, or 401 if not logged in. The UI calls this
    on page load to decide whether to show the login form or the app."""
    if user is None:
        raise HTTPException(401, "Not authenticated")
    return {"username": user["username"], "role": user["role"]}


# --- User management (admin-only) -------------------------------------------

@app.get("/users")
def list_users_endpoint(user: dict = Depends(_require_role("admin"))) -> list[dict]:
    return db.list_users(DB_PATH)


@app.post("/users")
def create_user_endpoint(body: UserCreate,
                          user: dict = Depends(_require_role("admin"))) -> dict:
    # Enforce password complexity for newly created users (the seeded
    # admin is exempt because it is a bootstrap credential).
    err = validate_password(body.password)
    if err:
        raise HTTPException(400, err)
    try:
        new_user = db.create_user(body.username, body.password, body.role, DB_PATH)
    except Exception:
        raise HTTPException(409, f"Username '{body.username}' already exists.")
    db.write_audit(user["username"], "user.create", target=body.username,
                   detail={"role": body.role}, db_path=DB_PATH)
    return new_user


@app.delete("/users/{user_id}")
def delete_user_endpoint(user_id: int,
                         user: dict = Depends(_require_role("admin"))) -> dict:
    if user_id == user["id"]:
        raise HTTPException(400, "Cannot delete your own account while logged in.")
    ok = db.delete_user(user_id, DB_PATH)
    if not ok:
        raise HTTPException(404, "User not found")
    db.write_audit(user["username"], "user.delete", target=str(user_id),
                   db_path=DB_PATH)
    return {"deleted": True}


@app.put("/users/{user_id}/role")
def update_user_role_endpoint(user_id: int, body: UserRoleUpdate,
                              user: dict = Depends(_require_role("admin"))) -> dict:
    ok = db.update_user_role(user_id, body.role, DB_PATH)
    if not ok:
        raise HTTPException(404, "User not found")
    db.write_audit(user["username"], "user.role", target=str(user_id),
                   detail={"role": body.role}, db_path=DB_PATH)
    return {"ok": True}


@app.get("/audit")
def get_audit_log_endpoint(limit: int = Query(200, ge=1, le=2000),
                           offset: int = Query(0, ge=0),
                           user: dict = Depends(_require_role("admin"))) -> list[dict]:
    """Return recent audit entries, newest first. Admin-only, because the audit log
    records every privileged action (auth, user/group/rule/agent mutations)
    and is the forensic trail for "who did what, when"."""
    return db.get_audit_log(limit=limit, offset=offset, db_path=DB_PATH)


@app.delete("/audit")
def clear_audit_log_endpoint(user: dict = Depends(_require_role("admin"))) -> dict:
    """Delete all audit entries. The clear action itself is recorded AFTER
    the truncation so the trail shows who cleared it (and when) without the
    old entries reappearing."""
    n = db.clear_audit(DB_PATH)
    db.write_audit(user["username"], "audit.clear", "",
                   {"deleted": n}, db_path=DB_PATH)
    return {"deleted": n}


def _seed_test_data() -> None:
    """Populate three groups with varied sample rules, lists, and destinations
    so agent functionality can be tested end-to-end.

    Groups created (in addition to the always-seeded "default" group):
      - "workstations":  the MITRE kill-chain detection suite (kc_rules below)
      - "servers":        server hardening (service install + log forwarding)
      - "tier-0":         high-value assets (aggressive threshold + sequence)

    Each group gets a distinct set of destinations (file:// paths under
    output/) and a mix of rule types (simple, threshold, sequence) and action
    types (forward_event, alert, forward_buffer). Several rules reference
    reusable `@@` lists so list expansion is exercised.
    Re-running is safe: groups/rules/lists are upserted, not duplicated.
    """
    print("[seed] ELF_SEED_TEST_DATA=1: seeding test groups, rules, and lists")

    # --- Reusable lists (global, shared across all groups) -------------------
    # The default `sensitive_processes` list is seeded by db.init_db; add a
    # couple more so list management + multi-list rules are testable.
    db.upsert_list("sensitive_processes",
        "# Sensitive processes to alert on (one per line).\n"
        "calc.exe\nnotepad.exe\nmspaint.exe\n", DB_PATH)
    db.upsert_list("living_off_the_land",
        "# LOLBins abused by attackers (one per line).\n"
        "# Lines starting with # are comments.\n"
        "powershell.exe\nwscript.exe\ncscript.exe\nmshta.exe\nregsvr32.exe\n",
        DB_PATH)
    db.upsert_list("suspicious_parents",
        "# Parent processes that should never spawn a shell.\n"
        "winword.exe\nexcel.exe\noutlook.exe\n", DB_PATH)
    # Auto-elevate binaries commonly abused for UAC bypass (used by the
    # kill-chain privilege-escalation rule).
    db.upsert_list("uac_bypass_binaries",
        "# Auto-elevate binaries abused for UAC bypass (one per line).\n"
        "fodhelper.exe\ncomputerdefaults.exe\neventvwr.exe\nsdclt.exe\nwsreset.exe\n",
        DB_PATH)

    # --- Group definitions --------------------------------------------------
    groups = {
        "workstations": {
            "description": "MITRE kill-chain detection suite for user workstations.",
            "retention_seconds": 60,
            "poll_interval_seconds": 15,
            "destinations": [
                {"name": "siem", "url": "file://./output/siem.jsonl"},
                {"name": "data_lake", "url": "file://./output/data_lake.jsonl"},
                {"name": "alerts", "url": "file://./output/alerts.jsonl"},
            ],
        },
        "servers": {
            "description": "Server hardening rules + continuous log forwarding.",
            "retention_seconds": 120,
            "poll_interval_seconds": 30,
            "destinations": [
                {"name": "siem", "url": "file://./output/servers_siem.jsonl"},
                {"name": "data_lake", "url": "file://./output/servers_data_lake.jsonl"},
                {"name": "alerts", "url": "file://./output/servers_alerts.jsonl"},
            ],
        },
        "tier-0": {
            "description": "High-value assets (DCs/admin hosts): aggressive thresholds.",
            "retention_seconds": 300,
            "poll_interval_seconds": 10,
            "destinations": [
                {"name": "siem", "url": "file://./output/tier0_siem.jsonl"},
                {"name": "data_lake", "url": "file://./output/tier0_data_lake.jsonl"},
                {"name": "alerts", "url": "file://./output/tier0_alerts.jsonl"},
            ],
        },
    }

    # Create each group (idempotent: fetch by name, create if missing, then
    # apply the destination/retention settings).
    group_ids: dict[str, int] = {}
    for name, cfg in groups.items():
        g = db.get_group_by_name(name, DB_PATH)
        if not g:
            g = db.create_group(name, cfg["description"], DB_PATH)
        db.update_group(g["id"], {
            "retention_seconds": cfg["retention_seconds"],
            "poll_interval_seconds": cfg["poll_interval_seconds"],
            "destinations": cfg["destinations"],
        }, DB_PATH)
        group_ids[name] = g["id"]

    # --- Rule definitions per group -----------------------------------------
    # Each rule is a Sigma YAML body. Rules exercise: simple/threshold/sequence
    # types, forward_event/alert/forward_buffer actions, @@list references,
    # and |contains/|endswith modifiers.
    def _rule(yaml_body: str) -> dict:
        parsed = yaml.safe_load(yaml_body)
        return {
            "yaml": yaml_body,
            "name": parsed.get("title", parsed.get("id", "")),
            "severity": parsed.get("level", "medium"),
            "enabled": parsed.get("status", "stable") != "deprecated",
        }

    sv_rules = [
        # Sequence rule: failed then success logon.
        _rule(
            "title: Server Failed Then Success Logon\n"
            "id: sv_failed_then_success\n"
            "status: stable\n"
            "description: A failed logon followed by success within 2 minutes on a server.\n"
            "author: ELF test data\n"
            "date: 2026-10-03\n"
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
            '      message: "Server: failed logon then success. Possible credential compromise."\n'
            "    - type: forward_buffer\n"
            "      destination: data_lake\n"
        ),
        # LOLBins detection via @@living_off_the_land list.
        _rule(
            "title: Living-off-the-Land Binary Execution\n"
            "id: sv_lolbin_execution\n"
            "status: stable\n"
            "description: Fires when a LOLBin from the @@living_off_the_land list launches.\n"
            "author: ELF test data\n"
            "date: 2026-10-03\n"
            "level: high\n"
            "logsource:\n"
            "  product: windows\n"
            "  service: security\n"
            "detection:\n"
            "  selection:\n"
            "    EventID: 4688\n"
            '    Image|endswith: "@@living_off_the_land"\n'
            "  condition: selection\n"
            "elf:\n"
            "  actions:\n"
            "    - type: alert\n"
            "      destination: alerts\n"
            '      message: "LOLBin execution detected on a server."\n'
            "    - type: forward_buffer\n"
            "      destination: siem\n"
        ),
        # forward_event: forward all successful logons to SIEM.
        _rule(
            "title: Forward All Server Logons\n"
            "id: sv_forward_logons\n"
            "status: stable\n"
            "description: Continuously forwards every successful logon (4624) to the SIEM.\n"
            "author: ELF test data\n"
            "date: 2026-10-03\n"
            "level: low\n"
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
            "      destination: siem\n"
        ),
    ]

    t0_rules = [
        # Aggressive threshold: 3 failed logons in 30s.
        _rule(
            "title: Tier-0 Aggressive Brute Force\n"
            "id: t0_aggressive_brute_force\n"
            "status: stable\n"
            "description: 3 failed logons within 30s on a tier-0 asset.\n"
            "author: ELF test data\n"
            "date: 2026-10-03\n"
            "level: critical\n"
            "logsource:\n"
            "  product: windows\n"
            "  service: security\n"
            "detection:\n"
            "  selection:\n"
            "    EventID: 4625\n"
            "  condition: selection\n"
            "elf:\n"
            "  threshold: 3\n"
            "  timeframe: 30s\n"
            "  group_by: TargetUserName\n"
            "  actions:\n"
            "    - type: alert\n"
            "      destination: alerts\n"
            '      message: "Tier-0 brute-force: 3 failed logons in 30s."\n'
            "    - type: forward_buffer\n"
            "      destination: data_lake\n"
        ),
        # Suspicious parent + LOLBin combo: office app spawning a LOLBin.
        _rule(
            "title: Office App Spawning LOLBin\n"
            "id: t0_office_lolbin\n"
            "status: stable\n"
            "description: An Office app (from @@suspicious_parents) spawning a LOLBin (from @@living_off_the_land).\n"
            "author: ELF test data\n"
            "date: 2026-10-03\n"
            "level: critical\n"
            "logsource:\n"
            "  product: windows\n"
            "  service: security\n"
            "detection:\n"
            "  selection:\n"
            "    EventID: 4688\n"
            '    ParentImage|endswith: "@@suspicious_parents"\n'
            '    Image|endswith: "@@living_off_the_land"\n'
            "  condition: selection\n"
            "elf:\n"
            "  actions:\n"
            "    - type: alert\n"
            "      destination: alerts\n"
            '      message: "Tier-0: Office app spawned a LOLBin. Likely macro attack."\n'
            "    - type: forward_buffer\n"
            "      destination: siem\n"
        ),
        # forward_event: forward all 4688 events EXCEPT those launched by
        # the SYSTEM account to SIEM for full visibility on tier-0 assets.
        _rule(
            "title: Forward Tier-0 Process Creation (non-SYSTEM)\n"
            "id: t0_forward_all_process_creation\n"
            "status: stable\n"
            "description: Forwards every 4688 event on tier-0 assets where the\n"
            "  subject user is not SYSTEM to the SIEM.\n"
            "author: ELF test data\n"
            "date: 2026-10-03\n"
            "level: medium\n"
            "logsource:\n"
            "  product: windows\n"
            "  service: security\n"
            "detection:\n"
            "  selection:\n"
            "    EventID: 4688\n"
            "  filter_system:\n"
            "    SubjectUserName: SYSTEM\n"
            "  condition: selection and not filter_system\n"
            "elf:\n"
            "  actions:\n"
            "    - type: forward_event\n"
            "      destination: siem\n"
        ),
    ]

    # --- MITRE kill-chain demo rules (Execution -> Impact) -------------------
    # 12 rules covering the 11 tactics from Execution to Impact; Credential
    # Access is doubled (LSASS dump + password spray). Every title and
    # description names its kill-chain step (tactic). Each pairs with an
    # Atomic Red Team test runnable on a single Windows host and showcases a
    # different ELF capability (contains/regex/cidr modifiers, |all lists,
    # @@list refs, threshold+group_by, distinct counting, sequence, quantifier
    # conditions, multi-channel System/7045, field-value matching, and the
    # full low->critical severity + action-type spread).
    kc_rules = [
        # KC-01 Execution (T1059.001): encoded PowerShell via 4688 cmdline.
        _rule(
            "title: Kill-Chain 01 (Execution) - Encoded PowerShell Command\n"
            "id: win_kc_01_ps_encoded\n"
            "status: test\n"
            "description: Execution step of the MITRE kill chain - encoded PowerShell command line (Atomic Red Team T1059.001, PowerShell Command Execution). Multi-value contains matching. Trigger - Invoke-AtomicTest T1059.001 -TestNumbers 17 (elevated prompt).\n"
            "author: ELF test data\n"
            "date: 2026-10-18\n"
            "level: high\n"
            "tags:\n"
            "  - attack.execution\n"
            "  - attack.t1059.001\n"
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
            '      message: "Encoded PowerShell command line detected."\n'
        ),
        # KC-02 Persistence (T1543.003): service install via System/7045.
        _rule(
            "title: Kill-Chain 02 (Persistence) - Service Installed\n"
            "id: win_kc_02_service_install\n"
            "status: test\n"
            "description: Persistence step of the MITRE kill chain - new service installed (Atomic Red Team T1543.003, Service Installation CMD). System-channel rule showing multi-channel support. Trigger - Invoke-AtomicTest T1543.003 -TestNumbers 2 (elevated prompt; run the same command with -GetPrereqs first to fetch the service binary).\n"
            "author: ELF test data\n"
            "date: 2026-10-18\n"
            "level: medium\n"
            "tags:\n"
            "  - attack.persistence\n"
            "  - attack.t1543.003\n"
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
            '      message: "New service installed (possible persistence)."\n'
            "    - type: forward_event\n"
            "      destination: siem\n"
        ),
        # KC-03 Privilege Escalation (T1548.002): UAC-bypass binary via @@list.
        _rule(
            "title: Kill-Chain 03 (Privilege Escalation) - UAC Bypass Binary Launch\n"
            "id: win_kc_03_uac_bypass\n"
            "status: test\n"
            "description: Privilege Escalation step of the MITRE kill chain - known auto-elevate UAC-bypass binary launched (Atomic Red Team T1548.002, Bypass UAC using Fodhelper). Reusable-list matching. Trigger - Invoke-AtomicTest T1548.002 -TestNumbers 3 (no elevation needed, the test itself performs the bypass).\n"
            "author: ELF test data\n"
            "date: 2026-10-18\n"
            "level: medium\n"
            "tags:\n"
            "  - attack.privilege_escalation\n"
            "  - attack.t1548.002\n"
            "logsource:\n"
            "  product: windows\n"
            "  service: security\n"
            "detection:\n"
            "  selection:\n"
            "    EventID: 4688\n"
            '    Image|endswith: "@@uac_bypass_binaries"\n'
            "  condition: selection\n"
            "elf:\n"
            "  actions:\n"
            "    - type: alert\n"
            "      destination: alerts\n"
            '      message: "Known UAC-bypass binary launched."\n'
        ),
        # KC-04 Defense Evasion (T1685.005, formerly T1070.001): log clearing.
        _rule(
            "title: Kill-Chain 04 (Defense Evasion) - Security Event Log Cleared\n"
            "id: win_kc_04_log_clear\n"
            "status: test\n"
            "description: Defense Evasion step of the MITRE kill chain - event log clearing via wevtutil, Clear-EventLog, or the audit-log-cleared 1102 event (Atomic Red Team T1685.005, Clear Logs). Multi-selection OR condition. Trigger - Invoke-AtomicTest T1685.005 -TestNumbers 1 -InputArgs @{log_name='Security'} (elevated prompt).\n"
            "author: ELF test data\n"
            "date: 2026-10-18\n"
            "level: high\n"
            "tags:\n"
            "  - attack.defense_evasion\n"
            "  - attack.t1685.005\n"
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
            '      message: "Event log clearing detected (defense evasion)."\n'
            "    - type: forward_buffer\n"
            "      destination: data_lake\n"
        ),
        # KC-05 Credential Access (T1003.001): LSASS dump via comsvcs.
        _rule(
            "title: Kill-Chain 05 (Credential Access) - LSASS Dump via comsvcs MiniDump\n"
            "id: win_kc_05_lsass_dump\n"
            "status: test\n"
            "description: Credential Access step of the MITRE kill chain - LSASS memory dump attempt via rundll32 comsvcs.dll MiniDump (Atomic Red Team T1003.001). Shows the all AND-list modifier. Trigger - Invoke-AtomicTest T1003.001 -TestNumbers 2 (elevated prompt; disable Defender real-time protection first).\n"
            "author: ELF test data\n"
            "date: 2026-10-18\n"
            "level: critical\n"
            "tags:\n"
            "  - attack.credential_access\n"
            "  - attack.t1003.001\n"
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
            '      message: "LSASS memory dump attempt via comsvcs.dll."\n'
        ),
        # KC-06 Credential Access (T1110.003): password-spray threshold,
        # grouped by source IP, since a spray is one source hitting many users
        # (per-user counting would be brute force instead).
        _rule(
            "title: Kill-Chain 06 (Credential Access) - Password Spray (Many Users, One Source)\n"
            "id: win_kc_06_password_spray\n"
            "status: test\n"
            "description: Credential Access step of the MITRE kill chain - many failed logons from one source IP (Atomic Red Team T1110.003, Password Spray). Threshold grouped by source IP instead of user. Trigger - run net use \\\\127.0.0.1\\IPC$ /user:LAB\\nosuchuser1 BadPassword1 5+ times within 60s (the atomic spray tests authenticate against the DC, whose 4625 events this host cannot see).\n"
            "author: ELF test data\n"
            "date: 2026-10-18\n"
            "level: high\n"
            "tags:\n"
            "  - attack.credential_access\n"
            "  - attack.t1110.003\n"
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
            '      message: "Password spray: 5+ failed logons from one source in 60s."\n'
            "    - type: forward_buffer\n"
            "      destination: data_lake\n"
        ),
        # KC-07 Discovery (T1046): port scan via WFP 5156 + distinct counting.
        _rule(
            "title: Kill-Chain 07 (Discovery) - Network Scan (10 Unique Hosts in 60s)\n"
            "id: win_kc_07_port_scan\n"
            "status: test\n"
            "description: Discovery step of the MITRE kill chain - contacting many unique destinations fast (Atomic Red Team T1046, Port-Scanning /24 Subnet). Threshold with distinct counting and a CIDR filter. Trigger - Invoke-AtomicTest T1046 -TestNumbers 10 (scans a /24, easily crossing the 10-unique-destination threshold).\n"
            "author: ELF test data\n"
            "date: 2026-10-18\n"
            "level: medium\n"
            "tags:\n"
            "  - attack.discovery\n"
            "  - attack.t1046\n"
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
            '      message: "Port scan: 10 unique destinations contacted in 60s."\n'
        ),
        # KC-08 Lateral Movement (T1021.001): RDP, seen from either side. The
        # client launch (4688) is what the host running the test writes; the
        # type-10 logon (4624) is written by the host that accepts a session.
        _rule(
            "title: Kill-Chain 08 (Lateral Movement) - RDP Client Launched or RemoteInteractive Logon\n"
            "id: win_kc_08_rdp_logon\n"
            "status: test\n"
            "description: Lateral Movement step of the MITRE kill chain - the RDP client started toward another host (mstsc.exe with /v:), or a RemoteInteractive logon type 10 received (Atomic Red Team T1021.001, RDP to Remote Host). Two selections in one condition with a machine-account filter. Trigger - mstsc.exe /v:<host> on the watched host, no credentials needed (the demo script opens and closes it); the logon side fires on the host that accepts the session.\n"
            "author: ELF test data\n"
            "date: 2026-10-18\n"
            "level: medium\n"
            "tags:\n"
            "  - attack.lateral_movement\n"
            "  - attack.t1021.001\n"
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
            '      message: "RDP client launched toward another host, or a RemoteInteractive logon received."\n'
            "    - type: forward_event\n"
            "      destination: siem\n"
        ),
        # KC-09 Collection (T1074.001): archive staging via regex.
        _rule(
            "title: Kill-Chain 09 (Collection) - Data Staged with Archive Tool\n"
            "id: win_kc_09_archive_stage\n"
            "status: test\n"
            "description: Collection step of the MITRE kill chain - archive tool staging data (Atomic Red Team T1074.001, Zip a Folder with PowerShell for Staging in Temp). Regex matching with alternation. Trigger - Invoke-AtomicTest T1074.001 -TestNumbers 3.\n"
            "author: ELF test data\n"
            "date: 2026-10-18\n"
            "level: medium\n"
            "tags:\n"
            "  - attack.collection\n"
            "  - attack.t1074.001\n"
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
            '      message: "Archive tool staging data (possible collection)."\n'
        ),
        # KC-10 Command and Control (T1105): ingress transfer, 1-of glob.
        _rule(
            "title: Kill-Chain 10 (Command and Control) - Download Tool / Ingress Transfer\n"
            "id: win_kc_10_ingress_transfer\n"
            "status: test\n"
            "description: Command and Control step of the MITRE kill chain - LOLBin download cradle (Atomic Red Team T1105, certutil download urlcache). Quantifier condition over tool-specific selections. Trigger - Invoke-AtomicTest T1105 -TestNumbers 7 (elevated prompt).\n"
            "author: ELF test data\n"
            "date: 2026-10-18\n"
            "level: high\n"
            "tags:\n"
            "  - attack.command_and_control\n"
            "  - attack.t1105\n"
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
            '      message: "LOLBin download cradle detected (ingress tool transfer)."\n'
        ),
        # KC-11 Exfiltration (T1048.002): stage-then-upload sequence.
        _rule(
            "title: Kill-Chain 11 (Exfiltration) - Data Staged then Uploaded (Sequence)\n"
            "id: win_kc_11_stage_exfil\n"
            "status: test\n"
            "description: Exfiltration step of the MITRE kill chain - archive staging followed by an upload command (Atomic Red Team T1074.001 then T1048.002, Exfiltrate data HTTPS using curl). Ordered two-stage sequence. Trigger - Invoke-AtomicTest T1074.001 -TestNumbers 3, then within 300s Invoke-AtomicTest T1048.002 -TestNumbers 1 (run the latter with -GetPrereqs first to fetch the curl artifact).\n"
            "author: ELF test data\n"
            "date: 2026-10-18\n"
            "level: high\n"
            "tags:\n"
            "  - attack.exfiltration\n"
            "  - attack.t1048.002\n"
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
            '      message: "Data staged then uploaded. Possible exfiltration."\n'
            "    - type: forward_buffer\n"
            "      destination: data_lake\n"
        ),
        # KC-12 Impact (T1490): shadow copy / backup deletion.
        _rule(
            "title: Kill-Chain 12 (Impact) - Shadow Copy / Backup Deletion\n"
            "id: win_kc_12_inhibit_recovery\n"
            "status: test\n"
            "description: Impact step of the MITRE kill chain - backup or shadow copy deletion, a ransomware precursor (Atomic Red Team T1490, Windows - Delete Volume Shadow Copies). Critical level with alert plus forward_buffer. Trigger - Invoke-AtomicTest T1490 -TestNumbers 1 (elevated prompt; on client SKUs the shadow-copy prereq may fail, but the delete command still runs and fires the rule).\n"
            "author: ELF test data\n"
            "date: 2026-10-18\n"
            "level: critical\n"
            "tags:\n"
            "  - attack.impact\n"
            "  - attack.t1490\n"
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
            '      message: "Backup/shadow copy deletion. Ransomware precursor."\n'
            "    - type: forward_buffer\n"
            "      destination: siem\n"
        ),
    ]

    # Upsert each rule into its group (idempotent on (rule_id, group_id)).
    for rule in sv_rules:
        parsed = yaml.safe_load(rule["yaml"])
        db.upsert_rule(
            rule_id=parsed["id"], group_id=group_ids["servers"],
            yaml_body=rule["yaml"], name=rule["name"],
            severity=rule["severity"], enabled=rule["enabled"], db_path=DB_PATH,
        )
    for rule in t0_rules:
        parsed = yaml.safe_load(rule["yaml"])
        db.upsert_rule(
            rule_id=parsed["id"], group_id=group_ids["tier-0"],
            yaml_body=rule["yaml"], name=rule["name"],
            severity=rule["severity"], enabled=rule["enabled"], db_path=DB_PATH,
        )

    # Kill-chain rules all target the workstations group so a single
    # workstation can run the full Atomic Red Team chain and trigger every rule.
    for rule in kc_rules:
        parsed = yaml.safe_load(rule["yaml"])
        db.upsert_rule(
            rule_id=parsed["id"], group_id=group_ids["workstations"],
            yaml_body=rule["yaml"], name=rule["name"],
            severity=rule["severity"], enabled=rule["enabled"], db_path=DB_PATH,
        )

    print(f"[seed] test data ready: groups={list(group_ids)} "
          f"lists=4 rules=12+3+3=18 (12 kill-chain rules in workstations)")


def _seed_default_rules() -> None:
    """Seed the default group with the project's sample Sigma rules on first
    run, and replace any non-Sigma seed rules already stored in the database
    with their Sigma form.

    A stored rule is treated as non-Sigma if its YAML body does not parse to a
    mapping with a top-level `id`, or if it uses the legacy `detections:` list
    schema. Such rules are overwritten with the canonical Sigma seed body so a
    recomposed container comes up clean without needing to wipe the volume.
    """
    group = db.get_group_by_name("default", DB_PATH)
    if not group:
        return
    # These mirror the agent's local rules/ so a fresh server and a fresh agent
    # start in sync. The server's copy is authoritative after the first poll.
    # Rules follow the Sigma standard (https://github.com/SigmaHQ/sigmahq.github.io/tree/main/docs).
    seeds = {
        # Linux samples (rules/lin_*.yaml); a Windows agent skips them.
        "lin_cron_persistence": {
            "name": 'Crontab Edited',
            "severity": 'medium',
            "yaml": (
                'title: Crontab Edited\n'
                'id: lin_cron_persistence\n'
                'status: stable\n'
                "description: crontab was run to install or edit a user's schedule. Needs the execve audit rule.\n"
                'author: ELF\n'
                'date: 2026-10-20\n'
                'level: medium\n'
                'tags:\n'
                '  - attack.persistence\n'
                '  - attack.t1053.003\n'
                'logsource:\n'
                '  product: linux\n'
                '  category: process_creation\n'
                'detection:\n'
                '  selection:\n'
                "    Image|endswith: '/crontab'\n"
                '  filter_list:\n'
                "    CommandLine|contains: ' -l'\n"
                '  condition: selection and not filter_list\n'
                'falsepositives:\n'
                '  - Administrators scheduling jobs\n'
                'elf:\n'
                '  actions:\n'
                '    - type: alert\n'
                '      destination: alerts\n'
                '      message: "crontab edited."\n'
                '    - type: forward_buffer\n'
                '      destination: siem\n'
            ),
        },
        "lin_curl_pipe_shell": {
            "name": 'Download Piped To Shell',
            "severity": 'high',
            "yaml": (
                'title: Download Piped To Shell\n'
                'id: lin_curl_pipe_shell\n'
                'status: stable\n'
                'description: A shell started with a command line that downloads with curl or wget and pipes the result into sh or bash. Needs the execve audit rule.\n'
                'author: ELF\n'
                'date: 2026-10-20\n'
                'level: high\n'
                'tags:\n'
                '  - attack.execution\n'
                '  - attack.t1059.004\n'
                '  - attack.command_and_control\n'
                '  - attack.t1105\n'
                'logsource:\n'
                '  product: linux\n'
                '  category: process_creation\n'
                'detection:\n'
                '  selection_shell:\n'
                '    Image|endswith:\n'
                "      - '/sh'\n"
                "      - '/bash'\n"
                "      - '/dash'\n"
                "      - '/zsh'\n"
                '  selection_download:\n'
                '    CommandLine|contains:\n'
                "      - 'curl '\n"
                "      - 'wget '\n"
                '  selection_pipe:\n'
                '    CommandLine|contains:\n'
                "      - '| sh'\n"
                "      - '| bash'\n"
                "      - '|sh'\n"
                "      - '|bash'\n"
                '  condition: selection_shell and selection_download and selection_pipe\n'
                'falsepositives:\n'
                '  - Installers that document this pattern (confirm the source)\n'
                'elf:\n'
                '  actions:\n'
                '    - type: alert\n'
                '      destination: alerts\n'
                '      message: "Download piped into a shell."\n'
                '    - type: forward_buffer\n'
                '      destination: siem\n'
            ),
        },
        "lin_forward_sudo_commands": {
            "name": 'Forward Sudo Commands',
            "severity": 'low',
            "yaml": (
                'title: Forward Sudo Commands\n'
                'id: lin_forward_sudo_commands\n'
                'status: stable\n'
                'description: Continuously forwards every command run through sudo to the SIEM.\n'
                'author: ELF\n'
                'date: 2026-10-20\n'
                'level: low\n'
                'tags:\n'
                '  - attack.privilege_escalation\n'
                '  - attack.t1548.003\n'
                'logsource:\n'
                '  product: linux\n'
                '  service: sudo\n'
                'detection:\n'
                '  selection:\n'
                "    Message|contains: 'COMMAND='\n"
                '  condition: selection\n'
                'falsepositives:\n'
                '  - Normal administration\n'
                'elf:\n'
                '  actions:\n'
                '    - type: forward_event\n'
                '      destination: siem\n'
            ),
        },
        "lin_new_user_or_group": {
            "name": 'Account Or Group Created',
            "severity": 'medium',
            "yaml": (
                'title: Account Or Group Created\n'
                'id: lin_new_user_or_group\n'
                'status: stable\n'
                'description: A local user or group was created (useradd, groupadd). Compliance forwarding with context.\n'
                'author: ELF\n'
                'date: 2026-10-20\n'
                'level: medium\n'
                'tags:\n'
                '  - attack.persistence\n'
                '  - attack.t1136.001\n'
                'logsource:\n'
                '  product: linux\n'
                '  service: useradd\n'
                'detection:\n'
                '  selection:\n'
                '    Message|startswith:\n'
                "      - 'new user'\n"
                "      - 'new group'\n"
                '  condition: selection\n'
                'falsepositives:\n'
                '  - Provisioning tools creating accounts\n'
                'elf:\n'
                '  actions:\n'
                '    - type: alert\n'
                '      destination: alerts\n'
                '      message: "A local account or group was created."\n'
                '    - type: forward_buffer\n'
                '      destination: siem\n'
            ),
        },
        "lin_shadow_file_read": {
            "name": 'Shadow File Read',
            "severity": 'high',
            "yaml": (
                'title: Shadow File Read\n'
                'id: lin_shadow_file_read\n'
                'status: stable\n'
                'description: A process started with /etc/shadow on its command line. Needs the execve audit rule.\n'
                'author: ELF\n'
                'date: 2026-10-20\n'
                'level: high\n'
                'tags:\n'
                '  - attack.credential_access\n'
                '  - attack.t1003.008\n'
                'logsource:\n'
                '  product: linux\n'
                '  category: process_creation\n'
                'detection:\n'
                '  selection:\n'
                "    CommandLine|contains: '/etc/shadow'\n"
                '  filter_system:\n'
                '    Image|endswith:\n'
                "      - '/unix_chkpwd'\n"
                "      - '/passwd'\n"
                "      - '/chage'\n"
                "      - '/usermod'\n"
                "      - '/useradd'\n"
                "      - '/userdel'\n"
                "      - '/pwck'\n"
                '  condition: selection and not filter_system\n'
                'falsepositives:\n'
                '  - Backup jobs that copy /etc (allowlist the backup binary)\n'
                'elf:\n'
                '  actions:\n'
                '    - type: alert\n'
                '      destination: alerts\n'
                '      message: "/etc/shadow named on a command line."\n'
                '    - type: forward_buffer\n'
                '      destination: siem\n'
            ),
        },
        "lin_ssh_brute_force": {
            "name": 'SSH Brute Force',
            "severity": 'high',
            "yaml": (
                'title: SSH Brute Force\n'
                'id: lin_ssh_brute_force\n'
                'status: stable\n'
                'description: Fires when 5 failed SSH logins for one user occur within 60 seconds.\n'
                'author: ELF\n'
                'date: 2026-10-20\n'
                'level: high\n'
                'tags:\n'
                '  - attack.credential_access\n'
                '  - attack.t1110\n'
                'logsource:\n'
                '  product: linux\n'
                '  service: sshd\n'
                'detection:\n'
                '  selection:\n'
                "    Message|startswith: 'Failed '\n"
                '  condition: selection\n'
                'falsepositives:\n'
                '  - Users mistyping passwords\n'
                '  - Automation with an expired key\n'
                'elf:\n'
                '  threshold: 5\n'
                '  timeframe: 60s\n'
                '  group_by: Computer\n'
                '  actions:\n'
                '    - type: alert\n'
                '      destination: alerts\n'
                '      message: "Possible SSH brute force: 5 failed logins within 60s."\n'
                '    - type: forward_buffer\n'
                '      destination: siem\n'
            ),
        },
        "win_brute_force_logon": {
            "name": "Brute Force Logon Attempt",
            "severity": "high",
            "yaml": (
                "title: Brute Force Logon Attempt\n"
                "id: win_brute_force_logon\n"
                "status: stable\n"
                "description: Fires when 5 failed logons (EventID 4625) occur within 60 seconds.\n"
                "author: ELF\n"
                "date: 2026-10-01\n"
                "level: high\n"
                "tags:\n"
                "  - attack.credential_access\n"
                "  - attack.t1110\n"
                "logsource:\n"
                "  product: windows\n"
                "  service: security\n"
                "detection:\n"
                "  selection:\n"
                "    EventID: 4625\n"
                "  condition: selection\n"
                "falsepositives:\n"
                "  - Misconfigured service accounts\n"
                "  - Users mistyping passwords\n"
                "elf:\n"
                "  threshold: 5\n"
                "  timeframe: 60s\n"
                "  group_by: TargetUserName\n"
                "  actions:\n"
                "    - type: alert\n"
                "      destination: alerts\n"
                '      message: "Possible brute-force logon: 5 failed logons within 60s."\n'
                "    - type: forward_buffer\n"
                "      destination: siem\n"
            ),
        },
        "win_failed_then_success_logon": {
            "name": "Failed Then Success Logon",
            "severity": "medium",
            "yaml": (
                "title: Failed Then Success Logon\n"
                "id: win_failed_then_success_logon\n"
                "status: stable\n"
                "description: A failed logon (4625) followed by a success (4624) within 2 minutes.\n"
                "author: ELF\n"
                "date: 2026-10-01\n"
                "level: medium\n"
                "tags:\n"
                "  - attack.credential_access\n"
                "  - attack.t1078\n"
                "logsource:\n"
                "  product: windows\n"
                "  service: security\n"
                "detection:\n"
                "  selection_failed:\n"
                "    EventID: 4625\n"
                "  selection_success:\n"
                "    EventID: 4624\n"
                "  condition: selection_failed or selection_success\n"
                "falsepositives:\n"
                "  - User mistypes password then succeeds\n"
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
                '      message: "Failed logon followed by success. Possible credential compromise."\n'
                "    - type: forward_buffer\n"
                "      destination: data_lake\n"
            ),
        },
        "win_forward_all_logons": {
            "name": "Forward All Logons",
            "severity": "low",
            "yaml": (
                "title: Forward All Logons\n"
                "id: win_forward_all_logons\n"
                "status: stable\n"
                "description: Continuously forwards every successful logon (4624) to the SIEM.\n"
                "author: ELF\n"
                "date: 2026-10-01\n"
                "level: low\n"
                "tags:\n"
                "  - attack.persistence\n"
                "  - attack.t1078\n"
                "logsource:\n"
                "  product: windows\n"
                "  service: security\n"
                "detection:\n"
                "  selection:\n"
                "    EventID: 4624\n"
                "  condition: selection\n"
                "falsepositives:\n"
                "  - Normal user logons\n"
                "elf:\n"
                "  actions:\n"
                "    - type: forward_event\n"
                "      destination: siem\n"
            ),
        },
    }

    def _is_sigma(body: str) -> bool:
        """True if the YAML body is a Sigma mapping with a top-level id."""
        try:
            parsed = yaml.safe_load(body)
        except Exception:
            return False
        return isinstance(parsed, dict) and bool(parsed.get("id"))

    # The Linux samples live in their own group so a Linux host enrolls into
    # a ruleset that is all its own; the Windows samples stay in `default`.
    linux_group = db.get_group_by_name(LINUX_GROUP_NAME, DB_PATH)
    if not linux_group:
        linux_group = db.create_group(
            LINUX_GROUP_NAME, "Linux hosts: journal and audit rules.", DB_PATH)
        db.update_group(linux_group["id"], {
            "retention_seconds": 60,
            "poll_interval_seconds": 30,
            "destinations": [
                {"name": "siem", "url": "file://./output/siem.jsonl"},
                {"name": "data_lake", "url": "file://./output/data_lake.jsonl"},
                {"name": "alerts", "url": "file://./output/alerts.jsonl"},
            ],
        }, DB_PATH)

    def _seed_into(target: dict, chosen: dict, other_group_id: int) -> None:
        """Add the chosen seeds to `target` when missing, replace any
        non-Sigma body in place (a recomposed container self-heals without
        wiping the persisted volume), and move a sample that an earlier
        version seeded into the other group out of it."""
        by_id = {r["rule_id"]: r for r in db.list_rules(target["id"], DB_PATH)}
        for rid, info in chosen.items():
            row = by_id.get(rid)
            if row is None or not _is_sigma(row["yaml_body"]):
                db.upsert_rule(
                    rule_id=rid, group_id=target["id"], yaml_body=info["yaml"],
                    name=info["name"], severity=info["severity"], enabled=True,
                    db_path=DB_PATH,
                )
        for rid in chosen:
            db.delete_rule(rid, other_group_id, DB_PATH)

    windows_seeds = {rid: info for rid, info in seeds.items() if not rid.startswith("lin_")}
    linux_seeds = {rid: info for rid, info in seeds.items() if rid.startswith("lin_")}
    _seed_into(group, windows_seeds, linux_group["id"])
    _seed_into(linux_group, linux_seeds, group["id"])


# --- Helpers ----------------------------------------------------------------

def _rule_to_dict(r: dict) -> dict:
    """Public rule shape: parse the YAML body so the UI/agent get structured
    fields plus the raw body. Rules follow the Sigma standard.

    The YAML is authoritative for the display fields: `title` is the name,
    `description` is the description, `level` is the severity, and `status`
    drives enabled (deprecated/unsupported -> disabled). We fall back to the
    stored DB columns only when the YAML lacks the field, so the left-hand
    rule list always reflects what is saved in the YAML on the right.
    """
    out = {
        "rule_id": r["rule_id"], "group_id": r["group_id"],
        "name": r["name"], "description": r["description"],
        "severity": r["severity"], "enabled": bool(r["enabled"]),
        "yaml_body": r["yaml_body"], "updated_at": r["updated_at"],
    }
    try:
        parsed = yaml.safe_load(r["yaml_body"])
        if isinstance(parsed, dict):
            # Sigma top-level fields override the stored DB columns so the UI
            # list always reflects the YAML body.
            if parsed.get("title"):
                out["name"] = parsed.get("title")
            if parsed.get("description") is not None:
                out["description"] = parsed.get("description") or ""
            if parsed.get("level"):
                out["severity"] = parsed.get("level")
            if parsed.get("status") in ("deprecated", "unsupported"):
                out["enabled"] = False
            out["detection"] = parsed.get("detection")
            out["sigma_id"] = parsed.get("id")
            out["sigma_title"] = parsed.get("title")
            out["sigma_level"] = parsed.get("level")
            out["sigma_status"] = parsed.get("status")
            out["logsource"] = parsed.get("logsource")
            out["tags"] = parsed.get("tags", [])
            out["falsepositives"] = parsed.get("falsepositives", [])
    except Exception:
        out["detection"] = None
    return out


def _rule_to_agent_dict(r: dict) -> dict:
    """Lean rule shape for the agent config response.

    The agent only needs the rule_id (to name the on-disk file) and the raw
    yaml_body (which it writes verbatim to rules/<rule_id>.yaml and parses
    locally with its own YAML loader). Sending the parsed Sigma fields
    (detection, logsource, tags, ...) back to the agent is wasted bandwidth:
    with 2600 rules the parsed payload is several MB and exceeds the agent's
    bounded WinHTTP receive timeout (12002). `enabled` is included so the
    agent can skip disabled rules without parsing the YAML first.
    """
    return {
        "rule_id": r["rule_id"],
        "yaml_body": r["yaml_body"],
        "enabled": bool(r["enabled"]),
    }


def _rule_to_summary_dict(r: dict) -> dict:
    """Lightweight rule shape for list views (the /rules endpoint and the UI
    rule list).

    This returns ONLY the columns already stored in the DB row, with no
    yaml.safe_load() per rule. With 2600 rules the full `_rule_to_dict` parses
    2600 YAML bodies on every list refresh (2+ minutes); this summary shape
    is built from DB columns in milliseconds. The UI list only renders name,
    rule_id, severity, and enabled, all of which are DB columns.

    `sigma_id` is included (defaulting to rule_id) so the UI's secondary line
    keeps working without a YAML parse. Callers that need the full parsed
    shape (the editor, validation) fetch a single rule via GET /rules/{id}.
    """
    return {
        "rule_id": r["rule_id"],
        "group_id": r["group_id"],
        "name": r["name"] or r["rule_id"],
        "description": r["description"],
        "severity": r["severity"],
        "enabled": bool(r["enabled"]),
        "updated_at": r["updated_at"],
        "sigma_id": r["rule_id"],
    }


# --- Agent config cache + ruleset fingerprint --------------------------------
#
# The per-group ruleset is built once and cached until a rule or list
# changes, instead of running `SELECT * FROM rules` and re-serializing every
# yaml_body (several MB gzipped for a SigmaHQ import) per agent on every poll
# interval. The cache entry also carries a content hash of the ruleset. An
# agent that sends back the hash it last applied (`?known_hash=`) gets a tiny
# response with no rules at all when nothing changed, and skips its own
# rewrite/reload/resubscribe cycle.
# Group settings (retention, destinations, mirror_logs) are NOT cached; they
# are one row and may change independently of the ruleset.
_CONFIG_CACHE: dict[int, dict] = {}
_CONFIG_CACHE_LOCK = threading.Lock()


def _invalidate_config_cache(group_id: int | None = None) -> None:
    """Drop the cached ruleset for one group (or all groups when None;
    lists are global, so a list change affects every group)."""
    with _CONFIG_CACHE_LOCK:
        if group_id is None:
            _CONFIG_CACHE.clear()
        else:
            _CONFIG_CACHE.pop(group_id, None)


def _group_ruleset(group_id: int) -> dict:
    """{rules, lists, ruleset_hash} for a group, built on first use and
    cached until the next rule/list mutation. Only ENABLED rules are sent:
    a rule toggled off in the UI must not run on agents, and omitting it
    (rather than sending enabled=false) is what changes the hash."""
    with _CONFIG_CACHE_LOCK:
        entry = _CONFIG_CACHE.get(group_id)
    if entry is not None:
        return entry
    rules = [_rule_to_agent_dict(r) for r in db.list_rules(group_id, DB_PATH)
             if r.get("enabled")]
    # Reusable lists are global (shared across all groups). The agent writes
    # each to lists/<name>.txt and expands `@@name` references at rule-load
    # time. Send only name + content (the agent doesn't need timestamps).
    lists = [{"name": l["name"], "content": l["content"]}
             for l in db.list_lists(DB_PATH)]
    # Content-derived (not updated_at-derived): re-saving an identical rule
    # must not make every agent in the group reload.
    h = hashlib.sha256()
    for r in sorted(rules, key=lambda r: r["rule_id"]):
        h.update(r["rule_id"].encode("utf-8"))
        h.update(b"\x00")
        h.update(r["yaml_body"].encode("utf-8"))
        h.update(b"\n")
    h.update(b"lists\n")
    for l in sorted(lists, key=lambda l: l["name"]):
        h.update(l["name"].encode("utf-8"))
        h.update(b"\x00")
        h.update((l["content"] or "").encode("utf-8"))
        h.update(b"\n")
    entry = {"rules": rules, "lists": lists, "ruleset_hash": h.hexdigest()}
    with _CONFIG_CACHE_LOCK:
        _CONFIG_CACHE[group_id] = entry
    return entry


def _build_agent_config(agent: dict, group: dict, known_hash: str = "") -> dict:
    """Assemble the effective config + ruleset an agent should apply.

    `known_hash` is the ruleset_hash the agent last applied. When it matches
    the group's current hash the response omits `rules` and `lists` and sets
    `ruleset_unchanged: true`; the agent must treat an ABSENT `rules` key as
    "no change", never as "empty ruleset". Old agents never send a hash and
    always receive the full payload; old servers never send a hash and new
    agents fall back to full sync."""
    # Destinations are an ordered list of {name, url} on the group; flatten
    # to the {name: url} mapping the agent expects.
    destinations: dict[str, str] = {}
    for d in group.get("destinations", []):
        name = (d.get("name") or "").strip()
        url = (d.get("url") or "").strip()
        if name and url:
            destinations[name] = url

    ruleset = _group_ruleset(group["id"])
    unchanged = bool(known_hash) and known_hash == ruleset["ruleset_hash"]
    # Reboot/reinstall protection: known_agent is True when the agent has
    # contacted the server before (first_seen < last_seen). On a true first
    # install, first_seen == last_seen (both just set in register_agent).
    # The agent uses this to decide whether to resume from saved bookmarks
    # (known device rebooting) or wait for rules before collecting (fresh
    # install, no backlog to forward).
    first_seen = float(agent.get("first_seen") or 0)
    last_seen = float(agent.get("last_seen") or 0)
    known_agent = bool(first_seen and last_seen and last_seen > first_seen)
    out = {
        "agent_id": agent["agent_id"],
        "hostname": agent.get("hostname", ""),
        "group_name": group["name"],
        "known_agent": known_agent,
        "retention_seconds": group["retention_seconds"],
        "poll_interval_seconds": group["poll_interval_seconds"],
        "destinations": destinations,
        "ruleset_hash": ruleset["ruleset_hash"],
        # Per-group mirror toggle: when False the agent stops POSTing
        # forwarded-log batches (POST /logs) but still reports alerts:
        # alerts are the detection record and always mirror. Default on
        # for groups created before the column existed (None → True).
        "mirror_logs": bool(group.get("mirror_logs")) if group.get("mirror_logs") is not None else True,
    }
    if unchanged:
        out["ruleset_unchanged"] = True
    else:
        out["rules"] = ruleset["rules"]
        out["lists"] = ruleset["lists"]
    # Pending on-demand commands for this agent (e.g. "collect logs"). We
    # deliver them here (riding the existing poll) and immediately mark them
    # sent so a fast retry poll does not re-deliver. The agent ACKs by
    # POSTing a completion result to /collect/{id}/done.
    pending = db.pending_commands(agent["agent_id"], DB_PATH)
    if pending:
        import json as _json
        commands = []
        for c in pending:
            try:
                params = _json.loads(c["params"]) if c["params"] else {}
            except Exception:
                params = {}
            commands.append({
                "id": c["id"],
                "type": c["command_type"],
                "params": params,
            })
        out["commands"] = commands
        db.mark_commands_sent([c["id"] for c in pending], DB_PATH)
    return out


# --- Agents -----------------------------------------------------------------

@app.post("/agents/register")
def register_agent(body: AgentRegister) -> dict:
    # If a group_id is supplied, place the agent in that group, including
    # existing agents (so re-installing into a different group actually moves
    # the agent). When group_id is omitted (e.g. auto-registration via
    # /config), existing agents keep their current group.
    group_id = body.group_id if body.group_id is not None else 1
    update_group = body.group_id is not None
    agent = db.register_agent(body.agent_id, body.hostname, group_id=group_id,
                               ip_address=body.ip_address, os_name=body.os_name,
                               db_path=DB_PATH, update_group=update_group)
    # Mint an enrollment token so the install script can embed it in
    # config.ini. The agent then sends it as `Authorization: Bearer <token>`
    # on every subsequent request. The raw token is only returned here
    # (the DB stores only the SHA-256 hash), so the install script must
    # capture it from the response body and write it to config.ini before
    # the agent starts. Idempotent: re-registering replaces the token.
    raw_token = db.issue_agent_token(body.agent_id, DB_PATH)
    db.write_audit("system", "agent.enroll", body.agent_id,
                   {"group_id": group_id}, db_path=DB_PATH)
    agent["auth_token"] = raw_token
    return agent


@app.post("/agents/{agent_id}/reissue-token")
def reissue_agent_token(agent_id: str,
                        user: dict = Depends(_require_role("admin"))) -> dict:
    """Re-enroll an agent: mint a fresh enrollment token, replacing any
    existing one. Returns the raw token (only available once) so the admin
    can embed it in a fresh install script for the agent host. Use this to
    recover from a compromised token without touching the agent binary."""
    agent = db.get_agent(agent_id, DB_PATH)
    if not agent:
        raise HTTPException(404, "Agent not found")
    raw_token = db.issue_agent_token(agent_id, DB_PATH)
    db.write_audit("admin", "agent.reenroll", agent_id, {}, db_path=DB_PATH)
    return {"agent_id": agent_id, "auth_token": raw_token}


@app.get("/agents")
def list_agents(user: dict = Depends(_require_auth)) -> list[dict]:
    rows = db.list_agents(DB_PATH)
    # Attach the latest command summary so the UI can show a per-row status
    # badge (pending / sent / done / failed) without a second round-trip.
    for a in rows:
        cmd = db.agent_command_summary(a["agent_id"], DB_PATH)
        if cmd:
            a["pending_command"] = {
                "id": cmd["id"],
                "type": cmd["command_type"],
                "status": cmd["status"],
                "created_at": cmd["created_at"],
                "completed_at": cmd["completed_at"],
                "result": cmd["result"],
                "error": cmd["error"],
            }
        else:
            a["pending_command"] = None
    return rows


@app.get("/agents/{agent_id}")
def get_agent(agent_id: str, user: dict = Depends(_require_auth)) -> dict:
    agent = db.get_agent(agent_id, DB_PATH)
    if not agent:
        raise HTTPException(404, "Agent not found")
    return agent


@app.put("/agents/{agent_id}/group")
def assign_agent_group(agent_id: str, body: AgentGroupAssignment,
                        user: dict = Depends(_require_role("admin"))) -> dict:
    agent = db.set_agent_group(agent_id, body.group_id, DB_PATH)
    if not agent:
        raise HTTPException(404, "Agent not found")
    db.write_audit(user["username"], "agent.group", agent_id,
                   {"group_id": body.group_id}, db_path=DB_PATH)
    return agent


@app.delete("/agents/{agent_id}")
def delete_agent(agent_id: str, cascade: bool = Query(False),
                 user: dict = Depends(_require_role("admin"))) -> dict:
    ok = db.delete_agent(agent_id, DB_PATH, cascade=cascade)
    if not ok:
        raise HTTPException(404, "Agent not found")
    db.write_audit(user["username"], "agent.delete", agent_id,
                   {"cascade": cascade}, db_path=DB_PATH)
    return {"deleted": True, "cascade": cascade}


# --- Groups -----------------------------------------------------------------

@app.get("/groups")
def list_groups(user: dict = Depends(_require_auth)) -> list[dict]:
    return db.list_groups(DB_PATH)


@app.post("/groups")
def create_group(body: GroupCreate,
                 user: dict = Depends(_require_role("admin"))) -> dict:
    try:
        g = db.create_group(body.name, body.description, DB_PATH)
    except Exception as e:
        raise HTTPException(400, str(e))
    db.write_audit(user["username"], "group.create", str(g["id"]),
                   {"name": body.name}, db_path=DB_PATH)
    return g


@app.get("/groups/{group_id}")
def get_group(group_id: int, user: dict = Depends(_require_auth)) -> dict:
    g = db.get_group(group_id, DB_PATH)
    if not g:
        raise HTTPException(404, "Group not found")
    return g


@app.put("/groups/{group_id}")
def update_group(group_id: int, body: GroupUpdate,
                 user: dict = Depends(_require_role("admin"))) -> dict:
    g = db.update_group(group_id, body.model_dump(exclude_none=True), DB_PATH)
    if not g:
        raise HTTPException(404, "Group not found")
    db.write_audit(user["username"], "group.update", str(group_id),
                   {"name": g.get("name")}, db_path=DB_PATH)
    return g


@app.delete("/groups/{group_id}")
def delete_group(group_id: int,
                 user: dict = Depends(_require_role("admin"))) -> dict:
    ok = db.delete_group(group_id, DB_PATH)
    if not ok:
        raise HTTPException(400, "Cannot delete group (default group or not found)")
    _invalidate_config_cache(group_id)
    db.write_audit(user["username"], "group.delete", str(group_id), db_path=DB_PATH)
    return {"deleted": True}


# --- Rules ------------------------------------------------------------------

@app.get("/rules")
def list_rules(group_id: int | None = Query(None),
               user: dict = Depends(_require_auth)) -> list[dict]:
    # Summary shape: DB columns only, no per-rule YAML parsing. The UI list
    # only needs name/rule_id/severity/enabled. Use GET /rules/{rule_id} for
    # the full parsed shape (editor, validation). This keeps a 2600-rule list
    # responsive instead of parsing 2600 YAML bodies on every refresh.
    return [_rule_to_summary_dict(r) for r in db.list_rules(group_id, DB_PATH)]


@app.post("/rules")
def upsert_rule(body: RuleUpsert, group_id: int = Query(...),
                user: dict = Depends(_require_role("admin", "rule_contributor"))) -> dict:
    # Enforce the same validation the UI uses. Without this, a direct API
    # call (or a UI bug) could save an invalid rule that the agent would
    # then load and silently mis-handle (e.g. an unknown action type that
    # prints spurious [FORWARD] lines but never reaches the server).
    v = validate_rule_yaml({"yaml_body": body.yaml_body})
    if not v["valid"]:
        raise HTTPException(400, v["error"])
    result = _rule_to_dict(db.upsert_rule(
        body.rule_id, group_id, body.yaml_body, body.name, body.description,
        body.severity, body.enabled, DB_PATH,
    ))
    _invalidate_config_cache(group_id)
    db.write_audit(user["username"], "rule.create", body.rule_id,
                   {"group_id": group_id, "name": body.name}, db_path=DB_PATH)
    return result


@app.get("/rules/{rule_id}")
def get_rule(rule_id: str, group_id: int = Query(...),
             user: dict = Depends(_require_auth)) -> dict:
    r = db.get_rule(rule_id, group_id, DB_PATH)
    if not r:
        raise HTTPException(404, "Rule not found")
    return _rule_to_dict(r)


@app.put("/rules/{rule_id}")
def update_rule(rule_id: str, body: RuleUpsert, group_id: int = Query(...),
                user: dict = Depends(_require_role("admin", "rule_contributor"))) -> dict:
    if body.rule_id != rule_id:
        raise HTTPException(400, "rule_id in body must match path")
    # Enforce the same validation the UI uses (see POST /rules above).
    v = validate_rule_yaml({"yaml_body": body.yaml_body})
    if not v["valid"]:
        raise HTTPException(400, v["error"])
    result = _rule_to_dict(db.upsert_rule(
        rule_id, group_id, body.yaml_body, body.name, body.description,
        body.severity, body.enabled, DB_PATH,
    ))
    _invalidate_config_cache(group_id)
    db.write_audit(user["username"], "rule.upsert", rule_id,
                   {"group_id": group_id, "name": body.name}, db_path=DB_PATH)
    return result


@app.delete("/rules/{rule_id}")
def delete_rule(rule_id: str, group_id: int = Query(...),
                 user: dict = Depends(_require_role("admin", "rule_contributor"))) -> dict:
    ok = db.delete_rule(rule_id, group_id, DB_PATH)
    if not ok:
        raise HTTPException(404, "Rule not found")
    _invalidate_config_cache(group_id)
    db.write_audit(user["username"], "rule.delete", rule_id,
                   {"group_id": group_id}, db_path=DB_PATH)
    return {"deleted": True}


@app.post("/rules/bulk-delete")
def bulk_delete_rules(body: BulkRuleDelete, group_id: int = Query(...),
                      user: dict = Depends(_require_role("admin", "rule_contributor"))) -> dict:
    """Delete many rules from one group in a single transaction. The UI uses
    this for the bulk-delete flow (select rules → confirm → delete). Returns
    the count actually removed (may be less than requested if some ids no
    longer exist in the group). An empty rule_ids list is rejected so a stray
    request can't silently delete nothing."""
    if not body.rule_ids:
        raise HTTPException(400, "rule_ids must not be empty")
    deleted = db.delete_rules(body.rule_ids, group_id, DB_PATH)
    _invalidate_config_cache(group_id)
    db.write_audit(user["username"], "rule.bulk_delete", ",".join(body.rule_ids[:10]),
                   {"group_id": group_id, "count": deleted,
                    "requested": len(body.rule_ids)}, db_path=DB_PATH)
    return {"deleted": deleted, "requested": len(body.rule_ids)}


# --- Bulk rule import (Sigma zip upload + SigmaHQ fetch) --------------------
#
# These endpoints let an operator import many Sigma rules at once. Two sources
# are supported:
#
#   1. Upload a .zip of Sigma .yml files (POST /rules/import, multipart).
#   2. Fetch the SigmaHQ/sigma master branch from GitHub and import its
#      rules/windows/ folder (POST /rules/import/sigmahq).
#
# SigmaHQ rules are pure Sigma: they have no `elf:` block, so the agent would
# drop them (YamlRuleLoader rejects rules with zero actions). The import
# pipeline injects an `elf:` block into each rule based on a severity→action
# map the operator chooses in the UI (e.g. critical → alert + forward_buffer,
# high → alert, medium → forward_event, low → forward_event).
#
# Both endpoints share a two-step flow controlled by `dry_run`:
#   - dry_run=true  → validate + count only, return a preview (no DB writes).
#   - dry_run=false → validate + count + bulk upsert into the target group.
#
# The response always includes the count so the UI can show it both before
# and after the import completes.

import io
import zipfile
import urllib.request
import urllib.error

# Sigma severity levels (Sigma `level` field) in descending order of severity.
# Used to filter rules by minimum severity and to drive the severity→action
# mapping. See https://github.com/SigmaHQ/sigma-specification.
_SIGMA_LEVELS = ["critical", "high", "medium", "low", "informational"]

# SigmaHQ release assets. The default release is r2026-07-01; its assets
# are small, curated zip packages (core / core+ / core++ / all / emerging
# threats addon) published on the GitHub release page. They are listed via
# the GitHub API so the operator can pick which packages to import.
_SIGMAHQ_DEFAULT_TAG = "r2026-07-01"
_SIGMAHQ_API_BASE = "https://api.github.com/repos/SigmaHQ/sigma"

# SigmaHQ release tags are GitHub git refs. They may contain
# alphanumerics, dots, dashes, and underscores (e.g. "r2026-07-01",
# "v1.2.0", "main"). Reject anything else to prevent path-traversal / SSRF
# via the tag (it's interpolated into the GitHub API URL).
_SAFE_TAG = re.compile(r"^[A-Za-z0-9._/-]+$")


def _validate_sigmahq_tag(tag: str) -> str:
    """Validate and return a safe SigmaHQ release tag. Raises HTTPException
    on invalid input."""
    t = tag.strip()
    if not t:
        return _SIGMAHQ_DEFAULT_TAG
    if not _SAFE_TAG.match(t) or ".." in t:
        raise HTTPException(400, "Invalid release tag. Only letters, digits, "
                                 "dots, dashes, slashes, and underscores are allowed.")
    return t

# Server-side import cache. A successful *preview* stores its fully-planned
# rules (with injected elf: blocks and serialized YAML) under a random token.
# The subsequent *commit* then just writes the cached plan to the DB, so there is no need
# to re-upload the zip or re-download from SigmaHQ, which is what caused the
# "failed to fetch" errors (re-downloading 50MB / re-uploading a large zip on
# commit would time out the request). Entries expire after 30 minutes.
_IMPORT_CACHE: dict[str, dict] = {}
_IMPORT_CACHE_TTL = 30 * 60  # seconds


def _import_cache_store(plan: dict, group_id: int) -> str:
    """Store a planned import under a random token and return the token."""
    import secrets
    token = secrets.token_urlsafe(16)
    _IMPORT_CACHE[token] = {
        "plan": plan,
        "group_id": group_id,
        "ts": time.time(),
    }
    _import_cache_sweep()
    return token


def _import_cache_get(token: str) -> dict | None:
    """Return the cached import for `token`, or None if missing/expired."""
    entry = _IMPORT_CACHE.get(token)
    if not entry:
        return None
    if time.time() - entry["ts"] > _IMPORT_CACHE_TTL:
        _IMPORT_CACHE.pop(token, None)
        return None
    return entry


def _import_cache_sweep() -> None:
    """Drop expired entries to keep the cache from growing unbounded."""
    now = time.time()
    expired = [t for t, e in _IMPORT_CACHE.items() if now - e["ts"] > _IMPORT_CACHE_TTL]
    for t in expired:
        _IMPORT_CACHE.pop(t, None)


def _parse_sigma_rules_from_zip(raw: bytes) -> list[dict]:
    """Parse every .yml/.yaml file inside a zip archive into a list of
    Sigma-rule dicts. A single YAML file may contain multiple documents
    (yaml.safe_load_all). Non-mapping documents are skipped. Returns a list
    of {file, doc} where `doc` is the parsed Sigma mapping.
    """
    out: list[dict] = []
    try:
        zf = zipfile.ZipFile(io.BytesIO(raw))
    except zipfile.BadZipFile as e:
        raise ValueError(f"Not a valid zip archive: {e}")
    for name in zf.namelist():
        # Skip directories and non-YAML files.
        lower = name.lower()
        if not (lower.endswith(".yml") or lower.endswith(".yaml")):
            continue
        try:
            data = zf.read(name)
        except Exception:
            continue
        text = data.decode("utf-8", errors="replace")
        try:
            for doc in yaml.safe_load_all(text):
                if isinstance(doc, dict):
                    out.append({"file": name, "doc": doc, "raw": text})
        except yaml.YAMLError:
            # Skip files that don't parse; they'll show up as "skipped" in
            # the count since they never enter the list.
            continue
    return out


def _build_elf_block(actions: list[dict]) -> dict:
    """Build an `elf:` block dict from a list of action dicts. Each action is
    {type, destination, message?}. Returns the block ready to merge into a
    Sigma rule under the `elf:` key."""
    block: dict = {"actions": actions}
    return block


def _inject_elf_block(doc: dict, elf_block: dict) -> dict:
    """Return a copy of `doc` with the given `elf:` block merged in. If the
    rule already has an `elf:` block, its actions are REPLACED (the operator's
    chosen mapping takes precedence over whatever was in the file)."""
    out = dict(doc)
    out["elf"] = dict(elf_block)
    return out


def _sigma_level(doc: dict) -> str:
    """Return the Sigma `level` of a parsed rule, lowercased, defaulting to
    'medium' when absent."""
    lvl = doc.get("level", "medium")
    return str(lvl).strip().lower() if isinstance(lvl, str) else "medium"


def _sigma_logsource_product(doc: dict) -> str:
    """Return the logsource.product (e.g. 'windows') lowercased, or '' if
    absent. Used by the logsource filter."""
    ls = doc.get("logsource")
    if not isinstance(ls, dict):
        return ""
    p = ls.get("product", "")
    return str(p).strip().lower() if isinstance(p, str) else ""


def _sigma_logsource_category(doc: dict) -> str:
    """Return the logsource.category lowercased, or '' if absent."""
    ls = doc.get("logsource")
    if not isinstance(ls, dict):
        return ""
    c = ls.get("category", "")
    return str(c).strip().lower() if isinstance(c, str) else ""


def _rule_id_from_doc(doc: dict) -> str | None:
    """Return the Sigma `id` (used as the database rule_id), or None."""
    rid = doc.get("id")
    if not isinstance(rid, str) or not rid.strip():
        return None
    return rid.strip()


def _filter_and_plan(parsed: list[dict],
                     severity_map: dict[str, list[dict]],
                     min_severity: str,
                     logsource_filter: str,
                     overwrite: bool,
                     group_id: int) -> dict:
    """Filter the parsed Sigma rules and build an import plan.

    severity_map: {severity: [action dicts]}, the operator's chosen actions
        per severity. A severity is only imported if it has at least one
        action in this map (checkboxes ensure this in the UI).
    min_severity: only import rules with level >= this (critical > high >
        medium > low > informational).
    logsource_filter: only import rules whose logsource.product matches this
        (e.g. 'windows'). Empty string = no filter.
    overwrite: if True, existing rules in the target group are replaced; if
        False, existing rules are skipped (counted as 'skipped_existing').
    group_id: the target group (used to check for existing rules).

    Returns a dict with:
      planned:   [{rule_id, name, severity, file, yaml_body}]  rules to import
      skipped_no_id: int      rules missing a Sigma id
      skipped_severity: int   rules below min_severity or with no action map
      skipped_logsource: int  rules not matching the logsource filter
      skipped_existing: int   rules already in the group (overwrite=False)
      skipped_invalid: int    rules that fail server validation after injection
      skipped_duplicate: int  later copies of a rule id already planned
      errors:    [{file, error}]  per-rule validation errors
    """
    # Pre-fetch existing rule_ids in the target group for the overwrite check.
    existing_ids: set[str] = set()
    if not overwrite:
        existing_ids = {r["rule_id"] for r in db.list_rules(group_id, DB_PATH)}

    min_idx = _SIGMA_LEVELS.index(min_severity) if min_severity in _SIGMA_LEVELS else 0

    planned: list[dict] = []
    skipped_no_id = 0
    skipped_severity = 0
    skipped_logsource = 0
    skipped_existing = 0
    skipped_invalid = 0
    skipped_duplicate = 0
    errors: list[dict] = []
    # The SigmaHQ release packages nest (core ⊂ core+ ⊂ core++ ⊂ all), so
    # selecting several yields the same rule id many times; a zip can carry
    # the same rule under two paths too. The first occurrence wins and the
    # rest are counted, so the preview reports unique rules.
    seen_ids: set[str] = set()

    for entry in parsed:
        doc = entry["doc"]
        fname = entry["file"]

        rid = _rule_id_from_doc(doc)
        if not rid:
            skipped_no_id += 1
            continue
        if rid in seen_ids:
            skipped_duplicate += 1
            continue
        seen_ids.add(rid)

        # Logsource filter.
        if logsource_filter:
            product = _sigma_logsource_product(doc)
            if product != logsource_filter.lower():
                skipped_logsource += 1
                continue

        # Severity filter: only import severities the operator mapped to at
        # least one action, AND that are >= min_severity.
        lvl = _sigma_level(doc)
        if lvl not in severity_map or not severity_map[lvl]:
            skipped_severity += 1
            continue
        if lvl in _SIGMA_LEVELS and _SIGMA_LEVELS.index(lvl) > min_idx:
            skipped_severity += 1
            continue

        # Overwrite check.
        if not overwrite and rid in existing_ids:
            skipped_existing += 1
            continue

        # Inject the elf: block and re-serialize to YAML.
        actions = severity_map[lvl]
        elf_block = _build_elf_block(actions)
        injected = _inject_elf_block(doc, elf_block)
        try:
            yaml_body = yaml.safe_dump(injected, sort_keys=False, allow_unicode=True)
        except Exception as e:
            skipped_invalid += 1
            errors.append({"file": fname, "rule_id": rid,
                           "error": f"YAML serialize failed: {e}"})
            continue

        # Validate the injected rule through the same validator the UI uses.
        v = validate_rule_yaml({"yaml_body": yaml_body})
        if not v["valid"]:
            skipped_invalid += 1
            errors.append({"file": fname, "rule_id": rid, "error": v["error"]})
            continue

        planned.append({
            "rule_id": rid,
            "name": doc.get("title", rid),
            "severity": lvl,
            "file": fname,
            "yaml_body": yaml_body,
        })

    return {
        "planned": planned,
        "skipped_no_id": skipped_no_id,
        "skipped_severity": skipped_severity,
        "skipped_logsource": skipped_logsource,
        "skipped_existing": skipped_existing,
        "skipped_invalid": skipped_invalid,
        "skipped_duplicate": skipped_duplicate,
        "errors": errors,
    }


def _commit_plan(planned: list[dict], group_id: int) -> int:
    """Upsert every planned rule into the target group in ONE transaction.
    Returns the number written (all of them, or 0 if the transaction
    failed; it is all-or-nothing so an agent polling mid-import never
    receives a partial ruleset). A failure is logged and surfaced through
    the returned count (0 written), not swallowed per rule as before."""
    rows = [{
        "rule_id": p["rule_id"], "yaml_body": p["yaml_body"],
        "name": p["name"], "description": "", "severity": p["severity"],
        "enabled": True,
    } for p in planned]
    try:
        written = db.upsert_rules_bulk(rows, group_id, DB_PATH)
    except Exception as e:  # noqa: BLE001 - report, don't crash the request
        log.error("rule import commit failed for group %s: %s", group_id, e)
        return 0
    _invalidate_config_cache(group_id)
    return written


def _import_response(plan: dict, dry_run: bool, written: int,
                     commit_token: str = "") -> dict:
    """Shape the JSON response for both the upload and sigmahq endpoints.

    `commit_token` is set on a successful *preview* (dry_run=true) so the UI
    can commit the cached plan without re-uploading/re-downloading the source.
    """
    return {
        "dry_run": dry_run,
        "planned": len(plan["planned"]),
        "written": written,
        "skipped_no_id": plan["skipped_no_id"],
        "skipped_severity": plan["skipped_severity"],
        "skipped_logsource": plan["skipped_logsource"],
        "skipped_existing": plan["skipped_existing"],
        "skipped_invalid": plan["skipped_invalid"],
        "skipped_duplicate": plan.get("skipped_duplicate", 0),
        "errors": plan["errors"][:50],  # cap the error list for the response
        "total_errors": len(plan["errors"]),
        "commit_token": commit_token,
        # Include a small preview of the first few planned rules so the UI
        # can show a table before the user commits.
        "preview": [
            {"rule_id": p["rule_id"], "name": p["name"],
             "severity": p["severity"], "file": p["file"]}
            for p in plan["planned"][:25]
        ],
    }


@app.post("/rules/import")
async def import_rules_zip(file: UploadFile = File(...),
                            group_id: int = Query(...),
                            dry_run: bool = Query(True),
                            min_severity: str = Query("low"),
                            logsource_filter: str = Query("windows"),
                            overwrite: bool = Query(False),
                            severity_map: str = Query(""),
                            user: dict = Depends(_require_role("admin", "rule_contributor"))):
    """Import Sigma rules from an uploaded .zip archive.

    The zip should contain .yml/.yaml Sigma rule files (possibly nested in
    folders, e.g. rules/windows/process_creation/...). Each rule gets an
    `elf:` block injected based on `severity_map` (a JSON string mapping
    severity → list of action dicts, e.g.
    `{"critical":[{"type":"alert","destination":"alerts"}],...}`).

    With `dry_run=true` (the default), the endpoint validates and counts
    without writing anything; the UI calls this first to show a preview.
    With `dry_run=false`, the planned rules are upserted into the target
    group.

    Returns counts of planned/skipped/invalid rules plus a preview list.
    """
    import json as _json
    try:
        smap = _json.loads(severity_map) if severity_map else {}
    except _json.JSONDecodeError as e:
        raise HTTPException(400, f"severity_map is not valid JSON: {e}")
    if not isinstance(smap, dict):
        raise HTTPException(400, "severity_map must be a JSON object.")
    # Normalize the map keys to lowercase.
    severity_map_norm: dict[str, list[dict]] = {}
    for k, v in smap.items():
        severity_map_norm[str(k).lower()] = v if isinstance(v, list) else []

    # Read the uploaded zip into memory (rules zips are small; the agent
    # binary upload uses chunked reads because the exe is ~900KB, but a
    # rules zip is typically a few MB). Enforce a size ceiling to prevent
    # memory-exhaustion DoS.
    raw = await file.read()
    if not raw:
        raise HTTPException(400, "Uploaded file is empty.")
    if len(raw) > MAX_RULES_ZIP_BYTES:
        raise HTTPException(413, f"Zip too large. Limit is "
                                 f"{MAX_RULES_ZIP_BYTES // (1024*1024)} MB.")
    try:
        parsed = _parse_sigma_rules_from_zip(raw)
    except ValueError as e:
        raise HTTPException(400, str(e))

    plan = _filter_and_plan(parsed, severity_map_norm, min_severity,
                            logsource_filter, overwrite, group_id)
    written = 0
    commit_token = ""
    if dry_run:
        # Cache the plan so the commit step doesn't need to re-upload the zip.
        commit_token = _import_cache_store(plan, group_id)
    else:
        written = _commit_plan(plan["planned"], group_id)
    db.write_audit(user["username"], "rule.import.zip", "",
                   {"group_id": group_id, "dry_run": dry_run,
                    "planned": plan.get("planned_count", 0),
                    "written": written}, db_path=DB_PATH)
    return _import_response(plan, dry_run, written, commit_token)


@app.post("/rules/import/sigmahq")
def import_rules_sigmahq(group_id: int = Query(...),
                         user: dict = Depends(_require_role("admin", "rule_contributor")),
                         dry_run: bool = Query(True),
                         min_severity: str = Query("low"),
                         logsource_filter: str = Query("windows"),
                         overwrite: bool = Query(False),
                         severity_map: str = Query(""),
                         assets: str = Query(""),
                         tag: str = Query("")):
    """Fetch one or more SigmaHQ release assets and import their rules.

    `assets` is a comma-separated list of asset names (e.g.
    "sigma_core.zip,sigma_emerging_threats_addon.zip") from the release
    identified by `tag` (default r2026-07-01). Each named asset is downloaded
    from the GitHub release, parsed, and merged. The logsource_filter is
    applied as a second layer (the release packages are already curated, so
    "windows" is a sensible default but not strictly required).

    With `dry_run=true` (the default), the endpoint validates and counts
    without writing; the UI calls this first to show a preview. The plan is
    cached server-side and the response carries a `commit_token` so the
    commit step doesn't re-download.

    Same response shape as POST /rules/import.
    """
    import json as _json
    try:
        smap = _json.loads(severity_map) if severity_map else {}
    except _json.JSONDecodeError as e:
        raise HTTPException(400, f"severity_map is not valid JSON: {e}")
    if not isinstance(smap, dict):
        raise HTTPException(400, "severity_map must be a JSON object.")
    severity_map_norm: dict[str, list[dict]] = {}
    for k, v in smap.items():
        severity_map_norm[str(k).lower()] = v if isinstance(v, list) else []

    rel_tag = _validate_sigmahq_tag(tag)
    asset_names = [a.strip() for a in assets.split(",") if a.strip()]
    if not asset_names:
        raise HTTPException(400, "No assets selected. Choose at least one "
                                 "release asset to import.")

    # Resolve the requested asset names to download URLs via the GitHub API.
    try:
        asset_urls = _sigmahq_resolve_assets(rel_tag, asset_names)
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(502, f"Failed to list SigmaHQ release assets: {e}")

    # Download each selected asset and merge the parsed rules. The release
    # packages are small (<= ~3MB each), so we read each fully into memory.
    parsed: list[dict] = []
    for name, url in asset_urls:
        req = urllib.request.Request(
            url, headers={"User-Agent": "ELF-management-server/1.0"})
        try:
            with urllib.request.urlopen(req, timeout=120) as resp:
                raw = resp.read()
        except urllib.error.URLError as e:
            raise HTTPException(502, f"Failed to download {name}: {e}")
        except Exception as e:
            raise HTTPException(502, f"Failed to download {name}: {e}")
        try:
            parsed.extend(_parse_sigma_rules_from_zip(raw))
        except ValueError as e:
            raise HTTPException(400, f"{name}: {e}")

    plan = _filter_and_plan(parsed, severity_map_norm, min_severity,
                            logsource_filter, overwrite, group_id)
    written = 0
    commit_token = ""
    if dry_run:
        # Cache the plan so the commit step doesn't re-download the assets.
        commit_token = _import_cache_store(plan, group_id)
    else:
        written = _commit_plan(plan["planned"], group_id)
    db.write_audit(user["username"], "rule.import.sigmahq", "",
                   {"group_id": group_id, "dry_run": dry_run, "tag": rel_tag,
                    "assets": asset_names,
                    "planned": plan.get("planned_count", 0),
                    "written": written}, db_path=DB_PATH)
    return _import_response(plan, dry_run, written, commit_token)


@app.get("/rules/import/sigmahq/assets")
def list_sigmahq_assets(tag: str = Query("")) -> dict:
    """List the release assets for a SigmaHQ release tag (default
    r2026-07-01) so the UI can render a checkbox picker. Returns
    {tag, assets: [{name, size, download_url}]}.
    """
    rel_tag = _validate_sigmahq_tag(tag)
    url = f"{_SIGMAHQ_API_BASE}/releases/tags/{rel_tag}"
    req = urllib.request.Request(
        url, headers={"User-Agent": "ELF-management-server/1.0",
                      "Accept": "application/vnd.github+json"})
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            import json as _json
            data = _json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        raise HTTPException(502, f"GitHub API error {e.code}: {e.reason}")
    except Exception as e:
        raise HTTPException(502, f"Failed to query GitHub release API: {e}")
    assets = []
    for a in data.get("assets", []):
        assets.append({
            "name": a.get("name", ""),
            "size": a.get("size", 0),
            "download_url": a.get("browser_download_url", ""),
        })
    return {"tag": rel_tag, "assets": assets}


def _sigmahq_resolve_assets(tag: str, names: list[str]) -> list[tuple[str, str]]:
    """Resolve a list of asset names to (name, download_url) pairs for the
    given release tag. Raises HTTPException if the release can't be queried
    or a requested name isn't found."""
    url = f"{_SIGMAHQ_API_BASE}/releases/tags/{tag}"
    req = urllib.request.Request(
        url, headers={"User-Agent": "ELF-management-server/1.0",
                      "Accept": "application/vnd.github+json"})
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            import json as _json
            data = _json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        raise HTTPException(502, f"GitHub API error {e.code}: {e.reason}")
    except Exception as e:
        raise HTTPException(502, f"Failed to query GitHub release API: {e}")
    by_name = {a.get("name", ""): a.get("browser_download_url", "")
               for a in data.get("assets", [])}
    out: list[tuple[str, str]] = []
    missing: list[str] = []
    for n in names:
        if n in by_name and by_name[n]:
            out.append((n, by_name[n]))
        else:
            missing.append(n)
    if missing:
        raise HTTPException(400, f"Asset(s) not found in release {tag}: "
                                 f"{', '.join(missing)}")
    return out


@app.post("/rules/import/commit")
def commit_import(body: dict,
                  user: dict = Depends(_require_role("admin", "rule_contributor"))) -> dict:
    """Commit a previously-previewed import using its cached plan.

    Body: {commit_token: str}. The token was returned by a successful preview
    (POST /rules/import or /rules/import/sigmahq with dry_run=true). The
    cached plan is written to the DB and the cache entry is consumed.

    This avoids re-uploading the zip / re-downloading from SigmaHQ on commit,
    which is what caused the "failed to fetch" errors when the commit
    request timed out.
    """
    token = body.get("commit_token") if isinstance(body, dict) else None
    if not token or not isinstance(token, str):
        raise HTTPException(400, "commit_token is required.")
    entry = _import_cache_get(token)
    if not entry:
        raise HTTPException(404, "Import preview expired or not found. "
                                  "Run the preview again.")
    plan = entry["plan"]
    group_id = entry["group_id"]
    written = _commit_plan(plan["planned"], group_id)
    # Consume the cache entry so a token can't be committed twice.
    _IMPORT_CACHE.pop(token, None)
    db.write_audit(user["username"], "rule.import.commit", "",
                   {"group_id": group_id, "written": written}, db_path=DB_PATH)
    return _import_response(plan, False, written, "")


# --- Lists (reusable value lists, global across all groups) -----------------

@app.get("/lists")
def list_lists(user: dict = Depends(_require_auth)) -> list[dict]:
    return db.list_lists(DB_PATH)


@app.post("/lists")
def create_list(body: ListUpsert,
                user: dict = Depends(_require_role("admin", "rule_contributor"))) -> dict:
    if not body.name.strip():
        raise HTTPException(400, "List name must not be empty.")
    # Reject names that aren't safe filenames (the agent writes <name>.txt).
    if not _is_safe_filename(body.name):
        raise HTTPException(400, "List name must be a safe filename (letters, digits, dash, underscore, dot).")
    existing = db.get_list(body.name, DB_PATH)
    if existing:
        raise HTTPException(409, f"A list named '{body.name}' already exists.")
    result = db.upsert_list(body.name, body.content, DB_PATH)
    _invalidate_config_cache()  # lists are global: every group's hash changes
    db.write_audit(user["username"], "list.create", body.name, db_path=DB_PATH)
    return result


@app.get("/lists/{name}")
def get_list(name: str, user: dict = Depends(_require_auth)) -> dict:
    l = db.get_list(name, DB_PATH)
    if not l:
        raise HTTPException(404, "List not found")
    return l


@app.put("/lists/{name}")
def update_list(name: str, body: ListUpsert,
                user: dict = Depends(_require_role("admin", "rule_contributor"))) -> dict:
    if body.name != name:
        raise HTTPException(400, "List name in body must match path.")
    existing = db.get_list(name, DB_PATH)
    if not existing:
        raise HTTPException(404, "List not found")
    result = db.upsert_list(name, body.content, DB_PATH)
    _invalidate_config_cache()
    db.write_audit(user["username"], "list.update", name, db_path=DB_PATH)
    return result


@app.delete("/lists/{name}")
def delete_list(name: str,
                user: dict = Depends(_require_role("admin", "rule_contributor"))) -> dict:
    ok = db.delete_list(name, DB_PATH)
    if not ok:
        raise HTTPException(404, "List not found")
    _invalidate_config_cache()
    db.write_audit(user["username"], "list.delete", name, db_path=DB_PATH)
    return {"deleted": True}


# --- Agent enrollment-token auth --------------------------------------------
#
# Agent-facing endpoints (GET /config, POST /alerts, POST /logs, POST
# /collect/*) require a per-agent enrollment token sent as
# `Authorization: Bearer <token>`. The token is minted by the install
# script (or POST /agents/register) and stored as a SHA-256 hash in the
# agent_tokens table. This is machine auth: it proves the agent binary
# was deployed via an install script generated by this server, not a
# rogue process impersonating an agent_id.
#
# Backward-compat grace: an agent that has NO token row in the DB is
# allowed through (with an auth.legacy audit event) unless
# ELF_REQUIRE_AGENT_TOKEN=1. This lets existing agents keep working
# until they're re-enrolled via the install script or the Re-enroll
# button. Once an agent HAS a token row, it must send the correct token
# (a wrong or missing token gets 401 regardless of the grace flag).

def _bearer_token(request: Request) -> str:
    """Extract the raw bearer token from the Authorization header, or ''."""
    auth = request.headers.get("authorization", "")
    if not auth.lower().startswith("bearer "):
        return ""
    return auth[7:].strip()


def _enforce_agent_token(agent_id: str, request: Request) -> None:
    """Verify the agent's enrollment token. Raises HTTPException(401) on
    failure. Allows agents with no token row through during the grace
    period (unless ELF_REQUIRE_AGENT_TOKEN=1), logging auth.legacy."""
    token = _bearer_token(request)
    has_row = db.agent_has_token(agent_id, DB_PATH)
    if has_row:
        # Agent has been enrolled: it must present the correct token.
        if not db.verify_agent_token(agent_id, token, DB_PATH):
            db.write_audit(f"agent:{agent_id}", "auth.deny", agent_id,
                           {"reason": "bad_token", "has_token": True}, db_path=DB_PATH)
            raise HTTPException(401, "Invalid or missing agent token")
        db.write_audit(f"agent:{agent_id}", "auth.ok", agent_id, db_path=DB_PATH)
    else:
        # No token row yet, so this is a legacy agent. Allow unless tokens are forced.
        if REQUIRE_AGENT_TOKEN:
            db.write_audit(f"agent:{agent_id}", "auth.deny", agent_id,
                           {"reason": "no_token", "has_token": False}, db_path=DB_PATH)
            raise HTTPException(401, "Agent enrollment required")
        # Grace: log once per request so the operator can see which agents
        # still need re-enrolling. (Not deduped to keep it simple.)
        db.write_audit(f"agent:{agent_id}", "auth.legacy", agent_id, db_path=DB_PATH)


# --- Agent-facing -----------------------------------------------------------

@app.get("/config/{agent_id}")
def get_agent_config(request: Request,
                     agent_id: str,
                     hostname: str = Query(""),
                     ip: str = Query(""),
                     os: str = Query(""),
                     events_created: int = Query(0),
                     bytes_created: int = Query(0),
                     events_forwarded: int = Query(0),
                     bytes_forwarded: int = Query(0),
                     known_hash: str = Query("", max_length=128)) -> dict:
    """The main endpoint the C++ agent polls. Registers/touches the agent,
    returns its effective config + ruleset. The agent sends its detected
    hostname, IP address, OS name, and cumulative event/byte counters as
    query params so the server can store them for display in the UI.
    `known_hash` (optional) is the ruleset_hash the agent last applied;
    when it still matches, the rules/lists are omitted from the response."""
    _enforce_agent_token(agent_id, request)
    agent = db.get_agent(agent_id, DB_PATH)
    if not agent:
        # Auto-register on first contact so the agent doesn't need a separate
        # registration step.
        agent = db.register_agent(agent_id, hostname=hostname, ip_address=ip,
                                   os_name=os,
                                   events_created=events_created,
                                   bytes_created=bytes_created,
                                   events_forwarded=events_forwarded,
                                   bytes_forwarded=bytes_forwarded,
                                   db_path=DB_PATH)
    else:
        db.touch_agent(agent_id, hostname=hostname, ip_address=ip,
                       os_name=os,
                       events_created=events_created,
                       bytes_created=bytes_created,
                       events_forwarded=events_forwarded,
                       bytes_forwarded=bytes_forwarded,
                       db_path=DB_PATH)
    group = db.get_group(agent["group_id"], DB_PATH)
    if not group:
        # The agent's group was deleted out from under it (e.g. via direct DB
        # edit, or a race during deletion). Reassign to the default group so
        # the agent gets a valid ruleset and the orphaned group_id is
        # persisted-corrected rather than re-detected on every poll.
        agent = db.set_agent_group(agent_id, 1, DB_PATH)
        group = db.get_group(1, DB_PATH)
    return _build_agent_config(agent, group, known_hash)


@app.post("/alerts")
def report_alert(request: Request, body: AlertReport, agent_id: str = Query(...)) -> dict:
    _enforce_agent_token(agent_id, request)
    payload = body.model_dump()
    payload["agent_id"] = agent_id
    rid = db.store_alert(agent_id, payload, DB_PATH)
    return {"stored": True, "id": rid}


@app.post("/logs")
def report_logs(request: Request, body: LogReport, agent_id: str = Query(...)) -> dict:
    _enforce_agent_token(agent_id, request)
    payload = body.model_dump()
    payload["agent_id"] = agent_id
    rid = db.store_logs(agent_id, payload, DB_PATH)
    # Also append to the newline-separated text file for review.
    db.append_logs_text(agent_id, payload, DB_PATH)
    return {"stored": True, "id": rid}


# --- On-demand log collection (collect logs) -------------------------------
#
# An analyst can request "send me all events from this host since <date>" from
# the Agents tab. The server queues a `collect_logs` command; the agent
# receives it on its next poll (via the `commands` array in /config), opens a
# time-bounded EvtQuery against every channel, and streams the events back in
# batches. Collected events are stored in the existing forwarded_logs table
# with rule_id='__collect__' so they appear in the Logs tab without a new
# table, and appended to logs.txt for the raw text view. They bypass the rule
# engine entirely (no re-detection, no metrics inflation).

COLLECT_RULE_ID = "__collect__"


def _normalize_start_time_to_utc(start_time: str) -> str:
    """Normalize a start_time string to an ISO-8601 UTC string suitable for
    the agent's EvtQuery XPath. Accepts a naive local time (treated as UTC for
    simplicity: the server runs in a container and the agent's query uses
    SystemTime which is UTC) or an offset-bearing string."""
    from datetime import datetime, timezone
    if not start_time:
        raise HTTPException(400, "start_time is required")
    # Try offset-aware parse first, then naive (assume UTC).
    try:
        dt = datetime.fromisoformat(start_time)
    except Exception:
        raise HTTPException(400, "start_time must be ISO-8601 (e.g. 2026-10-01T00:00:00)")
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")


@app.post("/agents/{agent_id}/collect")
def create_collect_command(agent_id: str, body: CollectRequest,
                           user: dict = Depends(_require_auth)) -> dict:
    """Queue a collect-logs command for an agent. The agent pulls historical
    events with TimeCreated >= start_time on its next poll."""
    agent = db.get_agent(agent_id, DB_PATH)
    if not agent:
        raise HTTPException(404, "Agent not found")
    start_utc = _normalize_start_time_to_utc(body.start_time)
    cmd = db.create_command(agent_id, "collect_logs",
                            {"start_time": start_utc}, DB_PATH)
    db.write_audit(user["username"], "collect.create", str(cmd["id"]),
                   {"agent_id": agent_id, "start_time": start_utc},
                   db_path=DB_PATH)
    return {"command_id": cmd["id"], "status": cmd["status"],
            "start_time": start_utc}


@app.post("/collect/{command_id}")
def report_collect_batch(request: Request, command_id: int, body: CollectBatch) -> dict:
    """Receive one streamed batch of collected events. Stored in
    forwarded_logs with rule_id='__collect__' so it shows up in the Logs tab
    and the raw text view without a new table."""
    _enforce_agent_token(body.agent_id, request)
    cmd = db.get_command(command_id, DB_PATH)
    if not cmd:
        raise HTTPException(404, "Command not found")
    if cmd["status"] not in ("sent", "done"):
        # Accept batches for a sent command; also tolerate late batches that
        # arrive after the done marker (race between the last batch and the
        # done POST). Reject for a failed/pending command.
        if cmd["status"] == "failed":
            raise HTTPException(409, "Command already failed")
    payload = body.model_dump()
    payload["rule_id"] = COLLECT_RULE_ID
    rid = db.store_logs(body.agent_id, payload, DB_PATH)
    db.append_logs_text(body.agent_id, payload, DB_PATH)
    return {"stored": True, "id": rid}


@app.post("/collect/{command_id}/done")
def complete_collect_command(request: Request, command_id: int, body: CollectDone) -> dict:
    """Mark a collect command done or failed. The agent posts this after the
    historical pull finishes (or errors out)."""
    _enforce_agent_token(body.agent_id, request)
    cmd = db.get_command(command_id, DB_PATH)
    if not cmd:
        raise HTTPException(404, "Command not found")
    status = body.status if body.status in ("done", "failed") else "done"
    result = {
        "events_collected": body.events_collected,
        "batches": body.batches,
    }
    db.complete_command(command_id, status, result, body.error, DB_PATH)
    return {"ok": True, "status": status}


# --- Agent binary distribution (offline install) ----------------------------

def _binary_os(value: str) -> str:
    """Normalize the ?os= query of the binary and script endpoints."""
    v = (value or "windows").strip().lower()
    if v not in AGENT_BINARY_NAMES:
        raise HTTPException(400, "os must be 'windows' or 'linux'")
    return v


def _agent_binary_path(target_os: str = "windows") -> str:
    return os.path.join(AGENT_BINARY_DIR, AGENT_BINARY_NAMES[target_os])


def _resolve_public_base(request: Request) -> str:
    """The base URL new agents should contact to download the binary and poll
    for config. ELF_PUBLIC_HOST overrides auto-detection so a container behind
    port mapping can advertise the Docker host's IP."""
    host = AGENT_PUBLIC_HOST or request.url.hostname or "localhost"
    port = AGENT_PUBLIC_PORT
    # Omit the port if it's the default for the scheme.
    if port == 80:
        return f"http://{host}"
    return f"http://{host}:{port}"


@app.get("/agent/binary")
def download_agent_binary(target_os: str = Query("windows", alias="os")):
    """Download the prebuilt agent executable for ?os=windows (default) or
    ?os=linux. Used by the generated install scripts so new hosts never
    reach out to the internet.

    No auth: the install script runs on a REMOTE Windows host that does NOT
    have the admin's session cookie, so _require_auth would 401 the very
    first step (downloading the binary). This is consistent with the other
    install-time endpoints (POST /agents/register, GET /agent/lsa-helper)
    which are also unauthenticated for the same reason. The binary itself
    is not secret; it's the same binary for every host."""
    target_os = _binary_os(target_os)
    path = _agent_binary_path(target_os)
    if not os.path.isfile(path):
        raise HTTPException(
            404,
            f"Agent binary for {target_os} not found on the server. Rebuild "
            f"the Docker image with server/agent/{AGENT_BINARY_NAMES[target_os]} "
            "staged and redeploy.",
        )
    return FileResponse(
        path,
        media_type="application/octet-stream",
        filename=AGENT_BINARY_NAMES[target_os],
    )


@app.get("/agent/binary/status")
def agent_binary_status(user: dict = Depends(_require_auth),
                        target_os: str = Query("windows", alias="os")):
    """Report whether the binary for ?os= is available (used by the UI)."""
    target_os = _binary_os(target_os)
    path = _agent_binary_path(target_os)
    exists = os.path.isfile(path)
    return JSONResponse({
        "available": exists,
        "os": target_os,
        "name": AGENT_BINARY_NAMES[target_os],
        "bytes": os.path.getsize(path) if exists else 0,
    }, headers={
        "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
        "Pragma": "no-cache",
    })


# --- LSA privilege helpers (served as downloadable C# source) -------------
# The install + cleanup scripts download this ~6KB C# helper from the server
# rather than embedding it base64-encoded in the one-liner. An inline copy
# pushes the one-liner to ~10KB, which some terminals/clipboards corrupt on
# paste (mangled characters break Add-Type and thus the SeServiceLogonRight
# grant → service 1069 logon failure). Serving the C# as a small downloadable
# file keeps the one-liner short and avoids that corruption entirely.

_LSA_GRANT_CS = r'''
using System;
using System.Runtime.InteropServices;
using System.Text;
public class LsaGrant {
  [DllImport("advapi32.dll",PreserveSig=false)]
  public static extern uint LsaOpenPolicy(IntPtr sa, ref LSA_OBJECT_ATTRIBUTES oa, uint access, out IntPtr handle);
  [DllImport("advapi32.dll",PreserveSig=false)]
  public static extern uint LsaAddAccountRights(IntPtr handle, IntPtr sid, LSA_UNICODE_STRING[] rights, uint count);
  [DllImport("advapi32.dll")] public static extern int LsaClose(IntPtr handle);
  [DllImport("advapi32.dll",CharSet=CharSet.Unicode)]
  public static extern bool LookupAccountName(string sys, string acc, byte[] sid, ref int sidLen, StringBuilder dom, ref int domLen, ref int use);
  [StructLayout(LayoutKind.Sequential)]
  public struct LSA_OBJECT_ATTRIBUTES { public int Length; public IntPtr RootDirectory; public LSA_UNICODE_STRING ObjectName; public uint Attributes; public IntPtr SecurityDescriptor; public IntPtr SecurityQualityOfService; }
  [StructLayout(LayoutKind.Sequential)]
  public struct LSA_UNICODE_STRING { public ushort Length; public ushort MaxLength; public IntPtr Buffer; }
  public static void Grant(string account, string right) {
    byte[] sid=new byte[256]; int sidLen=sid.Length, domLen=128; StringBuilder dom=new StringBuilder(domLen); int use=0;
    if (!LookupAccountName(null, account, sid, ref sidLen, dom, ref domLen, ref use)) throw new Exception("LookupAccountName failed");
    byte[] sidBytes=new byte[sidLen]; Array.Copy(sid, sidBytes, sidLen);
    IntPtr sidPtr=Marshal.AllocHGlobal(sidBytes.Length); Marshal.Copy(sidBytes, 0, sidPtr, sidBytes.Length);
    LSA_OBJECT_ATTRIBUTES oa=new LSA_OBJECT_ATTRIBUTES(); oa.Length=Marshal.SizeOf(oa); IntPtr handle;
    uint status=LsaOpenPolicy(IntPtr.Zero, ref oa, 0x810, out handle);
    if (status!=0) throw new Exception("LsaOpenPolicy failed: 0x"+status.ToString("X"));
    LSA_UNICODE_STRING r=new LSA_UNICODE_STRING(); r.Length=(ushort)(right.Length*2); r.MaxLength=r.Length; r.Buffer=Marshal.StringToHGlobalUni(right);
    LSA_UNICODE_STRING[] rights=new LSA_UNICODE_STRING[1]{r};
    uint addStatus=LsaAddAccountRights(handle, sidPtr, rights, 1);
    LsaClose(handle); Marshal.FreeHGlobal(sidPtr); Marshal.FreeHGlobal(r.Buffer);
    if (addStatus!=0) throw new Exception("LsaAddAccountRights failed: 0x"+addStatus.ToString("X"));
  }
}
'''.strip("\n")

_LSA_REVOKE_CS = r'''
using System;
using System.Runtime.InteropServices;
using System.Text;
public class LsaRevoke {
  [DllImport("advapi32.dll",PreserveSig=false)]
  public static extern uint LsaOpenPolicy(IntPtr sa, ref LSA_OBJECT_ATTRIBUTES oa, uint access, out IntPtr handle);
  [DllImport("advapi32.dll",PreserveSig=false)]
  public static extern uint LsaRemoveAccountRights(IntPtr handle, IntPtr sid, bool allRights, LSA_UNICODE_STRING[] rights, uint count);
  [DllImport("advapi32.dll")] public static extern int LsaClose(IntPtr handle);
  [DllImport("advapi32.dll",CharSet=CharSet.Unicode)]
  public static extern bool LookupAccountName(string sys, string acc, byte[] sid, ref int sidLen, StringBuilder dom, ref int domLen, ref int use);
  [StructLayout(LayoutKind.Sequential)]
  public struct LSA_OBJECT_ATTRIBUTES { public int Length; public IntPtr RootDirectory; public LSA_UNICODE_STRING ObjectName; public uint Attributes; public IntPtr SecurityDescriptor; public IntPtr SecurityQualityOfService; }
  [StructLayout(LayoutKind.Sequential)]
  public struct LSA_UNICODE_STRING { public ushort Length; public ushort MaxLength; public IntPtr Buffer; }
  public static void Revoke(string account, string right) {
    byte[] sid=new byte[256]; int sidLen=sid.Length, domLen=128; StringBuilder dom=new StringBuilder(domLen); int use=0;
    if (!LookupAccountName(null, account, sid, ref sidLen, dom, ref domLen, ref use)) return;
    byte[] sidBytes=new byte[sidLen]; Array.Copy(sid, sidBytes, sidLen);
    IntPtr sidPtr=Marshal.AllocHGlobal(sidBytes.Length); Marshal.Copy(sidBytes, 0, sidPtr, sidBytes.Length);
    LSA_OBJECT_ATTRIBUTES oa=new LSA_OBJECT_ATTRIBUTES(); oa.Length=Marshal.SizeOf(oa); IntPtr handle;
    uint status=LsaOpenPolicy(IntPtr.Zero, ref oa, 0x810, out handle);
    if (status!=0) { Marshal.FreeHGlobal(sidPtr); return; }
    LSA_UNICODE_STRING r=new LSA_UNICODE_STRING(); r.Length=(ushort)(right.Length*2); r.MaxLength=r.Length; r.Buffer=Marshal.StringToHGlobalUni(right);
    LSA_UNICODE_STRING[] rights=new LSA_UNICODE_STRING[1]{r};
    LsaRemoveAccountRights(handle, sidPtr, false, rights, 1);
    LsaClose(handle); Marshal.FreeHGlobal(sidPtr); Marshal.FreeHGlobal(r.Buffer);
  }
}
'''.strip("\n")


@app.get("/agent/lsa-helper")
def lsa_helper(mode: str = Query("grant", description="'grant' for install, 'revoke' for cleanup")):
    """Serve the C# LSA privilege helper as plain text. The install and
    cleanup scripts download this file and feed it to Add-Type instead of
    embedding a large base64 blob in the one-liner (which got corrupted
    when copy-pasted through some terminals)."""
    if mode == "revoke":
        cs = _LSA_REVOKE_CS
        name = "LsaRevoke.cs"
    else:
        cs = _LSA_GRANT_CS
        name = "LsaGrant.cs"
    return PlainTextResponse(
        cs,
        media_type="text/plain; charset=utf-8",
        headers={"Cache-Control": "no-store, no-cache, must-revalidate, max-age=0"},
    )


# --- Companion files (extra files shipped alongside the agent) ------------
# The agent is built with the MSVC runtime statically linked (/MT), so it has
# no external VC++ runtime DLL dependencies. These endpoints remain for
# install must work with no internet, the operator uploads them once and the
# install script downloads them into the agent's directory (Windows resolves
# DLLs from the exe's folder first).

import re
_SAFE_FILENAME = re.compile(r"^[A-Za-z0-9._-]+$")


def _is_safe_filename(name: str) -> bool:
    """Reject path traversal / odd characters in companion filenames."""
    # Kept for any extra files an operator wants to ship next to the agent.
    return bool(_SAFE_FILENAME.match(name)) and name not in AGENT_BINARY_NAMES.values()


@app.get("/agent/files")
def list_agent_files() -> list[dict]:
    """List companion files stored alongside the agent binary (e.g. extra
    agent binary."""
    if not os.path.isdir(AGENT_BINARY_DIR):
        return []
    out = []
    for name in sorted(os.listdir(AGENT_BINARY_DIR)):
        if name in AGENT_BINARY_NAMES.values():
            continue
        full = os.path.join(AGENT_BINARY_DIR, name)
        if os.path.isfile(full):
            out.append({"name": name, "bytes": os.path.getsize(full)})
    return out


@app.post("/agent/files")
async def upload_agent_file(file: UploadFile = File(...),
                            user: dict = Depends(_require_role("admin"))):
    """Upload a companion file. The uploaded filename
    is preserved."""
    name = os.path.basename(file.filename or "")
    if not _is_safe_filename(name):
        raise HTTPException(400, "Invalid filename")
    os.makedirs(AGENT_BINARY_DIR, exist_ok=True)
    path = os.path.join(AGENT_BINARY_DIR, name)
    total = 0
    with open(path, "wb") as f:
        while True:
            chunk = await file.read(1024 * 1024)
            if not chunk:
                break
            total += len(chunk)
            if total > MAX_FILE_UPLOAD_BYTES:
                f.close()
                os.remove(path)
                raise HTTPException(413, f"File too large. Limit is "
                                         f"{MAX_FILE_UPLOAD_BYTES // (1024*1024)} MB.")
            f.write(chunk)
    size = os.path.getsize(path)
    db.write_audit(user["username"], "agent.file.upload", name,
                   {"bytes": size}, db_path=DB_PATH)
    return {"stored": True, "name": name, "bytes": size}


@app.get("/agent/files/{name}")
def download_agent_file(name: str, user: dict = Depends(_require_auth)):
    """Download a companion file by name."""
    if not _is_safe_filename(name):
        raise HTTPException(400, "Invalid filename")
    path = os.path.join(AGENT_BINARY_DIR, name)
    if not os.path.isfile(path):
        raise HTTPException(404, "File not found")
    return FileResponse(path, media_type="application/octet-stream", filename=name)


@app.delete("/agent/files/{name}")
def delete_agent_file(name: str,
                      user: dict = Depends(_require_role("admin"))) -> dict:
    """Delete a companion file."""
    if not _is_safe_filename(name):
        raise HTTPException(400, "Invalid filename")
    path = os.path.join(AGENT_BINARY_DIR, name)
    if not os.path.isfile(path):
        raise HTTPException(404, "File not found")
    os.remove(path)
    db.write_audit(user["username"], "agent.file.delete", name, db_path=DB_PATH)
    return {"deleted": True, "name": name}


def _build_install_ps1(base: str, group: str, group_id: int,
                       account_mode: str, domain: str, username: str) -> str:
    """Build the multi-line install .ps1 body (no placeholders left).

    The script is a normal, readable, multi-line PowerShell file (the user
    asked for "not a one liner"), so it can contain '#' comments and
    here-strings freely. It is downloaded from the UI (or copy-pasted) and
    run from an elevated PowerShell prompt on the target host.

    account_mode == 'local':
      Creates a dedicated least-privilege LOCAL user "ELFAgent" with a
      random password (the original behavior).

    account_mode == 'domain':
      Runs the service as an EXISTING DOMAIN\\username account. The
      password is NOT in the script; the script prompts for it at run
      time with Read-Host -AsSecureString, so it never transits the
      clipboard, the server DB, or the script file. The account must
      already exist in AD; the script grants it the local rights it needs
      (SeServiceLogonRight, SeSecurityPrivilege, Event Log Readers, ACL
      on the data dir) exactly like it does for the local account.
    """
    # The config.ini template. __AGENT_ID__ / __DATA_DIR__ / __AUTH_TOKEN__
    # are replaced by the script at install time (agent_id must be the
    # host's own COMPUTERNAME; the auth token comes from the register call).
    config_ini = (
        "[buffer]\n"
        "retention_seconds=30\n"
        "\n"
        "[rules]\n"
        "directory=__DATA_DIR__\\rules\n"
        "\n"
        "[lists]\n"
        "directory=__DATA_DIR__\\lists\n"
        "\n"
        "[server]\n"
        f"url={base}\n"
        "poll_interval_seconds=30\n"
        "agent_id=__AGENT_ID__\n"
        "auth_token=__AUTH_TOKEN__\n"
        "\n"
        "[logging]\n"
        "level=notice\n"
        "max_file_size_mb=1\n"
        "max_files=3\n"
        "directory=__DATA_DIR__\\logs\n"
        "\n"
        "[spool]\n"
        "max_spool_mb=100\n"
        "directory=__DATA_DIR__\\spool\n"
        "\n"
        "[destinations]\n"
        "siem = file://__DATA_DIR__\\output\\siem.jsonl\n"
        "data_lake = file://__DATA_DIR__\\output\\data_lake.jsonl\n"
        "alerts = file://__DATA_DIR__\\output\\alerts.jsonl\n"
    )
    import base64
    cfg_b64 = base64.b64encode(config_ini.encode("utf-16-le")).decode("ascii")

    # --- Shared prologue (both modes) --------------------------------------
    ps = f'''# ==========================================================================
# ELF Agent install script
# Generated by the ELF management server for group '{group}'.
#
# Run this from an ELEVATED PowerShell prompt (Run as Administrator) on the
# target Windows host. It:
#   1. Downloads the agent exe from the management server.
#   2. Creates the writable state tree under %ProgramData%\\ELFAgent.
#   3. Provisions the service account (see below).
#   4. Grants the account the minimum rights the agent needs.
#   5. Writes config.ini with agent_id = this host's computer name.
#   6. Registers the agent with the server and embeds the auth token.
#   7. Installs + starts the service (auto-start, crash recovery).
#
# Service account: {account_mode} mode.
# ==========================================================================
$ErrorActionPreference = 'Stop'
$base = '{base}'
$group = '{group}'
$groupId = {group_id}
$binName = '{AGENT_BINARY_NAME}'
$agentId = $env:COMPUTERNAME
$svcName = 'ELFAgent'
$installDir = Join-Path $env:ProgramFiles 'ELFAgent'
$dataDir = Join-Path $env:ProgramData 'ELFAgent'

# --- 1. Download the agent binary ------------------------------------------
# Stop + remove any existing service FIRST: a running old agent holds a lock
# on the exe, which would make the download below fail with "file in use".
#
# KILL-FIRST: a hung agent process never reports SERVICE_STOPPED, and the
# SCM will NOT force-kill it on its own - Stop-Service then blocks forever
# and the service sits in "stopping". So we ask the SCM for the service's
# PID, request a graceful stop, give it a few seconds, and hard-kill the
# process if it is still alive BEFORE deleting the service.
function Stop-ElfService([string]$name) {{
    $svc = Get-Service -Name $name -ErrorAction SilentlyContinue
    if (-not $svc) {{ return }}
    # 'StopPending' must be handled too: a hung agent sits in 'stopping'
    # forever (the SCM never force-kills it), and re-running the install
    # script on such a host must still kill the stuck process.
    if ($svc.Status -ne 'Running' -and $svc.Status -ne 'StopPending') {{ return }}
    # Ask the SCM for the service's process id (works even while the
    # service is stuck in 'stopping' - the process is still alive).
    # NOTE: $pid is a read-only automatic variable in PowerShell, so the
    # service's pid is kept in $svcPid.
    $proc = Get-CimInstance Win32_Service -Filter "Name='$name'" -ErrorAction SilentlyContinue
    $svcPid = 0
    if ($proc -and $proc.ProcessId -and $proc.ProcessId -gt 0) {{ $svcPid = $proc.ProcessId }}
    if ($svcPid -gt 0) {{
        Write-Host "  Requesting graceful stop of $name (pid $svcPid)..."
        Stop-Service -Name $name -Force -ErrorAction SilentlyContinue
        # Wait up to 10s for a clean stop (the agent flushes bookmarks on
        # shutdown, so prefer graceful whenever it works).
        $deadline = (Get-Date).AddSeconds(10)
        while ((Get-Date) -lt $deadline) {{
            $p = Get-Process -Id $svcPid -ErrorAction SilentlyContinue
            if (-not $p) {{ return }}   # process gone - clean stop
            Start-Sleep -Milliseconds 500
        }}
        # Still alive after the grace period - hard-kill it. A stuck
        # 'stopping' service can ONLY be cleared by killing the process.
        if (Get-Process -Id $svcPid -ErrorAction SilentlyContinue) {{
            Write-Host "  Service did not stop in time - killing pid $svcPid."
            taskkill /F /PID $svcPid 2>$null | Out-Null
            Start-Sleep -Seconds 1
        }}
    }} else {{
        # No PID (service stopped, or SCM can't tell us) - plain stop.
        Stop-Service -Name $name -Force -ErrorAction SilentlyContinue
    }}
}}
if (Get-Service -Name $svcName -ErrorAction SilentlyContinue) {{
    Write-Host '  Stopping and removing the existing ELFAgent service...'
    Stop-ElfService $svcName
    sc.exe delete $svcName | Out-Null
}}
New-Item -ItemType Directory -Force -Path $installDir | Out-Null
$exe = Join-Path $installDir $binName
Write-Host "Downloading agent binary from $base ..."
Invoke-WebRequest -Uri "$base/agent/binary" -OutFile $exe -UseBasicParsing
if (-not (Test-Path $exe)) {{ throw "Download failed: $exe was not created." }}

# --- 2. Create the writable state tree -------------------------------------
# If a previous install left a locked-down data dir, take ownership back
# first so the new install can write into it.
if (Test-Path $dataDir) {{
    takeown /f $dataDir /r /d Y 2>$null | Out-Null
    icacls $dataDir /grant 'Administrators:F' /t /c 2>$null | Out-Null
}}
foreach ($sub in @('logs', 'state\\bookmarks', 'spool', 'rules', 'lists', 'output')) {{
    New-Item -ItemType Directory -Force -Path (Join-Path $dataDir $sub) | Out-Null
}}

'''
    # --- Mode-specific account provisioning --------------------------------
    if account_mode == "domain":
        account_ref = "DOMAIN\\USERNAME"  # replaced below
        ps += f'''# --- 3. Service account: existing DOMAIN account ---------------------------
# The service runs as an existing domain account. The password is prompted
# for SECURELY at run time (masked input, never echoed, never stored in
# this file) so it does not transit the clipboard or the management server.
$domainUser = '{domain}\\{username}'
Write-Host ''
Write-Host "Service account: $domainUser"
Write-Host 'Enter the password for this account when prompted.'
Write-Host '(Input is masked; the password is used only to start the service.)'
$secPw = Read-Host -Prompt "Password for $domainUser" -AsSecureString
# sc.exe needs the plaintext password once, at install time only, to hand
# to the Service Control Manager. Convert in memory, use, discard.
$pw = [Runtime.InteropServices.Marshal]::PtrToStringAuto(
    [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secPw))
if (-not $pw) {{ throw 'No password entered.' }}

# Verify the credentials actually work BEFORE wiring them into the service
# (a typo'd password would otherwise surface as SCM error 1069 at start).
# NOTE: PrincipalContext.ValidateCredentials wants the BARE username
# (SamAccountName), not DOMAIN\\user - passing the qualified form makes it
# query the LOCAL machine instead of AD and reject a valid password. Strip
# the domain prefix from $domainUser so validation targets AD correctly.
$validateUser = ($domainUser -split '\\\\')[-1]
try {{
    # Validate via the Windows credential API (no logon session is created).
    Add-Type -AssemblyName System.DirectoryServices.AccountManagement
    $ctx = New-Object System.DirectoryServices.AccountManagement.PrincipalContext(
        [System.DirectoryServices.AccountManagement.ContextType]::Domain, '{domain}')
    if (-not $ctx.ValidateCredentials($validateUser, $pw)) {{
        throw "Credentials for $domainUser were rejected by the domain."
    }}
    Write-Host '  Credentials verified against the domain.'
}} catch {{
    Write-Warning "Could not validate credentials ($($_.Exception.Message))."
    Write-Warning 'Continuing - if the password is wrong the service will fail'
    Write-Warning 'to start with error 1069 (logon failure). Check the password'
    Write-Warning 'and re-run this script.'
}}

# Grant the DOMAIN account the same local rights the local account gets.
# LookupAccountName resolves DOMAIN\\user to a SID on the local machine
# (works for machine-local and domain accounts alike).
# EAP=Continue: 'net localgroup /add' writes to stderr when the account is
# already a member (error 1378 on re-runs), and under $ErrorActionPreference
# = 'Stop' PS 5.1 turns that native stderr into a TERMINATING error that
# kills the whole script. The same applies to /delete in the cleanup script.
$prevEap = $ErrorActionPreference
$ErrorActionPreference = 'Continue'
net localgroup 'Event Log Readers' $domainUser /add 2>&1 | Out-Null
$ErrorActionPreference = $prevEap
$lsaPath = Join-Path $env:TEMP 'elf_lsa_grant.cs'
Invoke-WebRequest -Uri "$base/agent/lsa-helper?mode=grant" -OutFile $lsaPath -UseBasicParsing
$lsaCode = Get-Content -Path $lsaPath -Raw
if (-not ('LsaGrant' -as [type])) {{
    Add-Type -TypeDefinition $lsaCode -Language CSharp
}}
[LsaGrant]::Grant($domainUser, 'SeServiceLogonRight')
[LsaGrant]::Grant($domainUser, 'SeSecurityPrivilege')
Remove-Item $lsaPath -Force -ErrorAction SilentlyContinue
$svcAccount = $domainUser
$accountLabel = $domainUser

'''
    else:  # local
        ps += f'''# --- 3. Service account: dedicated LOCAL user ------------------------------
# Creates a local user "ELFAgent" with a random 24-char password. The
# password is generated at install time and handed to the SCM; nobody ever
# types it. The account gets only the rights the agent needs.
# DC HARD-STOP: a domain controller has NO local account database. On a DC,
# New-LocalUser would create a DOMAIN account named ELFAgent - and if a
# domain account with that name already exists, the Set-LocalUser branch
# below would RESET THE DOMAIN ACCOUNT'S PASSWORD to a random value,
# breaking every other host whose service runs as that account (error 1069
# on their next start). Local mode is therefore refused outright on a DC;
# re-generate the install script in domain mode instead.
if ((Get-CimInstance Win32_ComputerSystem -ErrorAction SilentlyContinue).DomainRole -ge 4) {{
    throw 'Local service-account mode is not supported on a domain controller: a DC has no local account database, so this would create or modify a DOMAIN account. Re-generate the install script in domain mode and use a dedicated domain service account.'
}}
$svcAccount = 'ELFAgent'
$accountLabel = ".$env:COMPUTERNAME\\ELFAgent"
$pw = -join ((65..90) + (97..122) + (48..57) | Get-Random -Count 24 | ForEach-Object {{ [char]$_ }})
$sec = ConvertTo-SecureString $pw -AsPlainText -Force
if (-not (Get-LocalUser -Name $svcAccount -ErrorAction SilentlyContinue)) {{
    New-LocalUser -Name $svcAccount -Password $sec -PasswordNeverExpires `
        -Description 'ELF agent service account' | Out-Null
}} else {{
    Set-LocalUser -Name $svcAccount -Password $sec
}}
# EAP=Continue: 'net localgroup /add' writes to stderr when the account is
# already a member (error 1378 on re-runs), and under $ErrorActionPreference
# = 'Stop' PS 5.1 turns that native stderr into a TERMINATING error that
# kills the whole script mid-run (leaving no service, no config, no ACL).
$prevEap = $ErrorActionPreference
$ErrorActionPreference = 'Continue'
net localgroup 'Event Log Readers' $svcAccount /add 2>&1 | Out-Null
$ErrorActionPreference = $prevEap
$lsaPath = Join-Path $env:TEMP 'elf_lsa_grant.cs'
Invoke-WebRequest -Uri "$base/agent/lsa-helper?mode=grant" -OutFile $lsaPath -UseBasicParsing
$lsaCode = Get-Content -Path $lsaPath -Raw
if (-not ('LsaGrant' -as [type])) {{
    Add-Type -TypeDefinition $lsaCode -Language CSharp
}}
[LsaGrant]::Grant($svcAccount, 'SeServiceLogonRight')
[LsaGrant]::Grant($svcAccount, 'SeSecurityPrivilege')
Remove-Item $lsaPath -Force -ErrorAction SilentlyContinue

'''
    # --- Shared epilogue (both modes) ---------------------------------------
    ps += f'''# --- 4. Lock down the data dir ----------------------------------------------
# Only SYSTEM and the service account may touch %ProgramData%\\ELFAgent, so
# normal users cannot read the agent's logs or tamper with the spool.
$acl = Get-Acl $dataDir
$acl.SetAccessRuleProtection($true, $false)
$rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
    $svcAccount, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')
$acl.AddAccessRule($rule)
$sysRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
    'NT AUTHORITY\\SYSTEM', 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')
$acl.AddAccessRule($sysRule)
Set-Acl -Path $dataDir -AclObject $acl
# Local Administrators may READ the logs subtree (and only that) so an
# operator can troubleshoot without taking ownership; spool/rules/state stay
# private to SYSTEM + the service account. The service's own rights are
# unchanged.
$logsDir = Join-Path $dataDir 'logs'
if (-not (Test-Path $logsDir)) {{ New-Item -ItemType Directory -Path $logsDir -Force | Out-Null }}
$lacl = Get-Acl $logsDir
$adminRead = New-Object System.Security.AccessControl.FileSystemAccessRule(
    'BUILTIN\\Administrators', 'ReadAndExecute', 'ContainerInherit,ObjectInherit', 'None', 'Allow')
$lacl.AddAccessRule($adminRead)
Set-Acl -Path $logsDir -AclObject $lacl

# --- 5. Write config.ini ------------------------------------------------------
$cfgB64 = '{cfg_b64}'
$cfg = [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String($cfgB64))
$cfg = $cfg.Replace('__AGENT_ID__', $agentId)
$cfg = $cfg.Replace('__DATA_DIR__', $dataDir)

# --- 6. Register with the management server -----------------------------------
# The server mints an enrollment token for this agent; it is embedded into
# config.ini so the agent can authenticate on its first poll.
$body = @{{ agent_id = $agentId; hostname = $env:COMPUTERNAME; group_id = $groupId }} | ConvertTo-Json
$authToken = ''
try {{
    $resp = Invoke-RestMethod -Uri "$base/agents/register" -Method POST `
        -Body $body -ContentType 'application/json'
    $authToken = $resp.auth_token
}} catch {{
    Write-Warning "Could not register with the server ($($_.Exception.Message))."
    Write-Warning 'The agent will register itself on first contact; you may'
    Write-Warning 'need to approve it in the UI.'
}}
$cfg = $cfg.Replace('__AUTH_TOKEN__', $authToken)
Set-Content -Path (Join-Path $installDir 'config.ini') -Value $cfg -Encoding ASCII

# --- 7. Install + start the service -------------------------------------------
$cmd = "`"$exe`""
# Any pre-existing service was already stopped + deleted in step 1 (a running
# old agent would lock the exe). This is just a safety net in case something
# recreated it in between. Stop-ElfService (defined in step 1) kills a hung
# process instead of blocking on Stop-Service forever.
if (Get-Service -Name $svcName -ErrorAction SilentlyContinue) {{
    Stop-ElfService $svcName
    sc.exe delete $svcName | Out-Null
}}
'''
    if account_mode == "domain":
        ps += f'''# For a domain account, obj= is the full DOMAIN\\user form.
sc.exe create $svcName binPath= $cmd start= auto obj= "$svcAccount" password= $pw | Out-Null
'''
    else:
        ps += f'''# For a local account, obj= is .\\ELFAgent (dot = this machine).
sc.exe create $svcName binPath= $cmd start= auto obj= ".$svcAccount" password= $pw | Out-Null
'''
    ps += f'''sc.exe failure $svcName reset= 86400 actions= restart/30000/restart/30000/restart/60000 | Out-Null
sc.exe description $svcName "Efficient Log Forwarder - collects Windows events, applies correlation rules locally, and forwards relevant events to the management server." | Out-Null
Start-Service $svcName

# Clear the plaintext password out of memory as soon as the SCM has it.
Remove-Variable pw -ErrorAction SilentlyContinue
Remove-Variable secPw -ErrorAction SilentlyContinue
Remove-Variable sec -ErrorAction SilentlyContinue

Write-Host ''
Write-Host "ELF agent installed as service '$svcName' at $installDir and started as $agentId (group: $group)."
Write-Host "  Account: $accountLabel (Event Log Readers, SeServiceLogonRight, SeSecurityPrivilege)"
Write-Host "  Data dir: $dataDir (ACL: SYSTEM + service account only)"
Write-Host "  Start: Auto (boot). Recovery: restart 30s/30s/60s."
Write-Host ''
Write-Host 'If Start-Service fails with error 1069 (logon failure):'
Write-Host '  - domain mode: check the password you entered, and that the'
Write-Host '    account has "Log on as a service" allowed by GPO on this host.'
'''
    return ps


@app.post("/install-script", response_class=PlainTextResponse)
def post_install_script(req: InstallScriptRequest,
                        request: Request,
                        user: dict = Depends(_require_role("admin"))):
    """Generate the install script: a .ps1 for a Windows host (os=windows,
    the default) or a bash script with a systemd unit for a Linux host
    (os=linux; account_mode 'local' creates a system user, 'existing'
    uses the account named in `username`). Windows service-account modes:

      * account_mode='local' (default): the script creates a dedicated
        least-privilege local user 'ELFAgent' with a random password.
      * account_mode='domain': the service runs as an EXISTING domain
        account (DOMAIN\\username). The password is NOT part of the script;
        the script prompts for it securely (Read-Host -AsSecureString) at
        install time on the target host, so the password never transits
        the clipboard, the server, or the script file.

    The response is a full multi-line .ps1 (not a one-liner); the operator
    saves/downloads it and runs it from an elevated PowerShell prompt.
    """
    grp = db.get_group_by_name(req.group, DB_PATH)
    if not grp:
        raise HTTPException(404, f"Group '{req.group}' not found")
    if req.os == "linux":
        if req.account_mode == "domain":
            raise HTTPException(400, "Linux hosts use account_mode 'local' or 'existing'.")
        try:
            script = linux_install.build_install_sh(
                _resolve_public_base(request), req.group, grp["id"],
                req.account_mode, req.username, req.audit_execve)
        except ValueError as e:
            raise HTTPException(400, str(e))
        db.write_audit(user["username"], "install-script.generate", req.group,
                       {"os": "linux", "account_mode": req.account_mode,
                        "audit_execve": req.audit_execve,
                        "agent_id_hint": request.client.host if request.client else None},
                       db_path=DB_PATH)
        return script
    if req.account_mode == "existing":
        raise HTTPException(400, "account_mode 'existing' applies to Linux hosts only.")
    if req.account_mode == "domain" and (not req.domain.strip() or not req.username.strip()):
        raise HTTPException(
            400,
            "Domain mode requires both 'domain' and 'username' "
            "(the DOMAIN\\user of an existing service account).",
        )
    base = _resolve_public_base(request)
    ps1 = _build_install_ps1(base, req.group, grp["id"],
                             req.account_mode, req.domain.strip(), req.username.strip())
    db.write_audit(user["username"], "install-script.generate", req.group,
                   {"os": "windows", "account_mode": req.account_mode,
                    "agent_id_hint": request.client.host if request.client else None},
                   db_path=DB_PATH)
    return ps1


@app.get("/install-script", response_class=PlainTextResponse)
def get_install_script(request: Request, group: str = Query(..., description="Group name the new agent joins"),
                        user: dict = Depends(_require_role("admin"))):
    """GET form of POST /install-script: local-account mode only. Kept so
    bookmarks/copied links to this URL keep working. Returns the same
    multi-line .ps1 as the POST form (not a one-liner: a one-liner is
    fragile to copy and cannot prompt for a password)."""
    req = InstallScriptRequest(group=group, account_mode="local")
    return post_install_script(req, request, user)


@app.get("/cleanup-script", response_class=PlainTextResponse)
def get_cleanup_script(user: dict = Depends(_require_role("admin")),
                       target_os: str = Query("windows", alias="os")):
    """Return a static script that removes ALL artifacts left by an ELF
    agent install: ?os=linux gives the bash version (unit, directories,
    audit rule, the dedicated elf user); the default is the PowerShell
    version described below.

    The PowerShell script removes ALL artifacts left
    by a previous (failed or successful) ELFAgent install. This is the
    troubleshooting tool to run when the install script fails partway
    through and leaves a half-installed state behind, e.g. a locked-down
    data dir, a service that won't start, or a user with leftover rights.

    The script is fully static (no server dependency, no placeholders) so
    it works even if the management server is unreachable. It is fully
    idempotent and safe to run multiple times. It:
      * stops + deletes the ELFAgent service (if it exists),
      * detects which account the service ran as (local ELFAgent user or
        a DOMAIN\\user account) from the service's obj= setting BEFORE
        deleting the service,
      * removes the local ELFAgent user (if it exists); the dedicated
        service account is deleted along with the service,
      * removes the account from Event Log Readers (local or domain),
      * revokes SeServiceLogonRight/SeSecurityPrivilege from a DOMAIN
        account via the LSA API (the domain account itself is NOT
        touched, since it exists in AD and may be used elsewhere; only the
        rights granted on THIS host are revoked). For the local user the
        rights are simply orphaned with the deleted SID.
      * takes ownership of + deletes the ProgramData\\ELFAgent tree
        (which has a locked-down ACL that blocks normal deletion),
      * deletes the Program Files\\ELFAgent directory.
      * DOMAIN CONTROLLER SAFETY: a DC has no local account database - the
        "local" account APIs (Get-LocalUser/Remove-LocalUser/net
        localgroup) operate on Active Directory. On a DC (DomainRole >= 4)
        the script therefore SKIPS account deletion and group-membership
        edits entirely and prints manual AD commands instead. (Deleting
        the DOMAIN service account from a DC would break the ELF service
        on every host that runs as that account.)

    The script is a normal multi-line .ps1 (matching the install script
    format) so it can carry '#' comments explaining each step.
    """
    if _binary_os(target_os) == "linux":
        return linux_install.CLEANUP_SH
    ps_script = r'''# ==========================================================================
# ELF Agent cleanup script
# Run from an ELEVATED PowerShell prompt (Run as Administrator) on the
# target host. Removes every artifact an ELF agent install leaves behind:
# the service, the local service account (if the install created one),
# group memberships, LSA rights, and both directories. Safe to run
# multiple times; safe to run when nothing is installed.
#
# If the service ran as a DOMAIN account, the account itself is NOT
# deleted (it lives in AD and may be used by other hosts) - only the
# rights granted to it on THIS host are revoked.
#
# DOMAIN CONTROLLER SAFETY: a DC has no local account database - the
# "local" account APIs (Get-LocalUser/Remove-LocalUser/net localgroup)
# operate on ACTIVE DIRECTORY. On a DC this script therefore NEVER deletes
# accounts and NEVER edits group membership; it only cleans up this host
# (service, per-machine LSA rights, directories) and prints the manual AD
# commands instead.
# ==========================================================================
$ErrorActionPreference = 'SilentlyContinue'
$svcName = 'ELFAgent'
$svcAccount = 'ELFAgent'
$installDir = Join-Path $env:ProgramFiles 'ELFAgent'
$dataDir = Join-Path $env:ProgramData 'ELFAgent'
Write-Host '=== ELF Agent Cleanup ==='

# --- 0. Domain controller safety check -------------------------------------
# Win32_ComputerSystem.DomainRole: 4 = backup DC, 5 = primary DC. On a DC
# the "local" account APIs write to Active Directory, so every account
# deletion / group-membership edit below is skipped entirely. The check
# FAILS CLOSED: if the machine's role cannot be determined, assume it IS
# a DC - skipping cleanup on a weird box is harmless, but deleting a
# domain account by accident is not.
$isDC = $false
$roleKnown = $false
try {
    if ((Get-CimInstance Win32_ComputerSystem -ErrorAction Stop).DomainRole -ge 4) { $isDC = $true }
    $roleKnown = $true
} catch { }
if (-not $roleKnown) {
    try {
        $pt = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\ProductOptions' -Name ProductType -ErrorAction Stop).ProductType
        if ($pt -eq 'LanmanNT') { $isDC = $true }
        $roleKnown = $true
    } catch { }
}
if (-not $roleKnown) { $isDC = $true }
if ($isDC) {
    Write-Host '  Domain controller detected: account deletion and group'
    Write-Host '  membership changes are SKIPPED (they would modify AD).'
}

# --- 1. Find out which account the service runs as, BEFORE deleting it ---
# sc.exe qc prints the service config; the SERVICE_START_NAME line shows
# the account. A local install shows .\ELFAgent or LocalSystem ; a domain
# install shows DOMAIN\user. We need this before the service is deleted
# because the config is gone afterwards.
$svcAccountUsed = $null
$svc = Get-Service -Name $svcName -ErrorAction SilentlyContinue
if ($svc) {
    $qc = sc.exe qc $svcName
    $objLine = ($qc | Select-String -Pattern 'SERVICE_START_NAME\s+:').ToString()
    if ($objLine -match 'SERVICE_START_NAME\s+:\s*(\S+)') { $svcAccountUsed = $Matches[1] }
}

# --- 2. Stop + delete the service ------------------------------------------
# KILL-FIRST: a hung agent process never reports SERVICE_STOPPED, and the
# SCM will NOT force-kill it on its own - Stop-Service then blocks forever
# and the service sits in "stopping" (where sc.exe delete also fails). So
# we ask the SCM for the service's PID, request a graceful stop, give it a
# few seconds, and hard-kill the process if it is still alive BEFORE
# deleting the service.
function Stop-ElfService([string]$name) {
    $svc = Get-Service -Name $name -ErrorAction SilentlyContinue
    if (-not $svc) { return }
    if ($svc.Status -ne 'Running' -and $svc.Status -ne 'StopPending') { return }
    # Ask the SCM for the service's process id (works even while the
    # service is stuck in 'stopping' - the process is still alive).
    # NOTE: $pid is a read-only automatic variable in PowerShell, so the
    # service's pid is kept in $svcPid.
    $proc = Get-CimInstance Win32_Service -Filter "Name='$name'" -ErrorAction SilentlyContinue
    $svcPid = 0
    if ($proc -and $proc.ProcessId -and $proc.ProcessId -gt 0) { $svcPid = $proc.ProcessId }
    if ($svcPid -gt 0) {
        Write-Host "  Requesting graceful stop of $name (pid $svcPid)..."
        Stop-Service -Name $name -Force -ErrorAction SilentlyContinue
        # Wait up to 10s for a clean stop (the agent flushes bookmarks on
        # shutdown, so prefer graceful whenever it works).
        $deadline = (Get-Date).AddSeconds(10)
        while ((Get-Date) -lt $deadline) {
            $p = Get-Process -Id $svcPid -ErrorAction SilentlyContinue
            if (-not $p) { return }   # process gone - clean stop
            Start-Sleep -Milliseconds 500
        }
        # Still alive after the grace period - hard-kill it. A stuck
        # 'stopping' service can ONLY be cleared by killing the process.
        if (Get-Process -Id $svcPid -ErrorAction SilentlyContinue) {
            Write-Host "  Service did not stop in time - killing pid $svcPid."
            taskkill /F /PID $svcPid 2>$null | Out-Null
            Start-Sleep -Seconds 1
        }
    } else {
        # No PID (service stopped, or SCM can't tell us) - plain stop.
        Stop-Service -Name $name -Force -ErrorAction SilentlyContinue
    }
}
if ($svc) {
    Write-Host "Stopping service $svcName ..."
    Stop-ElfService $svcName
    Start-Sleep -Seconds 2
    sc.exe delete $svcName 2>$null | Out-Null
    Start-Sleep -Seconds 1
    Write-Host '  Service deleted.'
} else {
    Write-Host "  Service $svcName not found (already removed)."
}

# --- 3. Remove the LOCAL service account (if the install created one) ------
# NEVER on a domain controller: on a DC Get-LocalUser/Remove-LocalUser
# operate on Active Directory, so "Remove-LocalUser ELFAgent" deletes the
# DOMAIN service account - and every host whose ELF service runs as that
# account then fails with error 1069 on its next start.
if ($isDC) {
    Write-Host '  Skipping local-user deletion: domain controller detected.'
    Write-Host '  On a DC, Remove-LocalUser would delete the DOMAIN account'
    Write-Host '  "ELFAgent", which may run the ELF service on other hosts.'
    Write-Host '  If you deliberately want to delete the domain account, run:'
    Write-Host '    Remove-ADUser -Identity ELFAgent'
} elseif (Get-LocalUser -Name $svcAccount -ErrorAction SilentlyContinue) {
    Write-Host "Removing $svcAccount from Event Log Readers ..."
    net localgroup 'Event Log Readers' $svcAccount /delete 2>$null | Out-Null
    Write-Host "Deleting local user $svcAccount ..."
    Remove-LocalUser -Name $svcAccount -ErrorAction SilentlyContinue
    Write-Host '  User deleted.'
} else {
    Write-Host "  Local user $svcAccount not found (already removed, or a domain account was used)."
}

# --- 4. Revoke rights granted to a DOMAIN account on this host --------------
# If the service ran as DOMAIN\user, the install granted that account
# SeServiceLogonRight + SeSecurityPrivilege and Event Log Readers on THIS
# host. The domain account is NOT deleted (it exists in AD; other hosts
# may use it) - but the local grants should be rolled back.
# The -notmatch '^\.\\' guard skips the LOCAL form .\ELFAgent (dot prefix
# = this machine), whose rights are already orphaned with the deleted user.
if ($svcAccountUsed -and ($svcAccountUsed -match '\\') -and ($svcAccountUsed -notmatch '^\.\\')) {
    Write-Host "Service ran as domain account $svcAccountUsed - revoking local rights ..."
    if ($isDC) {
        # On a DC 'net localgroup' edits the DOMAIN built-in group - a
        # domain-scoped change affecting every host that relies on it.
        # Skip it and print the manual command instead.
        Write-Host '  DC: skipping Event Log Readers removal (that group is'
        Write-Host '  DOMAIN-scoped on a DC). To remove it deliberately, run:'
        Write-Host '    Remove-ADGroupMember -Identity "Event Log Readers" -Members ELFAgent -Confirm:$false'
    } else {
        net localgroup 'Event Log Readers' $svcAccountUsed /delete 2>$null | Out-Null
    }
    # The LSA revoke helper is a small C# snippet compiled inline via
    # Add-Type (no download needed - cleanup must work offline).
    $lsaRevokeCs = @"
using System;
using System.Runtime.InteropServices;
using System.Text;
public class LsaRevokeInline {
  [DllImport("advapi32.dll",PreserveSig=false)]
  public static extern uint LsaOpenPolicy(IntPtr sa, ref LSA_OBJECT_ATTRIBUTES oa, uint access, out IntPtr handle);
  [DllImport("advapi32.dll",PreserveSig=false)]
  public static extern uint LsaRemoveAccountRights(IntPtr handle, IntPtr sid, bool allRights, LSA_UNICODE_STRING[] rights, uint count);
  [DllImport("advapi32.dll")] public static extern int LsaClose(IntPtr handle);
  [DllImport("advapi32.dll",CharSet=CharSet.Unicode)]
  public static extern bool LookupAccountName(string sys, string acc, byte[] sid, ref int sidLen, StringBuilder dom, ref int domLen, ref int use);
  [StructLayout(LayoutKind.Sequential)]
  public struct LSA_OBJECT_ATTRIBUTES { public int Length; public IntPtr RootDirectory; public LSA_UNICODE_STRING ObjectName; public uint Attributes; public IntPtr SecurityDescriptor; public IntPtr SecurityQualityOfService; }
  [StructLayout(LayoutKind.Sequential)]
  public struct LSA_UNICODE_STRING { public ushort Length; public ushort MaxLength; public IntPtr Buffer; }
  public static void Revoke(string account, string right) {
    byte[] sid=new byte[256]; int sidLen=sid.Length, domLen=128; StringBuilder dom=new StringBuilder(domLen); int use=0;
    if (!LookupAccountName(null, account, sid, ref sidLen, dom, ref domLen, ref use)) return;
    byte[] sidBytes=new byte[sidLen]; Array.Copy(sid, sidBytes, sidLen);
    IntPtr sidPtr=Marshal.AllocHGlobal(sidBytes.Length); Marshal.Copy(sidBytes, 0, sidPtr, sidBytes.Length);
    LSA_OBJECT_ATTRIBUTES oa=new LSA_OBJECT_ATTRIBUTES(); oa.Length=Marshal.SizeOf(oa); IntPtr handle;
    uint status=LsaOpenPolicy(IntPtr.Zero, ref oa, 0x810, out handle);
    if (status!=0) { Marshal.FreeHGlobal(sidPtr); return; }
    LSA_UNICODE_STRING r=new LSA_UNICODE_STRING(); r.Length=(ushort)(right.Length*2); r.MaxLength=r.Length; r.Buffer=Marshal.StringToHGlobalUni(right);
    LSA_UNICODE_STRING[] rights=new LSA_UNICODE_STRING[1]{r};
    LsaRemoveAccountRights(handle, sidPtr, false, rights, 1);
    LsaClose(handle); Marshal.FreeHGlobal(sidPtr); Marshal.FreeHGlobal(r.Buffer);
  }
}
"@
    if (-not ('LsaRevokeInline' -as [type])) {
        Add-Type -TypeDefinition $lsaRevokeCs -Language CSharp
    }
    [LsaRevokeInline]::Revoke($svcAccountUsed, 'SeServiceLogonRight')
    [LsaRevokeInline]::Revoke($svcAccountUsed, 'SeSecurityPrivilege')
    Write-Host "  Revoked SeServiceLogonRight + SeSecurityPrivilege + Event Log Readers for $svcAccountUsed on this host."
    Write-Host "  (The domain account itself was NOT deleted - it lives in AD.)"
}

# --- 5. Remove the data dir (locked-down ACL needs takeown first) -----------
if (Test-Path $dataDir) {
    Write-Host "Removing data dir $dataDir ..."
    takeown /f $dataDir /r /d Y 2>$null | Out-Null
    icacls $dataDir /grant 'Administrators:F' /t /c 2>$null | Out-Null
    Remove-Item -Path $dataDir -Recurse -Force -ErrorAction SilentlyContinue
    if (Test-Path $dataDir) {
        Write-Host "  WARNING: could not fully remove $dataDir (may need a reboot)."
    } else {
        Write-Host '  Data dir removed.'
    }
} else {
    Write-Host '  Data dir not found (already removed).'
}

# --- 6. Remove the install dir ----------------------------------------------
if (Test-Path $installDir) {
    Write-Host "Removing install dir $installDir ..."
    Remove-Item -Path $installDir -Recurse -Force -ErrorAction SilentlyContinue
    if (Test-Path $installDir) {
        Write-Host "  WARNING: could not fully remove $installDir."
    } else {
        Write-Host '  Install dir removed.'
    }
} else {
    Write-Host '  Install dir not found (already removed).'
}
Write-Host '=== Cleanup complete. You can now re-run the install script. ==='
'''
    return ps_script


# --- Observability ----------------------------------------------------------

@app.get("/alerts")
def list_alerts(limit: int = Query(100, ge=1, le=1000),
               q: str = Query("", max_length=200),
               sort: str = Query("recency"),
               offset: int = Query(0, ge=0),
               include_payload: bool = Query(False),
               user: dict = Depends(_require_auth)) -> list[dict]:
    """List recent alerts. `sort` is 'recency' (default; newest first) or
    'severity' (most severe first, then newest). `q` filters by substring
    against rule_id / rule name / message / agent_id. Each row carries
    `rule_name` (the rule's display name) when the rule still exists.

    Payloads are omitted by default because alert payloads embed the full trigger
    event XML (plus sequence/window events) and run to KBs each, so a
    200-row listing with payloads ships megabytes and stalls the browser.
    Pass include_payload=true only when the payloads are really needed (the
    UI fetches one alert at a time via GET /alerts/{id} instead)."""
    rows = db.list_alerts(DB_PATH, limit, q=q, sort=sort, offset=offset)
    if include_payload:
        # Explicit mode: attach each alert's payload. Only honored for small
        # limits; a 1000-row payload dump is exactly the browser stall the
        # default shape avoids.
        if limit > 200:
            raise HTTPException(400, "include_payload requires limit <= 200")
        for a in rows:
            full = db.get_alert(a["id"], DB_PATH)
            if full:
                a["payload"] = full.get("payload", "")
    return rows


@app.get("/alerts/{alert_id}")
def get_alert(alert_id: int, user: dict = Depends(_require_auth)) -> dict:
    """Fetch a single alert INCLUDING its payload (trigger event XML,
    sequence events, window events). The Alerts tab calls this on demand
    when the analyst expands a row; the list endpoint strips payloads so
    listing thousands of alerts stays fast."""
    a = db.get_alert(alert_id, DB_PATH)
    if not a:
        raise HTTPException(404, "Alert not found")
    return a


@app.get("/logs")
def list_logs(limit: int = Query(40, ge=1, le=1000),
              user: dict = Depends(_require_auth)) -> list[dict]:
    """List the newest forwarded-log batches. The UI shows the last 40;
    older batches' events live on in the logs.txt text file (their DB
    payloads are pruned to keep the table small)."""
    return db.list_logs(DB_PATH, limit)


@app.delete("/alerts")
def clear_alerts(user: dict = Depends(_require_role("admin"))) -> dict:
    n = db.clear_alerts(DB_PATH)
    db.write_audit(user["username"], "alerts.clear", "",
                   {"deleted": n}, db_path=DB_PATH)
    return {"deleted": n}


@app.delete("/logs")
def clear_logs(user: dict = Depends(_require_role("admin"))) -> dict:
    n = db.clear_logs(DB_PATH)
    # Also truncate the text file so it stays in sync with the DB.
    db.clear_logs_text(DB_PATH)
    db.write_audit(user["username"], "logs.clear", "",
                   {"deleted": n}, db_path=DB_PATH)
    return {"deleted": n}


@app.get("/logs/text")
def logs_text(user: dict = Depends(_require_auth)) -> PlainTextResponse:
    """Return the newline-separated forwarded-logs text file. Each line is a
    raw Windows event XML document (no JSON envelope). Alert details for a
    forward_buffer fire live in the alerts view via POST /alerts."""
    import os
    path = db.logs_text_path(DB_PATH)
    if not os.path.exists(path):
        return PlainTextResponse("", media_type="text/plain",
                                 headers={"Cache-Control": "no-store"})
    with open(path, "r", encoding="utf-8") as f:
        return PlainTextResponse(f.read(), media_type="text/plain",
                                 headers={"Cache-Control": "no-store"})


@app.get("/logs/size")
def logs_size(user: dict = Depends(_require_auth)) -> dict:
    """Return the size of the forwarded-logs text file in bytes."""
    return JSONResponse({"bytes": db.logs_text_size_bytes(DB_PATH)},
                        headers={"Cache-Control": "no-store"})


@app.get("/logs/stats")
def logs_stats(start: float = Query(0), end: float = Query(0),
               bucket: int = Query(1),
               user: dict = Depends(_require_auth)) -> dict:
    """Return time-bucketed event counts and bytes for the logs graphs.
    start/end are epoch timestamps; bucket is the bucket size in seconds
    (minimum 1). If end is 0, defaults to now. If start is 0, defaults to
    end - 1h. Returns {buckets: [{bucket_ts, event_count, bytes}], ...}."""
    if bucket < 1:
        bucket = 1
    if end and start and end < start:
        start, end = end, start
    if not end:
        end = time.time()
    if not start:
        start = end - 3600
    buckets = db.logs_timeseries(DB_PATH, start, end, bucket)
    total_events = sum(b["event_count"] for b in buckets)
    total_bytes = sum(b["bytes"] for b in buckets)
    return JSONResponse({
        "start": start, "end": end, "bucket_seconds": bucket,
        "buckets": buckets,
        "total_events": total_events, "total_bytes": total_bytes,
    }, headers={"Cache-Control": "no-store"})


@app.get("/logs/savings")
def logs_savings(user: dict = Depends(_require_auth)) -> dict:
    """Return per-agent savings: events/bytes created by the host vs.
    forwarded to the server. Used by the logs savings view."""
    rows = db.savings_report(DB_PATH)
    total_created = sum(r["events_created"] or 0 for r in rows)
    total_forwarded = sum(r["events_forwarded"] or 0 for r in rows)
    total_bytes_created = sum(r["bytes_created"] or 0 for r in rows)
    total_bytes_forwarded = sum(r["bytes_forwarded"] or 0 for r in rows)
    return JSONResponse({
        "agents": rows,
        "total_events_created": total_created,
        "total_events_forwarded": total_forwarded,
        "total_bytes_created": total_bytes_created,
        "total_bytes_forwarded": total_bytes_forwarded,
    }, headers={"Cache-Control": "no-store"})


@app.get("/metrics/savings")
def metrics_savings(user: dict = Depends(_require_auth)) -> dict:
    """Per-agent savings: events/bytes created by the host vs. forwarded to
    the server. Powers the Metrics page savings view."""
    return logs_savings()


@app.get("/metrics/stats")
def metrics_stats(start: float = Query(0), end: float = Query(0),
                  bucket: int = Query(1),
                  agent_id: str = Query(""),
                  user: dict = Depends(_require_auth)) -> dict:
    """Time-bucketed event counts and bytes for the Metrics page graphs.
    Same data as /logs/stats, exposed under /metrics for a clean separation.
    Optional agent_id filters the timeseries to a single agent; empty string
    means totals across all agents."""
    if bucket < 1:
        bucket = 1
    if end and start and end < start:
        start, end = end, start
    if not end:
        end = time.time()
    if not start:
        start = end - 3600
    aid = agent_id.strip() or None
    buckets = db.logs_timeseries_by_agent(DB_PATH, start, end, bucket, aid)
    total_events = sum(b["event_count"] for b in buckets)
    total_bytes = sum(b["bytes"] for b in buckets)
    return JSONResponse({
        "start": start, "end": end, "bucket_seconds": bucket,
        "agent_id": aid or "",
        "buckets": buckets,
        "total_events": total_events, "total_bytes": total_bytes,
    }, headers={"Cache-Control": "no-store"})


@app.get("/metrics/alerts")
def metrics_alerts(start: float = Query(0), end: float = Query(0),
                   bucket: int = Query(1),
                   agent_id: str = Query(""),
                   user: dict = Depends(_require_auth)) -> dict:
    """Time-bucketed alert counts for the Metrics page graphs. Optional
    agent_id filters to a single agent; empty means totals across all."""
    if bucket < 1:
        bucket = 1
    if end and start and end < start:
        start, end = end, start
    if not end:
        end = time.time()
    if not start:
        start = end - 3600
    aid = agent_id.strip() or None
    buckets = db.alerts_timeseries(DB_PATH, start, end, bucket, aid)
    total_alerts = sum(b["alert_count"] for b in buckets)
    return JSONResponse({
        "start": start, "end": end, "bucket_seconds": bucket,
        "agent_id": aid or "",
        "buckets": buckets,
        "total_alerts": total_alerts,
    }, headers={"Cache-Control": "no-store"})


@app.delete("/metrics/reset")
def reset_metrics(user: dict = Depends(_require_role("admin"))) -> dict:
    """Reset the Metrics page: zero every agent's cumulative created/forwarded
    counters and delete all stored forwarded-log batches (DB rows + the
    logs.txt text file). Alerts are KEPT; they are the detection record.
    Lets an operator start a clean measurement window (e.g. after tuning
    rules) without the historical totals dominating the savings view."""
    db.reset_agent_counters(DB_PATH)
    n = db.clear_logs(DB_PATH)
    db.clear_logs_text(DB_PATH)
    db.write_audit(user["username"], "metrics.reset", "",
                   {"logs_deleted": n}, db_path=DB_PATH)
    return {"ok": True, "logs_deleted": n}


@app.get("/health")
def health() -> dict:
    return {"status": "ok", "time": time.time()}


# --- Settings ---------------------------------------------------------------

@app.get("/settings")
def get_settings(user: dict = Depends(_require_auth)) -> dict:
    """Server-wide settings shown on the Logs tab. Any authenticated user
    may read them; only admins can change them (PUT)."""
    try:
        max_mb = int(db.get_setting("max_logs_text_mb", "100", DB_PATH))
    except ValueError:
        max_mb = 100  # non-numeric stored value: fall back to the default
    return {"max_logs_text_mb": max_mb}


@app.put("/settings")
def update_settings(body: SettingsUpdate,
                    user: dict = Depends(_require_role("admin"))) -> dict:
    """Update server-wide settings. Admin-only. Currently only
    max_logs_text_mb (the cap for the forwarded-logs text file; 0 =
    unlimited, enforced by trimming the oldest lines after each append)."""
    db.set_setting("max_logs_text_mb", str(body.max_logs_text_mb), DB_PATH)
    db.write_audit(user["username"], "settings.update", "",
                   {"max_logs_text_mb": body.max_logs_text_mb}, db_path=DB_PATH)
    return {"ok": True, "max_logs_text_mb": body.max_logs_text_mb}


# --- Rule validation --------------------------------------------------------

@app.post("/rules/validate")
def validate_rule_yaml(body: dict,
                       user: dict = Depends(_require_role("admin", "rule_contributor"))) -> dict:
    """Validate a Sigma YAML rule body server-side. Returns ok/error + parsed
    info. Used by the UI's editor before allowing a save.

    Sigma rules require: title, id, logsource, detection (with at least one
    selection and a condition). We also validate that the condition references
    selection names that exist.
    """
    yaml_body = body.get("yaml_body", "")
    if not yaml_body.strip():
        return {"valid": False, "error": "YAML body is empty."}
    if len(yaml_body) > MAX_YAML_BODY_BYTES:
        return {"valid": False, "error": f"YAML body too large. Limit is "
                                         f"{MAX_YAML_BODY_BYTES // 1024} KB."}
    try:
        parsed = yaml.safe_load(yaml_body)
    except yaml.YAMLError as e:
        return {"valid": False, "error": f"YAML parse error: {e}"}
    if not isinstance(parsed, dict):
        return {"valid": False, "error": "Top-level YAML must be a mapping (Sigma rule)."}

    rid = parsed.get("id")
    if not rid:
        return {"valid": False, "error": "Sigma rule is missing 'id' field."}
    title = parsed.get("title", rid)
    description = parsed.get("description", "")
    level = parsed.get("level", "medium")
    status = parsed.get("status", "stable")
    enabled = status not in ("deprecated", "unsupported")

    logsource = parsed.get("logsource")
    if not isinstance(logsource, dict):
        return {"valid": False, "error": "Sigma rule is missing 'logsource' (must be a mapping)."}

    detection = parsed.get("detection")
    if not isinstance(detection, dict):
        return {"valid": False, "error": "Sigma rule is missing 'detection' (must be a mapping)."}

    condition = detection.get("condition")
    if not isinstance(condition, str) or not condition.strip():
        return {"valid": False, "error": "Sigma detection is missing 'condition' string."}
    if "|" in condition:
        # Sigma aggregation/correlation expressions (`| count() > 5`,
        # `| near ...`) are not part of the agent's condition grammar; the
        # agent fails the condition closed, so the rule would load but never
        # match. Say so here instead. Use an ELF threshold/sequence rule.
        return {"valid": False, "error": (
            "Sigma aggregation expressions ('| count()', '| near') are not "
            "supported in condition. Use an elf.threshold or elf.sequence rule "
            "instead.")}

    # Collect selection names (every key in detection except 'condition').
    sel_names = [k for k in detection.keys() if k != "condition"]
    if not sel_names:
        return {"valid": False, "error": "Sigma detection has no selections."}

    # Lightweight condition validation: extract identifiers and check that
    # any non-keyword identifier (or glob prefix) matches a selection name.
    # Keywords: and, or, not, of, them, 1, all, parentheses.
    keywords = {"and", "or", "not", "of", "them", "1", "all"}
    import re
    tokens = re.findall(r"[A-Za-z0-9_*]+", condition)
    for tok in tokens:
        if tok in keywords:
            continue
        # Strip trailing '*' (glob) for the prefix check.
        prefix = tok[:-1] if tok.endswith("*") else tok
        if not any(name == prefix or name.startswith(prefix) for name in sel_names):
            # Unknown reference: warn but don't hard-fail (Sigma allows
            # selection* globs that may not match anything yet).
            pass  # lenient: allow unknown references

    # ELF extension validation. Two checks:
    #   1. Action types must be known (forward_event, alert, forward_buffer).
    #      An unknown type like "forward_alert" is silently ignored by the
    #      agent's runFireActions, so the rule would appear to "fire" with no
    #      effect, which is confusing. Reject it at save time so the misconfiguration
    #      is caught immediately.
    #   2. forward_event is a per-event action and is only meaningful for
    #      simple rules. Combining it with threshold or sequence correlation
    #      is contradictory (the event would be forwarded before the
    #      correlation window is satisfied), so reject it.
    #
    # The agent resolves the actions block the same way: it looks for
    # `elf.actions` first, and falls back to a top-level `actions` key when
    # there is no `elf` block. Mirror that lookup here so the server and the
    # agent apply identical validation logic ("use the same logic the agents
    # would use").
    elf_block = parsed.get("elf")
    if isinstance(elf_block, dict):
        is_threshold = "threshold" in elf_block
        is_sequence = "sequence" in elf_block
        actions = elf_block.get("actions", [])
    else:
        # No elf block: the agent falls back to a top-level actions list.
        is_threshold = "threshold" in parsed
        is_sequence = "sequence" in parsed
        actions = parsed.get("actions", [])
    if isinstance(actions, list):
        valid_types = {"forward_event", "alert", "forward_buffer"}
        for a in actions:
            if not isinstance(a, dict):
                return {"valid": False, "error": "Each action must be a mapping."}
            atype = a.get("type", "")
            if atype not in valid_types:
                return {
                    "valid": False,
                    "error": (
                        f"Unknown action type '{atype}'. Valid types: "
                        f"forward_event, alert, forward_buffer."
                    ),
                }
            if (is_threshold or is_sequence) and atype == "forward_event":
                kind = "threshold" if is_threshold else "sequence"
                return {
                    "valid": False,
                    "error": (
                        f"'forward_event' is not compatible with {kind} rules: "
                        f"forward_event forwards every matching event immediately, "
                        f"but a {kind} rule only fires once its correlation window "
                        f"is satisfied. Use 'alert' or 'forward_buffer' instead."
                    ),
                    }
    # The agent refuses to load a rule with no valid actions (it would match
    # and do nothing). Mirror that here so it cannot be saved in the first
    # place.
    if not isinstance(actions, list) or not actions:
        return {
            "valid": False,
            "error": (
                "Rule has no actions. Add an elf.actions list with at least "
                "one of: forward_event, alert, forward_buffer."
            ),
        }

    # timeframe validation. The agent loads a threshold/sequence rule with a
    # missing or zero timeframe as a 0-second window: every match expires
    # instantly and the rule never fires. Require a positive window. The
    # agent accepts a bare integer (seconds) or <n><s|m|h|d>.
    if is_threshold or is_sequence:
        if isinstance(elf_block, dict):
            tf = elf_block.get("timeframe", parsed.get("timeframe"))
        else:
            tf = parsed.get("timeframe")
        tf_secs = None
        if isinstance(tf, (int, float)) and not isinstance(tf, bool):
            tf_secs = int(tf)
        elif isinstance(tf, str):
            m = re.fullmatch(r"\s*(\d+)\s*([smhdSMHD]?)\s*", tf)
            if m:
                tf_secs = int(m.group(1)) * {"": 1, "s": 1, "m": 60, "h": 3600,
                                             "d": 86400}[m.group(2).lower()]
        if not tf_secs or tf_secs <= 0:
            kind = "threshold" if is_threshold else "sequence"
            return {
                "valid": False,
                "error": (
                    f"{kind} rules require a positive elf.timeframe "
                    f"(e.g. timeframe: 60s, 5m, 1h); got {tf!r}."
                ),
            }

    # group_by validation. group_by is MANDATORY for threshold rules; without
    # it the count is global (one shared window), which is the false-positive
    # trap this feature exists to remove (5 failed logons from 5
    # different users would fire a threshold-5 brute-force rule). Reject a
    # threshold rule without group_by, and reject group_by on non-threshold
    # rules (it's only honored by threshold rules today; sequence grouping is
    # future work). Mirror the agent's elf-first / top-level fallback.
    group_by = None
    if isinstance(elf_block, dict):
        group_by = elf_block.get("group_by", parsed.get("group_by"))
    else:
        group_by = parsed.get("group_by")
    if group_by is not None:
        if isinstance(group_by, str):
            group_by_fields = [group_by]
        elif isinstance(group_by, list) and all(isinstance(g, str) for g in group_by):
            group_by_fields = group_by
        else:
            return {
                "valid": False,
                "error": (
                    "group_by must be a string or a list of strings "
                    "(e.g. group_by: TargetUserName)."
                ),
            }
        if not is_threshold:
            return {
                "valid": False,
                "error": (
                    "group_by is only supported on threshold rules "
                    "(sequence-rule grouping is not yet implemented)."
                ),
            }
        if not group_by_fields:
            return {
                "valid": False,
                "error": "group_by must not be empty.",
            }
    else:
        # group_by absent.
        if is_threshold:
            return {
                "valid": False,
                "error": (
                    "Threshold rules require group_by to scope the count per "
                    "group (e.g. group_by: TargetUserName). Without it the "
                    "count is global and fires on N matches from N different "
                    "users/hosts, a false positive."
                ),
            }

    # distinct validation. Optional; threshold rules only. distinct switches
    # the fire condition from "N matching events" to "N unique resolved
    # values of the distinct field(s)", e.g. a ping-sweep rule counts unique
    # DestAddress values, so `ping -n 10 <onehost>` (10 events, 1 unique
    # destination) does not fire a threshold-5 rule. Mirror the agent's
    # elf-first / top-level fallback and the group_by type rules.
    distinct = None
    if isinstance(elf_block, dict):
        distinct = elf_block.get("distinct", parsed.get("distinct"))
    else:
        distinct = parsed.get("distinct")
    if distinct is not None:
        if isinstance(distinct, str):
            distinct_fields = [distinct]
        elif isinstance(distinct, list) and all(isinstance(d, str) for d in distinct):
            distinct_fields = distinct
        else:
            return {
                "valid": False,
                "error": (
                    "distinct must be a string or a list of strings "
                    "(e.g. distinct: DestAddress)."
                ),
            }
        if not is_threshold:
            return {
                "valid": False,
                "error": (
                    "distinct is only supported on threshold rules "
                    "(it changes what the threshold counts: unique field "
                    "values instead of matching events)."
                ),
            }
        if not distinct_fields:
            return {
                "valid": False,
                "error": "distinct must not be empty.",
            }

    # threshold_op validation. Optional; if present must be one of
    # gte/gt/eq. lt/lte/neq are not supported (under the fire-then-reset model
    # they would fire on every matching event after a reset). Only valid on
    # threshold rules. Absent = gte (the default, no error).
    threshold_op = None
    if isinstance(elf_block, dict):
        threshold_op = elf_block.get("threshold_op", parsed.get("threshold_op"))
    else:
        threshold_op = parsed.get("threshold_op")
    if threshold_op is not None:
        if not isinstance(threshold_op, str):
            return {
                "valid": False,
                "error": "threshold_op must be a string (gte, gt, or eq).",
            }
        if threshold_op not in ("gte", "gt", "eq"):
            return {
                "valid": False,
                "error": (
                    f"threshold_op must be one of: gte, gt, eq "
                    f"(got '{threshold_op}'; lt/lte/neq are not yet supported)."
                ),
            }
        if not is_threshold:
            return {
                "valid": False,
                "error": "threshold_op is only supported on threshold rules.",
            }

    # Reusable-list reference validation. A rule field value may reference a
    # reusable list with `@@name` (e.g. `Image|contains: "@@sensitive"`). The
    # list is expanded at agent load time. We scan all selection field values
    # for `@@` references and collect warnings for any that don't correspond
    # to an existing list. This is a WARNING, not a hard failure: a missing
    # list makes the field match nothing on the agent (safe default), so the
    # rule still loads and is simply inert for that field. Surfacing it here
    # helps the user catch typos in the list name before the rule silently
    # stops matching.
    warnings: list[str] = []
    existing_lists = {l["name"] for l in db.list_lists(DB_PATH)}
    import re as _re
    for sel_name in sel_names:
        sel = detection.get(sel_name)
        if not isinstance(sel, dict):
            continue
        for field, val in sel.items():
            # A field value can be a scalar string or a list of strings.
            # Strip any Sigma modifier prefix (e.g. "Image|contains" -> "Image").
            vals = val if isinstance(val, list) else [val]
            is_regex_field = "re" in field.split("|")[1:]
            for v in vals:
                if not isinstance(v, str):
                    continue
                if is_regex_field and not v.startswith("@@"):
                    # The agent compiles |re patterns once at load and
                    # disables a field whose pattern fails to compile (the
                    # rule then never matches on it). Python's `re` is not
                    # ECMAScript, but it catches the plain syntax errors.
                    try:
                        _re.compile(v)
                    except _re.error as e:
                        return {"valid": False, "error": (
                            f"Field '{field}' has an invalid regular "
                            f"expression {v!r}: {e}")}
                for m in _re.finditer(r"@@([A-Za-z0-9_.\-]+)", v):
                    lname = m.group(1)
                    if lname not in existing_lists:
                        warnings.append(
                            f"Field '{field.split('|')[0]}' references list "
                            f"'@@{lname}' which does not exist; this field "
                            f"will match nothing on the agent."
                        )

    return {
        "valid": True, "error": None,
        "rule_id": rid, "name": title, "description": description,
        "severity": level, "enabled": enabled,
        "status": status, "level": level,
        "warnings": warnings,
    }


# --- Web UI -----------------------------------------------------------------

@app.get("/", response_class=HTMLResponse)
def ui() -> HTMLResponse:
    # Send no-cache headers so the browser always fetches the latest HTML/JS
    # after a redeploy. Without this, the browser may serve a cached copy of
    # the inline JS from before the redeploy.
    return HTMLResponse(_UI_HTML, headers={
        "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
        "Pragma": "no-cache",
        "Expires": "0",
    })


# Single-file UI served inline so the Docker image needs no extra static dir.
_UI_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>ELF Management Console</title>
<link rel="icon" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 32 32'%3E%3Crect width='32' height='32' rx='7' fill='%231e293b'/%3E%3Cpath d='M9 8h14v4h-9v2h8v4h-8v2h9v4H9z' fill='%2393c5fd'/%3E%3C/svg%3E"/>
<style>
  * { box-sizing: border-box; }
  body { font-family: system-ui, -apple-system, sans-serif; margin: 0; background: #0f172a; color: #e2e8f0; height: 100vh; display: flex; flex-direction: column; }
  header { background: #1e293b; padding: 10px 20px; display: flex; gap: 16px; align-items: center; flex-shrink: 0; flex-wrap: wrap; }
  header h1 { margin: 0; font-size: 18px; }
  nav { display: flex; gap: 6px; flex-wrap: wrap; }
  nav button { background: #334155; color: #e2e8f0; border: none; padding: 8px 14px; border-radius: 6px; cursor: pointer; font-size: 13px; }
  /* Keyboard users get a visible focus ring; mouse clicks do not. */
  button:focus-visible, a:focus-visible, .rule-item:focus-visible { outline: 2px solid #93c5fd; outline-offset: 1px; }
  nav button.active { background: #3b82f6; }
  nav button:hover { background: #475569; }
  nav button.active:hover { background: #2563eb; }
  main { flex: 1; overflow: auto; padding: 20px; }
  table { width: 100%; border-collapse: collapse; background: #1e293b; border-radius: 8px; overflow: hidden; }
  th, td { text-align: left; padding: 10px 12px; border-bottom: 1px solid #334155; font-size: 13px; }
  th { background: #334155; }
  .card { background: #1e293b; padding: 16px; border-radius: 8px; margin-bottom: 16px; }
  input, textarea, select { width: 100%; padding: 8px; margin: 4px 0 12px; background: #0f172a; color: #e2e8f0; border: 1px solid #334155; border-radius: 4px; font-family: monospace; font-size: 13px; }
  /* Checkboxes/radios must NOT inherit the global width:100%/padding; that
     inflated every checkbox (including the rules select-mode ones) and
     caused a horizontal scrollbar in select mode. Keep them at their
     natural size. */
  input[type=checkbox], input[type=radio] { width: auto; padding: 0; margin: 0; }
  input:focus, textarea:focus, select:focus { outline: none; border-color: #3b82f6; }
  textarea { resize: vertical; }
  label { font-size: 12px; color: #94a3b8; display: block; margin-bottom: 2px; }
  .btn { background: #3b82f6; color: white; border: none; padding: 8px 16px; border-radius: 6px; cursor: pointer; font-size: 13px; }
  .btn:hover { background: #2563eb; }
  .btn:disabled { background: #475569; cursor: not-allowed; opacity: 0.6; }
  .btn.danger { background: #ef4444; }
  .btn.danger:hover { background: #dc2626; }
  .btn.secondary { background: #334155; }
  .btn.secondary:hover { background: #475569; }
  .btn.active { background: #1e3a5f; border: 1px solid #3b82f6; outline: none; }
  .row { display: flex; gap: 12px; }
  .row > div { flex: 1; }
  .badge { padding: 2px 8px; border-radius: 10px; font-size: 11px; }
  .badge.high { background: #ef4444; } .badge.medium { background: #f59e0b; }
  .badge.low { background: #22c55e; } .badge.critical { background: #b91c1c; }
  .badge.warn { background: #f59e0b; } .badge.info { background: #3b82f6; }
  .badge.ok { background: #22c55e; } .badge.danger { background: #ef4444; }
  .muted { color: #64748b; }
  pre { white-space: pre-wrap; max-height: 300px; overflow: auto; background: #0f172a; padding: 8px; border-radius: 4px; }

  /* Alert detail dropdown (per-alert event viewer) */
  .alert-detail { display: flex; gap: 16px; align-items: flex-start; flex-wrap: wrap; padding: 8px 4px; }
  .alert-summary { font-size: 12px; border-collapse: collapse; }
  .alert-summary th { text-align: right; color: #94a3b8; padding: 2px 10px 2px 0; white-space: nowrap; font-weight: 500; }
  .alert-summary td { padding: 2px 10px; color: #e2e8f0; }
  .xml-raw { background: #0f172a; border: 1px solid #334155; border-radius: 6px; padding: 10px; font-size: 12px;
    color: #e2e8f0; max-height: 400px; overflow: auto; white-space: pre; font-family: monospace; }
  details summary { cursor: pointer; color: #93c5fd; font-size: 13px; margin: 8px 0; }
  .alert-detail-row > td { background: #172033; border-top: 1px solid #334155; }
  /* Sequence events (prior stages of a sequence rule) shown above the trigger */
  .seq-events { width: 100%; border-bottom: 1px dashed #334155; padding-bottom: 8px; margin-bottom: 8px; }
  .seq-label { color: #93c5fd; font-size: 12px; font-weight: 600; margin: 4px 0 6px 0; }
  .seq-item { background: #0f172a; border: 1px solid #334155; border-radius: 6px; padding: 8px; margin-bottom: 8px; }
  .seq-item-head { color: #f97316; font-size: 11px; font-weight: 700; text-transform: uppercase; margin-bottom: 4px; }

  /* Rules editor layout */
  .rules-layout { display: flex; gap: 12px; height: calc(100vh - 130px); }
  .rules-left { width: 280px; flex-shrink: 0; background: #1e293b; border-radius: 8px; display: flex; flex-direction: column; overflow: hidden; }
  .rules-left-header { padding: 10px 12px; border-bottom: 1px solid #334155; display: flex; gap: 8px; align-items: center; flex-wrap: wrap; }
  .rules-left-header select { flex: 1; margin: 0; padding: 5px; min-width: 120px; }
  .rules-list { flex: 1; overflow-y: auto; }
  .rules-count-footer { padding: 8px 12px; border-top: 1px solid #334155; font-size: 12px; text-align: center; flex-shrink: 0; }
  .rule-count-badge { display: inline-block; background: #334155; color: #e2e8f0; padding: 1px 8px; border-radius: 10px; font-size: 11px; font-weight: 600; margin-left: 6px; vertical-align: middle; }
  .rule-item { padding: 10px 14px; border-bottom: 1px solid #334155; cursor: pointer; display: flex; flex-direction: column; gap: 2px; }
  .rule-item:hover { background: #334155; }
  .rule-item.active { background: #1e3a5f; border-left: 3px solid #3b82f6; }
  .rule-item .ri-name { font-size: 13px; font-weight: 500; }
  .rule-item .ri-id { font-size: 11px; color: #64748b; font-family: monospace; }
  .rule-item .ri-meta { display: flex; gap: 6px; align-items: center; margin-top: 2px; }
  /* Select mode: a checkbox column in front of the rule text. */
  .rule-item.sel { cursor: default; flex-direction: row; align-items: flex-start; gap: 8px; }
  .rule-item.sel input { margin-top: 3px; cursor: pointer; flex-shrink: 0; }
  .rule-item .ri-body { flex: 1; min-width: 0; }
  .rules-right { flex: 1; background: #1e293b; border-radius: 8px; display: flex; flex-direction: column; overflow: hidden; }
  .rules-right-header { padding: 10px 14px; border-bottom: 1px solid #334155; display: flex; gap: 10px; align-items: center; flex-wrap: wrap; }
  .rules-right-header .title { font-weight: 600; font-size: 14px; flex: 1; }
  .rules-editor { flex: 1; display: flex; flex-direction: column; overflow: hidden; }
  .rules-editor textarea { flex: 1; margin: 0; border: none; border-radius: 0; min-height: 0; font-size: 13px; line-height: 1.5; }
  .rules-editor-footer { padding: 10px 14px; border-top: 1px solid #334155; display: flex; gap: 10px; align-items: center; flex-shrink: 0; }
  .validation-status { font-size: 12px; flex: 1; }
  .validation-status.ok { color: #22c55e; }
  .validation-status.err { color: #ef4444; }
  .validation-status.checking { color: #f59e0b; }
  .empty-state { display: flex; align-items: center; justify-content: center; height: 100%; color: #64748b; font-size: 14px; }
  /* Modal */
  .modal-overlay { position: fixed; inset: 0; background: rgba(0,0,0,0.6); display: flex; align-items: center; justify-content: center; z-index: 1000; }
  .modal { background: #1e293b; border: 1px solid #334155; border-radius: 10px; width: 640px; max-width: 92vw; max-height: 88vh; overflow: auto; box-shadow: 0 10px 40px rgba(0,0,0,0.5); }
  .modal-header { display: flex; align-items: center; justify-content: space-between; padding: 14px 18px; border-bottom: 1px solid #334155; }
  .modal-header h3 { margin: 0; font-size: 16px; }
  .modal-close { background: none; border: none; color: #94a3b8; font-size: 22px; cursor: pointer; line-height: 1; }
  .modal-close:hover { color: #e2e8f0; }
  .modal-body { padding: 16px 18px; }
  .modal-body code { background: #0f172a; padding: 1px 5px; border-radius: 3px; font-size: 12px; }
  .modal-footer { display: flex; gap: 8px; justify-content: flex-end; margin-top: 12px; }
  .modal-warn { background: #422006; border: 1px solid #b45309; color: #fbbf24; padding: 8px 10px; border-radius: 6px; font-size: 12px; margin-bottom: 12px; }
  .btn.success { background: #16a34a; }
  .btn.success:hover { background: #15803d; }
  .btn.sm { padding: 4px 10px; font-size: 12px; }

  /* Indeterminate progress bar animation (used by the import modal). */
  @keyframes importBarSlide {
    0% { margin-left: -30%; }
    50% { margin-left: 100%; }
    100% { margin-left: -30%; }
  }

  /* Custom datetime picker (replaces native datetime-local so a "Now" button
     can live inside the calendar popup). */
  .dt-input { padding: 4px 6px; background: #0f172a; border: 1px solid #334155; border-radius: 4px; color: #e2e8f0; font-size: 13px; font-family: monospace; cursor: pointer; }
  .dt-input:hover { border-color: #3b82f6; }
  .dt-pop { position: absolute; z-index: 1100; background: #1e293b; border: 1px solid #334155; border-radius: 8px; box-shadow: 0 10px 40px rgba(0,0,0,0.5); padding: 12px; width: 260px; font-size: 13px; }
  .dt-pop-head { display: flex; align-items: center; justify-content: space-between; margin-bottom: 8px; }
  .dt-pop-head button { background: #334155; color: #e2e8f0; border: none; border-radius: 4px; padding: 2px 8px; cursor: pointer; font-size: 14px; line-height: 1; }
  .dt-pop-head button:hover { background: #475569; }
  .dt-pop-head .dt-label { font-weight: 600; }
  .dt-pop-grid { display: grid; grid-template-columns: repeat(7, 1fr); gap: 2px; }
  .dt-pop-grid .dt-dow { text-align: center; font-size: 11px; color: #64748b; padding: 2px 0; }
  .dt-pop-grid .dt-day { text-align: center; padding: 5px 0; border-radius: 4px; cursor: pointer; font-size: 12px; }
  .dt-pop-grid .dt-day:hover { background: #334155; }
  .dt-pop-grid .dt-day.other { color: #475569; }
  .dt-pop-grid .dt-day.today { outline: 1px solid #3b82f6; }
  .dt-pop-grid .dt-day.sel { background: #3b82f6; color: white; }
  .dt-pop-time { display: flex; align-items: center; gap: 6px; margin-top: 10px; justify-content: center; }
  .dt-pop-time input { width: 50px; padding: 3px 4px; margin: 0; background: #0f172a; border: 1px solid #334155; border-radius: 4px; color: #e2e8f0; font-size: 13px; font-family: monospace; text-align: center; }
  .dt-pop-time span { color: #64748b; }
  .dt-pop-actions { display: flex; gap: 8px; margin-top: 12px; justify-content: flex-end; }

  /* Group cards (always-visible summary, click to expand settings) */
  .g-card { background: #1e293b; border: 1px solid #334155; border-radius: 8px; margin-bottom: 12px; overflow: hidden; }
  .g-card-head { display: flex; align-items: center; gap: 12px; padding: 12px 16px; cursor: pointer; }
  .g-card-head:hover { background: #243345; }
  .g-card-head .g-chev { user-select: none; color: #94a3b8; font-size: 12px; width: 14px; }
  .g-card-head .g-name { font-weight: 600; font-size: 14px; }
  .g-card-head .g-desc { color: #64748b; font-size: 12px; flex: 1; }
  .g-card-head .g-count { background: #334155; color: #cbd5e1; padding: 2px 10px; border-radius: 10px; font-size: 11px; white-space: nowrap; }
  .g-card-body { display: none; padding: 12px 16px; border-top: 1px solid #334155; background: #0f172a; }
  .g-card-body.open { display: block; }
  .g-dest-row { display: flex; gap: 6px; margin-bottom: 6px; }
  .g-dest-row input { margin: 0; }
  .g-dest-row .g-dn { width: 130px; flex-shrink: 0; }
  .g-dest-row .g-du { flex: 1; }
  .g-dest-row .g-dx { background: #334155; color: #e2e8f0; border: none; border-radius: 4px; cursor: pointer; padding: 0 10px; font-size: 16px; line-height: 1; flex-shrink: 0; }
  .g-dest-row .g-dx:hover { background: #ef4444; }

  /* Docs page */
  .docs-layout { display: flex; gap: 16px; height: calc(100vh - 130px); align-items: stretch; }
  .docs-toc { display: block; width: 230px; flex-shrink: 0; background: #1e293b; border-radius: 8px; padding: 14px 10px; overflow-y: auto; }
  .docs-toc .dt-title { font-size: 11px; text-transform: uppercase; letter-spacing: 0.5px; color: #64748b; margin: 12px 6px 4px; }
  .docs-toc .dt-title:first-child { margin-top: 0; }
  .docs-toc a { display: block; color: #94a3b8; text-decoration: none; font-size: 13px; padding: 5px 10px; border-radius: 4px; border-left: 2px solid transparent; }
  .docs-toc a:hover { background: #334155; color: #e2e8f0; }
  .docs-toc a.active { background: #1e3a5f; color: #e2e8f0; border-left-color: #3b82f6; }
  .docs-content { flex: 1; min-width: 0; background: #1e293b; border-radius: 8px; padding: 24px 32px; overflow-y: auto; scroll-behavior: smooth; }
  .docs-content h2 { font-size: 20px; margin: 32px 0 12px; padding-bottom: 8px; border-bottom: 1px solid #334155; color: #e2e8f0; scroll-margin-top: 16px; }
  .docs-content h2:first-child { margin-top: 0; }
  .docs-content h3 { font-size: 16px; margin: 22px 0 8px; color: #93c5fd; scroll-margin-top: 16px; }
  .docs-content h4 { font-size: 14px; margin: 16px 0 6px; color: #94a3b8; }
  .docs-content p { line-height: 1.65; margin: 8px 0; font-size: 14px; color: #cbd5e1; }
  .docs-content ul, .docs-content ol { margin: 8px 0; padding-left: 22px; color: #cbd5e1; }
  .docs-content li { line-height: 1.65; margin: 4px 0; font-size: 14px; }
  .docs-content code { background: #0f172a; padding: 1px 6px; border-radius: 3px; font-size: 12px; color: #fbbf24; font-family: monospace; }
  .docs-content pre { background: #0f172a; border: 1px solid #334155; border-radius: 6px; padding: 12px 14px; overflow-x: auto; margin: 10px 0; max-height: none; }
  .docs-content pre code { background: none; padding: 0; color: #e2e8f0; font-size: 12px; }
  .docs-content table { margin: 10px 0; font-size: 13px; }
  .docs-content th { background: #334155; }
  .docs-content .callout { background: #172554; border: 1px solid #1e40af; border-left: 4px solid #3b82f6; border-radius: 6px; padding: 10px 14px; margin: 12px 0; font-size: 13px; line-height: 1.55; }
  .docs-content .callout.warn { background: #422006; border-color: #b45309; border-left-color: #f59e0b; }
  .docs-content .callout.good { background: #052e16; border-color: #166534; border-left-color: #22c55e; }
  .docs-content .callout code { color: #93c5fd; }
  .docs-content .callout.warn code { color: #fbbf24; }
  .docs-content .lead { font-size: 15px; color: #e2e8f0; }

  /* Metrics page: chart controls and chart cards */
  .metrics-presets { display: flex; gap: 6px; flex-wrap: wrap; }
  .metrics-preset { background: #334155; color: #e2e8f0; border: 1px solid transparent; border-radius: 6px; padding: 5px 12px; cursor: pointer; font-size: 12px; }
  .metrics-preset:hover { background: #475569; }
  .metrics-preset.active { background: #1e3a5f; border-color: #3b82f6; color: #93c5fd; }
  .metrics-chart-card { background: #0f172a; border: 1px solid #334155; border-radius: 8px; padding: 14px 16px; margin-bottom: 16px; }
  .metrics-chart-card h4 { margin: 0 0 8px 0; font-size: 14px; color: #94a3b8; display: flex; align-items: center; gap: 10px; }
  .metrics-chart-card h4 .metrics-chart-total { margin-left: auto; font-size: 13px; color: #e2e8f0; font-weight: 600; }
  .metrics-chart-wrap { position: relative; height: 280px; }
  .metrics-controls { display: flex; align-items: center; gap: 12px; margin: 16px 0; flex-wrap: wrap; font-size: 13px; }
  .metrics-controls label { display: flex; align-items: center; gap: 4px; margin: 0; color: #94a3b8; }
  .metrics-controls select { width: auto; min-width: 180px; margin: 0; padding: 5px 8px; }
  .metrics-note { background: #172554; border: 1px solid #1e40af; border-left: 4px solid #3b82f6; border-radius: 6px; padding: 8px 12px; font-size: 12px; color: #cbd5e1; margin: 12px 0; line-height: 1.5; }
  /* Role-based UI hiding. The body gets a class based on the current
     user's role (role-admin, role-editor, role-viewer). Elements marked
     with .admin-only or .editor-only are hidden unless the user has the
     matching role. */
  body.role-viewer .admin-only, body.role-viewer .editor-only { display: none !important; }
  body.role-editor .admin-only { display: none !important; }
</style>
<script src="/static/chart.umd.min.js"></script>
</head>
<body>
<!-- Login overlay: shown when GET /auth/me returns 401. Covers the app
     until the user authenticates. The app HTML below is still present so
     that after login the JS can populate it without a page reload. -->
<div id="login-overlay" style="display:none;position:fixed;inset:0;background:#0f172a;z-index:9999;align-items:center;justify-content:center">
  <div style="width:320px;padding:32px;background:#1e293b;border:1px solid #334155;border-radius:10px;box-shadow:0 10px 40px rgba(0,0,0,0.5)">
    <h2 style="margin:0 0 8px;text-align:center">ELF Login</h2>
    <p style="margin:0 0 20px;text-align:center;font-size:13px" class="muted">Sign in to manage agents and rules</p>
    <form id="login-form" onsubmit="return doLogin(event)">
      <input id="login-user" type="text" placeholder="Username" autocomplete="username" required autofocus
             style="width:100%;margin-bottom:12px;padding:8px;font-family:system-ui,sans-serif">
      <input id="login-pass" type="password" placeholder="Password" autocomplete="current-password" required
             style="width:100%;margin-bottom:16px;padding:8px;font-family:system-ui,sans-serif">
      <button type="submit" class="btn success" style="width:100%">Sign in</button>
    </form>
    <p id="login-error" style="display:none;margin:12px 0 0;color:#ef4444;font-size:13px;text-align:center"></p>
  </div>
</div>
<header>
  <h1>ELF Management</h1>
  <nav>
    <button id="tab-agents" class="active" onclick="showTab('agents')">Agents</button>
    <button id="tab-groups" onclick="showTab('groups')">Groups</button>
    <button id="tab-rules" onclick="showTab('rules')">Rules</button>
    <button id="tab-lists" onclick="showTab('lists')">Lists</button>
    <button id="tab-alerts" onclick="showTab('alerts')">Alerts</button>
    <button id="tab-metrics" onclick="showTab('metrics')">Metrics</button>
    <button id="tab-logs" onclick="showTab('logs')">Logs</button>
    <button id="tab-users" onclick="showTab('users')" style="display:none">Users</button>
    <button id="tab-audit" onclick="showTab('audit')" style="display:none">Audit</button>
    <button id="tab-docs" onclick="showTab('docs')">Docs</button>
  </nav>
  <button class="btn success admin-only" style="margin-left:auto" onclick="openAddAgent()" title="Generate an offline install script for a new host">+ Add New Agent</button>
  <label style="font-size:13px;font-weight:normal;display:flex;align-items:center;gap:4px;cursor:pointer;margin-left:12px"><input type="checkbox" id="global-autorefresh" onchange="setAutoRefresh(this.checked)" style="cursor:pointer"> Auto-refresh</label>
  <span id="global-autorefresh-status" class="muted" style="font-size:12px"></span>
  <span id="user-info" style="display:none;margin-left:12px;font-size:13px;align-items:center;gap:8px">
    <span id="user-name" class="muted"></span>
    <span id="user-role" class="badge medium" style="font-size:11px"></span>
    <button class="btn secondary sm" onclick="doLogout()" title="Sign out">Logout</button>
  </span>
</header>
<main>
  <!-- Add New Agent modal -->
  <div id="add-agent-modal" class="modal-overlay" style="display:none">
    <div class="modal">
      <div class="modal-header">
        <h3>Add New Agent</h3>
        <button class="modal-close" onclick="closeAddAgent()">&times;</button>
      </div>
      <div class="modal-body">
        <p class="muted" style="margin-top:0">Generate an install script for a new host. The script downloads the agent from this server, installs it as a <strong>least-privilege service</strong> that starts at boot, writes its config with <code>agent_id</code> set to the host's name, registers it in the chosen group and starts it. No internet access is needed on the target.</p>
        <div id="add-agent-binary-warn" class="modal-warn" style="display:none"></div>
        <label>Operating system</label>
        <div style="display:flex;gap:16px;flex-wrap:wrap;margin:4px 0 8px 0">
          <label style="display:flex;align-items:center;gap:6px;font-size:13px;font-weight:normal;cursor:pointer">
            <input type="radio" name="add-agent-os" id="add-agent-os-windows" value="windows" checked onchange="toggleInstallMode()" style="width:auto;margin:0">
            Windows <span class="muted" style="font-size:11px">(PowerShell, Windows service)</span>
          </label>
          <label style="display:flex;align-items:center;gap:6px;font-size:13px;font-weight:normal;cursor:pointer">
            <input type="radio" name="add-agent-os" id="add-agent-os-linux" value="linux" onchange="toggleInstallMode()" style="width:auto;margin:0">
            Linux <span class="muted" style="font-size:11px">(bash, systemd unit, journald)</span>
          </label>
        </div>
        <label>Group</label>
        <select id="add-agent-group"></select>
        <div id="add-agent-windows-account">
        <label style="margin-top:10px">Service account</label>
        <div style="display:flex;gap:16px;flex-wrap:wrap;margin:4px 0 8px 0">
          <label style="display:flex;align-items:center;gap:6px;font-size:13px;font-weight:normal;cursor:pointer">
            <input type="radio" name="add-agent-mode" id="add-agent-mode-local" value="local" checked onchange="toggleInstallMode()" style="width:auto;margin:0">
            Create a local service account <span class="muted" style="font-size:11px">(default, self-contained)</span>
          </label>
          <label style="display:flex;align-items:center;gap:6px;font-size:13px;font-weight:normal;cursor:pointer">
            <input type="radio" name="add-agent-mode" id="add-agent-mode-domain" value="domain" onchange="toggleInstallMode()" style="width:auto;margin:0">
            Use an existing domain account
          </label>
        </div>
        <div id="add-agent-domain-fields" style="display:none">
          <div class="row">
            <div>
              <label>Domain (NetBIOS or FQDN)</label>
              <input type="text" id="add-agent-domain" placeholder="CORP" autocomplete="off" />
            </div>
            <div>
              <label>Username</label>
              <input type="text" id="add-agent-username" placeholder="svc-elf-agent" autocomplete="off" />
            </div>
          </div>
          <p class="muted" style="font-size:11px;margin:4px 0 8px 0">The account must already exist in AD. The generated script prompts for the password <strong>securely at install time</strong> on the target host (masked input); the password is never stored in the script, the clipboard, or this server. See the <a href="#" onclick="showTab('docs');docScroll('svc-account');return false" style="color:#93c5fd">docs</a> for the rights the account needs.</p>
        </div>
        </div>
        <div id="add-agent-linux-account" style="display:none">
        <label style="margin-top:10px">Service account</label>
        <div style="display:flex;gap:16px;flex-wrap:wrap;margin:4px 0 8px 0">
          <label style="display:flex;align-items:center;gap:6px;font-size:13px;font-weight:normal;cursor:pointer">
            <input type="radio" name="add-agent-linux-mode" id="add-agent-linux-mode-local" value="local" checked onchange="toggleInstallMode()" style="width:auto;margin:0">
            Create a system user <code>elf</code> <span class="muted" style="font-size:11px">(default: no shell, no home directory)</span>
          </label>
          <label style="display:flex;align-items:center;gap:6px;font-size:13px;font-weight:normal;cursor:pointer">
            <input type="radio" name="add-agent-linux-mode" id="add-agent-linux-mode-existing" value="existing" onchange="toggleInstallMode()" style="width:auto;margin:0">
            Use an existing account
          </label>
        </div>
        <div id="add-agent-linux-user-fields" style="display:none">
          <label>Username</label>
          <input type="text" id="add-agent-linux-user" placeholder="svc-elf" autocomplete="off" />
          <p class="muted" style="font-size:11px;margin:4px 0 8px 0">The account must already exist on the host. The script adds it to the <code>systemd-journal</code> group and makes it the owner of <code>/var/lib/elf</code>; nothing else about it changes.</p>
        </div>
        <label style="display:flex;align-items:center;gap:6px;font-size:13px;font-weight:normal;cursor:pointer;margin:4px 0 8px 0">
          <input type="checkbox" id="add-agent-audit-execve" style="width:auto;margin:0">
          Also add an auditd rule that records program executions <span class="muted" style="font-size:11px">(what process_creation rules evaluate; needs auditd on the host)</span>
        </label>
        </div>
        <label>Install script</label>
        <textarea id="add-agent-script" rows="10" readonly placeholder="Click Generate to build the install script (.ps1)..."></textarea>
        <div class="modal-footer">
          <button class="btn secondary" onclick="closeAddAgent()">Close</button>
          <button class="btn" onclick="generateInstallScript()">Generate</button>
          <button class="btn success" onclick="copyInstallScript()" disabled id="add-agent-copy">Copy</button>
          <button class="btn secondary" onclick="downloadInstallScript()" disabled id="add-agent-download">Download .ps1</button>
        </div>
        <details style="margin-top:12px">
          <summary style="cursor:pointer;font-size:13px;color:#94a3b8">Troubleshooting: cleanup script</summary>
          <div style="margin-top:10px">
            <p class="muted" style="font-size:12px;margin-top:0">If a previous install failed partway through and left a half-installed state (locked-down data dir, service that won't start, stale user with rights), run this cleanup script first. On Windows it removes the service, the local service account, group memberships, LSA rights (including those granted to a domain account on this host), and both directories. On Linux it removes the systemd unit, the directories, the audit rule and the dedicated <code>elf</code> user. Safe to run multiple times. After it completes, re-run the install script.</p>
            <textarea id="cleanup-script" rows="6" readonly placeholder="Loading cleanup script..."></textarea>
            <div class="modal-footer" style="margin-top:8px">
              <button class="btn success" onclick="copyCleanupScript()" disabled id="cleanup-copy">Copy</button>
              <button class="btn secondary" onclick="downloadCleanupScript()" disabled id="cleanup-download">Download .ps1</button>
            </div>
          </div>
        </details>
      </div>
    </div>
  </div>
  <!-- Bulk rule import modal -->
  <div id="import-rules-modal" class="modal-overlay" style="display:none">
    <div class="modal" style="width:760px">
      <div class="modal-header">
        <h3>Import Sigma rules in bulk</h3>
        <button class="modal-close" onclick="closeImportModal()">&times;</button>
      </div>
      <div class="modal-body">
        <p class="muted" style="margin-top:0">Import many Sigma rules at once. Each rule gets an <code>elf:</code> block injected based on the severity→action map you choose below. Rules are added to the currently selected group. Use <strong>Preview</strong> first to validate and count without saving, then <strong>Import</strong> to commit.</p>

        <div style="display:flex;gap:16px;flex-wrap:wrap;margin-bottom:14px">
          <div style="flex:1;min-width:280px">
            <label style="font-size:13px;margin-bottom:6px;display:block">Source: upload a zip</label>
            <div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap">
              <input type="file" id="import-file" accept=".zip" style="flex:1;min-width:180px" />
              <button class="btn secondary sm" onclick="importFromZip(true)">Preview zip</button>
            </div>
            <p class="muted" style="font-size:11px;margin:4px 0 0 0">Upload a <code>.zip</code> of Sigma <code>.yml</code> files (folders allowed).</p>
          </div>
          <div style="flex:1;min-width:280px">
            <label style="font-size:13px;margin-bottom:6px;display:block">Or fetch from SigmaHQ release</label>
            <div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap">
              <input type="text" id="import-sigmahq-tag" value="r2026-07-01" placeholder="release tag" style="padding:5px 8px;width:130px;font-size:12px;background:#0f172a;border:1px solid #334155;border-radius:4px;color:#e2e8f0" />
              <button class="btn secondary sm" onclick="loadSigmaAssets()">List assets</button>
            </div>
            <p class="muted" style="font-size:11px;margin:4px 0 0 0">Choose which SigmaHQ release packages to import (curated, small zips).</p>
          </div>
        </div>

        <div id="import-sigmahq-assets" style="display:none;margin-bottom:14px">
          <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:6px">
            <label style="font-size:13px;display:block">SigmaHQ release assets <span id="import-sigmahq-tag-label" class="muted" style="font-size:11px"></span></label>
            <span class="muted" style="font-size:11px">check the packages you want, then Preview</span>
          </div>
          <div id="import-sigmahq-asset-list" style="max-height:180px;overflow:auto;background:#0f172a;border:1px solid #334155;border-radius:6px;padding:8px 10px"></div>
          <div style="display:flex;gap:8px;margin-top:8px;flex-wrap:wrap">
            <button class="btn secondary sm" onclick="importFromSigmaHQ(true)">Preview selected</button>
            <span id="import-sigmahq-assets-status" class="muted" style="font-size:12px;align-self:center"></span>
          </div>
        </div>

        <details style="margin-bottom:14px">
          <summary style="cursor:pointer;font-size:13px;color:#94a3b8;padding:6px 0">Filters &amp; options</summary>
          <div style="margin-top:10px;display:flex;gap:12px;flex-wrap:wrap">
            <div>
              <label style="font-size:12px;display:block;margin-bottom:4px">Logsource product filter</label>
              <select id="import-logsource-filter" style="padding:5px;min-width:120px">
                <option value="windows" selected>windows</option>
                <option value="linux">linux</option>
                <option value="">any (no filter)</option>
              </select>
            </div>
            <div>
              <label style="font-size:12px;display:block;margin-bottom:4px">Existing rules</label>
              <select id="import-overwrite" style="padding:5px;min-width:120px">
                <option value="0" selected>Skip (keep existing)</option>
                <option value="1">Overwrite in place</option>
              </select>
            </div>
          </div>
        </details>

        <label style="font-size:13px;margin-bottom:6px;display:block">Severity → action map <span class="muted" style="font-size:11px">(check <strong>import</strong> for each severity you want to bring in, then check the actions to inject for it; uncheck <strong>import</strong> to skip that severity entirely)</span></label>
        <div id="import-severity-map" style="display:flex;flex-direction:column;gap:8px;margin-bottom:14px"></div>

        <div id="import-progress" style="display:none;margin-bottom:10px">
          <div style="display:flex;justify-content:space-between;font-size:12px;margin-bottom:4px">
            <span id="import-progress-label" class="muted">Working…</span>
            <span id="import-progress-pct" class="muted"></span>
          </div>
          <div style="height:8px;background:#0f172a;border:1px solid #334155;border-radius:4px;overflow:hidden">
            <div id="import-progress-bar" style="height:100%;width:0%;background:#3b82f6;transition:width 0.2s"></div>
          </div>
        </div>

        <div id="import-status" class="muted" style="font-size:13px;margin-bottom:10px"></div>
        <div id="import-results" style="display:none">
          <h4 style="margin:10px 0 6px 0;font-size:14px">Preview results</h4>
          <div id="import-summary" style="font-size:13px;margin-bottom:10px"></div>
          <div id="import-errors" style="display:none;max-height:160px;overflow:auto;background:#0f172a;border:1px solid #334155;border-radius:6px;padding:8px 10px;font-size:12px;margin-bottom:10px"></div>
          <div id="import-preview-table" style="max-height:240px;overflow:auto;border:1px solid #334155;border-radius:6px"></div>
        </div>

        <div class="modal-footer">
          <button class="btn secondary" onclick="closeImportModal()">Close</button>
          <button class="btn" id="import-commit-btn" onclick="importCommit()" disabled>Import <span id="import-commit-count"></span></button>
        </div>
      </div>
    </div>
  </div>
  <div id="agents" class="tab">
    <div class="card">
      <h3 style="display:flex;align-items:center;gap:12px;flex-wrap:wrap">Registered Agents
        <button class="btn secondary sm" onclick="loadAgents()" title="Refresh agents now">↻ Refresh</button>
        <button class="btn secondary sm" onclick="exportAgentsCsv()" title="Download agents as CSV">⬇ Export CSV</button>
        <input id="agents-search" type="search" placeholder="Search hostname or IP…" oninput="filterAgents()" style="margin-left:auto;max-width:280px;padding:6px 10px;font-size:13px;background:#0f172a;border:1px solid #334155;border-radius:6px;color:#e2e8f0" />
      </h3>
      <table id="agents-table"><thead><tr><th>Agent ID</th><th>Hostname</th><th>IP Address</th><th>OS</th><th>Group</th><th>Last Seen</th><th>First Seen</th><th>Status</th><th></th></tr></thead><tbody></tbody></table>
    </div>
  </div>
  <div id="groups" class="tab" style="display:none">
    <div class="card">
      <div style="display:flex;align-items:center;gap:12px">
        <h3 style="margin:0">Groups</h3>
        <button class="btn success sm" id="g-toggle" onclick="toggleGroupForm()" title="Create a new group">+ Create Group</button>
      </div>
      <div id="g-form" style="display:none;margin-top:14px;border-top:1px solid #334155;padding-top:14px">
        <div class="row">
          <div>
            <label>Group name</label>
            <input id="g-name" placeholder="e.g. workstations" />
          </div>
          <div>
            <label>Description</label>
            <input id="g-desc" placeholder="What this group is for" />
          </div>
        </div>
        <div class="row">
          <div>
            <label>Retention (seconds)</label>
            <input id="g-retention" type="number" min="1" value="30" />
          </div>
          <div>
            <label>Poll interval (seconds)</label>
            <input id="g-poll" type="number" min="1" value="30" />
          </div>
        </div>
        <div style="margin-top:4px">
          <label>Destinations (name → URL, one per line; add <code>?format=json|ecs|hec|gelf|sentinel</code> for SIEM output; see Docs → Destinations)</label>
          <textarea id="g-dests" rows="4" placeholder="siem = file://output/siem.ndjson?format=ecs&#10;splunk = https://splunk.example.com:8088/services/collector/event?format=hec&amp;token=…&#10;alerts = file://output/alerts.jsonl" style="font-size:13px"></textarea>
        </div>
        <div style="display:flex;gap:8px;justify-content:flex-end;margin-top:4px">
          <button class="btn secondary" onclick="toggleGroupForm()">Cancel</button>
          <button class="btn admin-only" id="g-save-btn" onclick="createGroup()">Create Group</button>
        </div>
      </div>
    </div>
    <div id="groups-list"></div>
  </div>
  <div id="rules" class="tab" style="display:none">
    <div class="rules-layout">
      <div class="rules-left">
        <div class="rules-left-header">
          <select id="rule-group-filter" onchange="loadRules()" title="Filter rules by group"></select>
          <button class="btn success" onclick="newRule()" title="Create a new rule">+ New</button>
          <button class="btn secondary" onclick="openImportModal()" title="Import many Sigma rules at once">⬆ Import</button>
          <button class="btn secondary" id="rule-select-toggle" onclick="toggleRuleSelectMode()" title="Select rules to delete in bulk">☑ Select</button>
          <input id="rules-search" type="search" placeholder="Search rules…" oninput="renderRulesList()" title="Filter by name, id, or severity" style="flex-basis:100%;margin:0;padding:5px 8px;font-size:12px;background:#0f172a;border:1px solid #334155;border-radius:4px;color:#e2e8f0" />
        </div>
        <div id="rule-select-bar" style="display:none;padding:8px 12px;border-bottom:1px solid #334155;background:#0f172a;gap:8px;align-items:center;flex-wrap:wrap">
          <label style="display:flex;align-items:center;gap:4px;font-size:12px;cursor:pointer;font-weight:600">
            <input type="checkbox" id="rule-select-all" onchange="toggleAllRuleCheckboxes(this.checked)" style="cursor:pointer">
            <span id="rule-select-all-label">Select all</span>
          </label>
          <span id="rule-select-count" class="muted" style="font-size:12px">0 selected</span>
          <span style="flex:1"></span>
          <button class="btn secondary sm" onclick="toggleRuleSelectMode()">Cancel</button>
          <button class="btn danger sm" id="rule-bulk-delete-btn" onclick="confirmBulkDeleteRules()" disabled>Delete</button>
        </div>
        <div class="rules-list" id="rules-list"></div>
        <div id="rules-count-footer" class="rules-count-footer muted" style="display:none"></div>
      </div>
      <div class="rules-right">
        <div id="rules-editor-pane" class="rules-editor" style="display:none">
          <textarea id="r-yaml" placeholder="title: My Rule&#10;id: win_my_rule&#10;status: stable&#10;level: medium&#10;logsource:&#10;  product: windows&#10;  service: security&#10;detection:&#10;  selection:&#10;    EventID: 4624&#10;  condition: selection&#10;elf:&#10;  actions:&#10;    - type: forward_event&#10;      destination: siem" spellcheck="false" oninput="scheduleValidate()"></textarea>
          <div class="rules-editor-footer">
            <span id="validation-status" class="validation-status muted">Type to validate YAML...</span>
            <a href="https://github.com/SigmaHQ/sigmahq.github.io/tree/main/docs" target="_blank" rel="noopener" style="font-size:12px;color:#60a5fa;text-decoration:none;margin-right:8px" title="Open the Sigma rule documentation">📖 Sigma docs ↗</a>
            <button class="btn secondary" onclick="cancelEdit()">Cancel</button>
            <button class="btn danger" onclick="deleteCurrentRule()">Delete</button>
            <button class="btn" id="save-rule-btn" onclick="saveRule()" disabled>Save Rule</button>
          </div>
        </div>
        <div id="rules-empty" class="empty-state">Select a rule on the left, or click <b>+ New</b> to create one.<br><span style="font-size:12px;margin-top:8px;display:block">Rules follow the <a href="https://github.com/SigmaHQ/sigmahq.github.io/tree/main/docs" target="_blank" rel="noopener" style="color:#60a5fa">Sigma standard</a>.</span></div>
      </div>
    </div>
  </div>
  <div id="lists" class="tab" style="display:none">
    <div class="rules-layout">
      <div class="rules-left">
        <div class="rules-left-header">
          <span class="muted" style="font-size:13px;align-self:center">Reusable lists (referenced as <code>@@name</code>)</span>
          <button class="btn success" onclick="newList()" title="Create a new list">+ New</button>
        </div>
        <div class="rules-list" id="lists-list"></div>
      </div>
      <div class="rules-right">
        <div id="lists-editor-pane" class="rules-editor" style="display:none">
          <label style="font-size:13px;margin-bottom:6px;display:block">List name</label>
          <input id="l-name" placeholder="e.g. sensitive_processes" style="margin-bottom:10px" />
          <label style="font-size:13px;margin-bottom:6px;display:block">Content (one value per line; lines starting with <code>#</code> are comments)</label>
          <textarea id="l-content" placeholder="# Sensitive processes&#10;calc.exe&#10;notepad.exe" spellcheck="false"></textarea>
          <div class="rules-editor-footer">
            <span id="list-status" class="validation-status muted">Enter a name and content...</span>
            <button class="btn secondary" onclick="cancelListEdit()">Cancel</button>
            <button class="btn danger" onclick="deleteCurrentList()">Delete</button>
            <button class="btn" id="save-list-btn" onclick="saveList()">Save List</button>
          </div>
        </div>
        <div id="lists-empty" class="empty-state">Select a list on the left, or click <b>+ New</b> to create one.<br><span style="font-size:12px;margin-top:8px;display:block">Lists are newline-separated values shared across all groups. Rules reference them with <code>@@name</code>.</span></div>
      </div>
    </div>
  </div>
  <div id="alerts" class="tab" style="display:none">
    <div class="card">
      <h3 style="display:flex;align-items:center;gap:12px;flex-wrap:wrap">Recent Alerts
        <button class="btn secondary sm" onclick="loadAlerts()" title="Refresh alerts now">↻ Refresh</button>
        <input id="alerts-search" type="search" placeholder="Search rule, message, agent…" oninput="onAlertsSearchInput()" title="Filter alerts by substring" style="margin-left:auto;max-width:260px;padding:6px 10px;font-size:13px;background:#0f172a;border:1px solid #334155;border-radius:6px;color:#e2e8f0" />
        <select id="alerts-sort" onchange="onAlertsSortChange()" title="Sort order" style="width:auto;margin:0;padding:6px 8px;font-size:13px;background:#0f172a;border:1px solid #334155;border-radius:6px;color:#e2e8f0">
          <option value="recency">Newest first</option>
          <option value="severity">Severity first</option>
        </select>
        <button class="btn danger sm admin-only" onclick="clearAlerts()" title="Delete all stored alerts">Clear All</button>
      </h3>
      <table id="alerts-table"><thead><tr><th>ID</th><th>Time</th><th>Agent</th><th>Rule</th><th>Severity</th><th>Message</th><th>Details</th></tr></thead><tbody></tbody></table>
      <div id="alerts-pager" style="display:flex;align-items:center;gap:12px;justify-content:center;margin-top:10px"></div>
    </div>
  </div>
  <div id="metrics" class="tab" style="display:none">
    <div class="card">
      <h3 style="display:flex;align-items:center;gap:12px;flex-wrap:wrap">Metrics
        <button class="btn secondary sm" onclick="refreshMetricsView()" title="Refresh now" style="margin-left:auto">↻ Refresh</button>
        <button class="btn danger sm admin-only" onclick="resetMetrics()" title="Zero all agent counters and delete stored forwarded logs (alerts are kept)">Reset Metrics</button>
      </h3>

      <!-- Savings statistics -->
      <h4 style="margin:0 0 8px 0;font-size:14px;color:#94a3b8">Savings</h4>
      <div id="metrics-savings-summary" style="display:flex;gap:24px;flex-wrap:wrap;margin-bottom:16px;font-size:14px"></div>
      <table id="metrics-savings-table"><thead><tr><th>Agent</th><th>Hostname</th><th>Events Created</th><th>Events Forwarded</th><th>% Forwarded</th><th>Bytes Created</th><th>Bytes Forwarded</th><th>Savings</th></tr></thead><tbody></tbody></table>

      <!-- Chart controls: presets, custom range, agent filter -->
      <h4 style="margin:24px 0 4px 0;font-size:14px;color:#94a3b8">Event count, bytes &amp; alerts over time</h4>
      <div class="metrics-controls">
        <div class="metrics-presets" id="metrics-presets">
          <button class="metrics-preset" data-span="3600" onclick="applyMetricsPreset(this, 3600)">1h</button>
          <button class="metrics-preset active" data-span="86400" onclick="applyMetricsPreset(this, 86400)">24h</button>
          <button class="metrics-preset" data-span="604800" onclick="applyMetricsPreset(this, 604800)">7d</button>
          <button class="metrics-preset" data-span="2592000" onclick="applyMetricsPreset(this, 2592000)">30d</button>
          <button class="metrics-preset" data-span="0" onclick="applyMetricsPreset(this, 0)">All</button>
        </div>
        <label>From: <input type="text" id="metrics-date-from" readonly class="dt-input" onclick="openDtPicker('metrics-date-from')" placeholder="Click to set" /></label>
        <label>To: <input type="text" id="metrics-date-to" readonly class="dt-input" onclick="openDtPicker('metrics-date-to')" placeholder="Click to set" /></label>
        <label>Agent:
          <select id="metrics-agent-filter" onchange="refreshMetricsCharts()">
            <option value="">All agents</option>
          </select>
        </label>
        <span id="metrics-date-error" style="color:#ef4444;font-size:12px;display:none"></span>
      </div>

      <div class="metrics-note">
        <b>Forwarded vs. created.</b> These charts show what the server <em>received</em> (forwarded logs and alerts).
        The savings table above shows cumulative created-vs-forwarded counters per agent, but the agent only reports
        current snapshots; there is no historical "created over time" timeseries, so the charts cannot overlay it.
      </div>

      <!-- Event count chart -->
      <div class="metrics-chart-card">
        <h4>Events forwarded <span class="metrics-chart-total" id="metrics-count-total"></span></h4>
        <div class="metrics-chart-wrap"><canvas id="metrics-count-canvas"></canvas></div>
      </div>

      <!-- Bytes chart -->
      <div class="metrics-chart-card">
        <h4>Bytes forwarded <span class="metrics-chart-total" id="metrics-bytes-total"></span></h4>
        <div class="metrics-chart-wrap"><canvas id="metrics-bytes-canvas"></canvas></div>
      </div>

      <!-- Alerts chart -->
      <div class="metrics-chart-card">
        <h4>Alerts <span class="metrics-chart-total" id="metrics-alerts-total"></span></h4>
        <div class="metrics-chart-wrap"><canvas id="metrics-alerts-canvas"></canvas></div>
      </div>
    </div>
  </div>
  <div id="logs" class="tab" style="display:none">
    <div class="card">
      <h3 style="display:flex;align-items:center;gap:12px;flex-wrap:wrap">Forwarded Logs
        <button class="btn secondary sm" onclick="refreshLogsView()" title="Refresh now" style="margin-left:auto">↻ Refresh</button>
        <button class="btn danger sm admin-only" onclick="clearLogs()" title="Delete all stored logs">Clear All</button>
      </h3>
      <div id="logs-view-list">
        <div style="display:flex;align-items:center;gap:12px;margin-bottom:12px;font-size:13px;flex-wrap:wrap">
          <span class="muted">Logs text file:</span>
          <span id="logs-file-size" class="muted">-</span>
          <a href="/logs/text" target="_blank" class="btn secondary sm" title="Open the newline-separated logs text file">View text file</a>
          <a href="/logs/text" download="logs.txt" class="btn secondary sm" title="Download the logs text file">Download</a>
          <span class="muted" style="margin-left:12px">Max file size (MB, 0 = unlimited):</span>
          <input id="logs-max-size" type="number" min="0" max="10240" style="width:90px;padding:4px 6px;margin:0" />
          <button class="btn secondary sm" onclick="saveLogsMaxSize()" title="Save the max logs.txt size">Save</button>
        </div>
        <table id="logs-table"><thead><tr><th>ID</th><th>Agent</th><th>Rule</th><th>Alert ID</th><th>Events</th></tr></thead><tbody></tbody></table>
      </div>
    </div>
  </div>

  <!-- ===================== Docs tab ===================== -->
  <div id="docs" class="tab" style="display:none">
    <div class="docs-layout">
      <div class="docs-toc" id="docs-toc">
        <div class="dt-title">Getting started</div>
        <a href="#doc-overview" onclick="docScroll('overview');return false">Overview</a>
        <a href="#doc-how-it-works" onclick="docScroll('how-it-works');return false">How it works</a>
        <a href="#doc-install" onclick="docScroll('install');return false">Install your first agent</a>
        <a href="#doc-install-linux" onclick="docScroll('install-linux');return false">Linux hosts</a>
        <a href="#doc-svc-account" onclick="docScroll('svc-account');return false">Service accounts</a>
        <a href="#doc-antivirus" onclick="docScroll('antivirus');return false">Antivirus exclusions</a>
        <div class="dt-title">The web UI</div>
        <a href="#doc-ui-agents" onclick="docScroll('ui-agents');return false">Agents tab</a>
        <a href="#doc-ui-collect" onclick="docScroll('ui-collect');return false">Collect logs</a>
        <a href="#doc-ui-groups" onclick="docScroll('ui-groups');return false">Groups tab</a>
        <a href="#doc-ui-rules" onclick="docScroll('ui-rules');return false">Rules tab</a>
        <a href="#doc-ui-import" onclick="docScroll('ui-import');return false">Importing rules in bulk</a>
        <a href="#doc-ui-lists" onclick="docScroll('ui-lists');return false">Lists tab</a>
        <a href="#doc-ui-alerts" onclick="docScroll('ui-alerts');return false">Alerts tab</a>
        <a href="#doc-ui-metrics" onclick="docScroll('ui-metrics');return false">Metrics tab</a>
        <a href="#doc-ui-logs" onclick="docScroll('ui-logs');return false">Logs tab</a>
        <a href="#doc-ui-audit" onclick="docScroll('ui-audit');return false">Audit tab</a>
        <div class="dt-title">Building rules</div>
        <a href="#doc-rules-intro" onclick="docScroll('rules-intro');return false">Sigma rules overview</a>
        <a href="#doc-rules-fields" onclick="docScroll('rules-fields');return false">Standard Sigma fields</a>
        <a href="#doc-elf-block" onclick="docScroll('elf-block');return false">The elf: extension block</a>
        <a href="#doc-rule-types" onclick="docScroll('rule-types');return false">Rule types</a>
        <a href="#doc-actions" onclick="docScroll('actions');return false">Actions</a>
        <a href="#doc-lists" onclick="docScroll('lists');return false">Reusable lists</a>
        <a href="#doc-fields" onclick="docScroll('fields');return false">Field resolution</a>
        <a href="#doc-conditions" onclick="docScroll('conditions');return false">Condition expressions</a>
        <a href="#doc-destinations" onclick="docScroll('destinations');return false">Destinations</a>
        <div class="dt-title">Understanding your data</div>
        <a href="#doc-metrics-data" onclick="docScroll('metrics-data');return false">Metrics &amp; forwarding</a>
        <a href="#doc-alerts-logs" onclick="docScroll('alerts-logs');return false">Alerts &amp; logs</a>
        <a href="#doc-limitations" onclick="docScroll('limitations');return false">Limitations</a>
      </div>
      <div class="docs-content" id="docs-content">

        <h2 id="doc-overview">Welcome to ELF</h2>
        <p class="lead">The <strong>Efficient Log Forwarder (ELF)</strong> is a Windows agent that watches the Windows Event Log in real time, evaluates detection rules against the live event stream, and forwards matching events to your destinations.</p>
        <p>ELF runs <strong>detection rules locally</strong> on each host and forwards matching events, alerts, or correlated event batches. Rules are written in the <strong>Sigma format</strong>, the open standard for detection rules, extended with a small <code>elf:</code> block that adds thresholding, sequencing, and forwarding actions. You author rules once in the management UI and they are pushed to every agent in a group automatically.</p>
        <div class="callout">
          <strong>Components:</strong> a central management server (this web UI), a Windows agent that runs on each host, and a Sigma-based rule engine that decides what to forward. You manage rules and groups here; the agents do the detection and forwarding work on the hosts.
        </div>

        <h2 id="doc-how-it-works">How it works</h2>
        <p>ELF has two components that talk to each other over HTTP:</p>
        <ol>
          <li><strong>The management server</strong> (this web UI, running in Docker) holds the authoritative copy of the rules, groups, and agent configuration. You create groups, author rules, and manage reusable lists here.</li>
          <li><strong>The Windows agent</strong> runs on each monitored host. On startup it <strong>auto-derives a per-channel XPath filter from your rules</strong> and subscribes to only the channels and EventIDs the rules can match (this cuts the agent's event load by ~90% on a busy host), loads its rules, and begins evaluating matching events against them. Every <code>poll_interval_seconds</code> (default 30s) it contacts the server to pull the latest config and rules for its group, then re-derives the filter and re-subscribes if the ruleset changed.</li>
        </ol>
        <p>When an event matches a rule, the agent performs the rule's <strong>actions</strong>: forward the single event, raise an alert, or forward a batch of recent events. Actions send data to <strong>destinations</strong> (local files or HTTP endpoints) that you define per group.</p>
        <p>The agent also reports cumulative counters to the server on every poll: how many events and bytes it created (saw) vs. forwarded (sent). The server shows these on the Metrics tab.</p>
        <div class="callout">
          <strong>Agent → Server flow:</strong> the agent <em>pulls</em> config + rules (<code>GET /config/{agent_id}</code>) and <em>pushes</em> alerts + forwarded logs (<code>POST /alerts</code>, <code>POST /logs</code>). Agents are grouped; each group has its own rules, destinations, retention, and poll interval. An agent inherits everything from its group.
        </div>
        <div class="callout">
          <strong>Selective subscription (XPath filtering).</strong> The agent does not read every event on every channel. It looks at your rules, figures out which Windows channels and EventIDs they care about, and asks Windows to deliver <em>only</em> those events. On a busy Domain Controller this cuts the agent's event load by ~90%. You don't configure anything; it's automatic. A rule with no <code>logsource</code> (a catch-all) disables filtering for safety, since it could match anything. Whenever the ruleset changes (you edit a rule here, or the agent hot-reloads from disk), the agent re-derives the filter and re-subscribes.
        </div>

        <h2 id="doc-install">Install your first agent</h2>
        <p>Enrolling a new host takes one generated script: PowerShell for Windows, bash for Linux (see <a href="#" onclick="docScroll('install-linux');return false">Linux hosts</a>). The server builds it for you. For a Windows host:</p>
        <ol>
          <li>Click <strong>+ Add New Agent</strong> (top right of any page) and leave <strong>Windows</strong> selected.</li>
          <li>Pick the <strong>group</strong> the new agent should join (e.g. <em>workstations</em> or <em>servers</em>). The group determines which rules and destinations the agent gets.</li>
          <li>Choose the <strong>service account</strong> mode (see <a href="#" onclick="docScroll('svc-account');return false">Service accounts</a> below):
            <ul>
              <li><strong>Create a local service account</strong> (default): the script creates a dedicated local user <code>ELFAgent</code> with a random password. Self-contained; nothing to prepare in advance.</li>
              <li><strong>Use an existing domain account</strong>: for domain-joined hosts. Enter the <code>DOMAIN</code> and <code>username</code> of an AD service account; the script prompts for its password <em>securely at install time</em> on the target host (masked input; the password is never stored in the script, the clipboard, or this server).</li>
            </ul>
          </li>
          <li>Click <strong>Generate</strong>; the install script appears. Use <strong>Copy</strong> or <strong>Download .ps1</strong>.</li>
          <li>On the target Windows host, open an <strong>elevated PowerShell</strong> prompt (Run as Administrator) and run the script (paste it, or save the .ps1 and run <code>.\install-elf-agent.ps1</code>).</li>
        </ol>
        <p>The script downloads the agent executable from this server, installs it to <code>Program Files\ELFAgent</code>, provisions the service account, writes a <code>config.ini</code> with a unique <code>agent_id</code> (derived from the host's computer name), registers the agent in the chosen group, and installs + starts it as a Windows service. The service auto-starts on boot, restarts on crash, and runs invisibly to normal users. No internet access is needed beyond reaching this server.</p>
        <div class="callout">
          <strong>Least privilege.</strong> In local mode the agent runs as a dedicated local user, not Administrator. It has only <code>SeServiceLogonRight</code>, <code>SeSecurityPrivilege</code>, and membership in <em>Event Log Readers</em>. In domain mode the same rights are granted to the domain account <em>on that host</em>. Its logs and spool live under <code>%ProgramData%\ELFAgent</code> with an ACL that grants access only to SYSTEM and the service account, so normal users cannot read the logs or tamper with the spool.
        </div>
        <p>The agent binary is <strong>statically linked</strong>: it has no external DLL dependencies and runs on a clean Windows install. Only the single <code>efficient_log_forwarder.exe</code> needs to be on the host.</p>
        <p>Once running, the agent appears in the <strong>Agents</strong> tab within a few seconds (on its first poll). You can then change its group, view its details, or delete it from the UI.</p>

        <h2 id="doc-install-linux">Linux hosts</h2>
        <p>Pick <strong>Linux</strong> in the Add New Agent dialog. Paste the whole generated script into a shell on the host, or download <code>install-elf-agent.sh</code> and run it with <code>bash</code>. It asks for your sudo password once (the body runs in one root shell, so a paste never runs half-way or closes your session) and then:</p>
        <ol>
          <li>downloads <code>elf-agent</code> from this server into <code>/opt/elf/</code>;</li>
          <li>creates a dedicated <code>elf</code> system user (no shell, no home directory), or uses the existing account you named, and adds it to the <code>systemd-journal</code> group so it can read the journal;</li>
          <li>creates <code>/var/lib/elf/</code> (logs, spool, cursor, server-pushed rules, file destinations), owned by that user and private to it;</li>
          <li>registers the agent in the chosen group and writes <code>/etc/elf/config.ini</code> with its auth token;</li>
          <li>installs and starts the <code>elf-agent</code> systemd unit (starts at boot, restarts on failure, <code>ProtectSystem=strict</code> with <code>/var/lib/elf</code> as the only writable path).</li>
        </ol>
        <p><strong>Process starts need auditd.</strong> On Linux the agent reads the systemd journal. Syslog lines (sshd, sudo, cron, useradd, systemd) are always there; program executions are not, unless the kernel audit subsystem records them. Tick <em>Also add an auditd rule that records program executions</em> when the group's rules include <code>process_creation</code> rules: the script enables journald's audit socket (Debian and Ubuntu ship it disabled), sets <code>Audit=yes</code>, and installs an <code>execve</code> rule under <code>/etc/audit/rules.d/</code>. auditd itself must be installed on the host (<code>apt install auditd</code>).</p>
        <p><strong>Channels.</strong> A Sigma <code>service:</code> maps to the journal's syslog identifier: <code>sshd</code> (also <code>sshd-session</code>), <code>sudo</code>, <code>cron</code>, <code>kernel</code>, <code>systemd</code>, <code>auditd</code> (the audit stream, channel <code>audit</code>), and <code>syslog</code>/<code>auth</code> for the whole journal. <code>category: process_creation</code> with <code>product: linux</code> selects the audit <code>EXECVE</code> records, which the agent joins with the rest of the audit event so <code>Image</code>, <code>CommandLine</code>, <code>User</code>-style fields and the auditd names (<code>exe</code>, <code>comm</code>, <code>a0</code>, <code>key</code>) are all present. Import SigmaHQ's Linux rules with the product filter set to <code>linux</code>; an agent skips rules written for the other operating system.</p>
        <p>Check on the host with <code>systemctl status elf-agent</code>, <code>journalctl -u elf-agent</code> (notices and errors) and <code>/var/lib/elf/logs/elf_agent.log</code>. The cleanup script (same dialog, Linux selected) removes the unit, the directories, the audit rule and the <code>elf</code> user.</p>

        <h2 id="doc-svc-account">Service accounts (local vs domain)</h2>
        <p>On Windows the agent runs as a Windows service, so it needs an account to run under. ELF supports two modes (for Linux see <a href="#" onclick="docScroll('install-linux');return false">Linux hosts</a>):</p>
        <h3>Local mode (default, nothing to prepare)</h3>
        <p>The install script creates a dedicated local user <code>ELFAgent</code> with a random 24-character password and grants it exactly the rights it needs. This is the simplest option and works on any Windows host, domain-joined or not. The cleanup script deletes this account when you remove the agent.</p>
        <h3>Domain mode (use one AD service account for many hosts)</h3>
        <p>In a domain environment you can run the agent on every host under a single, centrally-managed AD service account instead of a per-host local account. Prepare the account once on a Domain Controller, then pick <em>Use an existing domain account</em> in the Add New Agent form.</p>
        <h4>Step 1: create the account on the Domain Controller</h4>
        <p>From an elevated PowerShell on a DC (or via AD Users and Computers):</p>
        <pre><code># Create a dedicated OU for service accounts if you don't have one
New-ADOrganizationalUnit -Name "Service Accounts" -Path "DC=corp,DC=local"

# Create the account. Password never expires; the account cannot
# interactively log on (it is only used to run the service).
$pw = Read-Host "Password" -AsSecureString
New-ADUser -Name "svc-elf-agent" `
  -Path "OU=Service Accounts,DC=corp,DC=local" `
  -AccountPassword $pw `
  -PasswordNeverExpires $true `
  -CannotChangePassword $true `
  -ChangePasswordAtLogon $false `
  -Enabled $true `
  -Description "ELF agent service account (log forwarder)"
# Block interactive + remote interactive logon (service-only account):
Set-ADUser svc-elf-agent -LogonWorkstations "" `
  -Add @{userWorkstations=""}
# Deny interactive logon via GPO is recommended (see Step 2).</code></pre>
        <div class="callout warn">
          <strong>Do not</strong> make the account a Domain Admin or local Administrator. The agent deliberately runs least-privilege; the install script grants it the few rights it actually needs on each host.
        </div>
        <h4>Step 2: required rights and permissions</h4>
        <p>The account needs the following. The <strong>install script grants items 1–3 automatically on the target host</strong> (via the LSA API and <code>net localgroup</code>), so normally you only need to ensure GPO does not <em>deny</em> them:</p>
        <table>
          <tr><th>Right / permission</th><th>Why</th><th>Granted by</th></tr>
          <tr><td><code>SeServiceLogonRight</code><br><em>(Log on as a service)</em></td><td>Required for the SCM to start the service under the account</td><td>Install script (LSA grant)</td></tr>
          <tr><td><code>SeSecurityPrivilege</code><br><em>(Manage auditing and security log)</em></td><td>Read the <strong>Security</strong> event channel (event IDs 4624/4625/4688 …)</td><td>Install script (LSA grant)</td></tr>
          <tr><td>Member of local <em>Event Log Readers</em></td><td>Read the other event channels (System, Application, …)</td><td>Install script (<code>net localgroup</code>)</td></tr>
          <tr><td>Write access to <code>%ProgramData%\ELFAgent</code></td><td>Logs, spool, bookmarks, downloaded rules</td><td>Install script (directory ACL)</td></tr>
        </table>
        <p>If a <strong>Group Policy</strong> defines <em>Deny log on as a service</em> or restricts <em>Log on as a service</em> to an explicit list, add the service account to that list (or exclude the OU from the GPO). A GPO that denies the right overrides the local LSA grant and the service will fail to start with <strong>error 1069</strong>.</p>
        <h4>Step 3: install the agent</h4>
        <p>In <strong>+ Add New Agent</strong>, choose <em>Use an existing domain account</em>, enter the NetBIOS domain (e.g. <code>CORP</code>) and username (e.g. <code>svc-elf-agent</code>), and Generate. On the target host, run the script from an elevated PowerShell; it prompts for the account's password with masked input, verifies the credentials against the domain, grants the local rights, and starts the service.</p>
        <div class="callout">
          <strong>Password handling.</strong> The password is prompted by <code>Read-Host -AsSecureString</code> on the target host at install time only; it is passed to the Service Control Manager and never written to the script, the config, or the management server. If the account's password is later rotated in AD, re-run the install script (or update the service credentials with <code>sc.exe config ELFAgent password= ...</code>).
        </div>
        <h3>Cleanup</h3>
        <p>The cleanup script (in the Add New Agent modal) removes the service, the local <code>ELFAgent</code> account, and both directories. If the service ran as a domain account, it revokes the rights granted to that account <em>on that host</em> (Event Log Readers, <code>SeServiceLogonRight</code>, <code>SeSecurityPrivilege</code>) but never deletes the AD account itself, which may be in use on other hosts. To remove the AD account entirely, delete it in AD Users and Computers.</p>

        <h2 id="doc-antivirus">Antivirus exclusions (Defender CPU spikes with large rulesets)</h2>
        <p>With a large ruleset (2000+ rules), Windows Defender's real-time scanning can drive <code>MsMpEng.exe</code> to 100% CPU on hosts running the agent. The cause is the agent's rule-file I/O, not the detection engine itself:</p>
        <ul>
          <li><strong>Where rules live.</strong> Server-pushed rules are stored in the agent's writable state tree at <code>%ProgramData%\ELFAgent\rules\</code> (one <code>.yaml</code> per rule), with lists in <code>%ProgramData%\ELFAgent\lists\</code>, not next to the exe in <code>Program Files</code>.</li>
          <li><strong>Bulk writes.</strong> When the ruleset changes, the agent rewrites every changed rule file in one poll, and each write fires a real-time scan. (The agent already skips unchanged files so steady-state polls stay quiet, but importing 2000 rules writes 2000 files at once.)</li>
          <li><strong>Cyclic reads.</strong> The agent re-reads every rule file every 60 seconds (hot reload), and each poll-triggered reload does the same. Defender intercepts every open.</li>
        </ul>
        <p><strong>Fix: add a path + process exclusion</strong> from an elevated PowerShell on the host:</p>
        <pre><code># Exclude the whole agent state tree (rules, lists, spool, logs, bookmarks)
Add-MpPreference -ExclusionPath "$env:ProgramData\ELFAgent"

# Process exclusion: stops Defender hooking every file the agent opens/creates
# (covers the exe itself + the 60s hot-reload that re-reads all rule files)
Add-MpPreference -ExclusionProcess "efficient_log_forwarder.exe"

# Verify
Get-MpPreference | Select-Object -ExpandProperty ExclusionPath</code></pre>
        <p>For a fleet, deploy the same exclusions via GPO: <em>Computer Configuration → Administrative Templates → Windows Components → Microsoft Defender Antivirus → Exclusions → Path/Process Exclusions</em>.</p>
        <div class="callout">
          <strong>Security trade-off.</strong> Excluding <code>%ProgramData%\ELFAgent</code> means files dropped there are never scanned. The risk is bounded: the tree is ACL'd to <code>SYSTEM</code> and the <code>ELFAgent</code> service account only (the install script sets this), so a normal user cannot plant files there. If your security posture prefers minimal exclusions, exclude just the hot paths instead:
          <pre><code>Add-MpPreference -ExclusionPath "$env:ProgramData\ELFAgent\rules"
Add-MpPreference -ExclusionPath "$env:ProgramData\ELFAgent\lists"
Add-MpPreference -ExclusionPath "$env:ProgramData\ELFAgent\spool"</code></pre>
        </div>
        <p>The <strong>process exclusion</strong> is the most effective single change for the read side; the <strong>path exclusion</strong> kills the write-side scan storm. Together they typically eliminate the 100% CPU spikes.</p>

        <h2 id="doc-ui-agents">Agents tab</h2>
        <p>The Agents tab lists every host running an ELF agent. Each row shows:</p>
        <ul>
          <li><strong>Agent ID</strong>: the unique identity (usually the host's computer name). This must match the <code>agent_id</code> in the agent's <code>config.ini</code>.</li>
          <li><strong>Hostname / IP / OS</strong>: reported by the agent on registration.</li>
          <li><strong>Group</strong>: an inline dropdown to move the agent to another group. Changes take effect on the agent's next poll.</li>
          <li><strong>Last seen / First seen</strong>: <em>Last seen</em> updates on every poll (every 30s by default). If it's stale, the agent is offline or can't reach the server.</li>
          <li><strong>Delete</strong>: removes the agent and all its alerts/logs from the database.</li>
        </ul>
        <p>Use the <strong>Refresh</strong> button to reload the list manually, or toggle <strong>Auto-refresh</strong> (top right) to refresh automatically. You can also export the agent list as CSV.</p>

        <h2 id="doc-ui-collect">Collect logs</h2>
        <p>The <strong>Collect logs</strong> action lets you pull historical Windows events from a host on demand, which is useful when an alert looks suspicious and an analyst needs the surrounding context to investigate. It is available per-agent from the <strong>⋯ Actions</strong> button on the Agents tab.</p>
        <p>When you trigger a collect, the server queues a <code>collect_logs</code> command for that agent. The agent picks the command up on its next poll (within <code>poll_interval_seconds</code>), queries the local Windows Event Log for all events from the <strong>start time</strong> you specify, and streams them back to the server in batches. The collected events land in the <strong>Logs</strong> tab tagged with a <span class="badge info">collect</span> badge so you can tell them apart from rule-forwarded events.</p>
        <div class="callout">
          <strong>How to use it:</strong> on the Agents tab, click <strong>⋯</strong> on a row to expand its panel, pick a start time (defaults to 24 hours ago), and click <strong>Collect logs</strong>. A status line shows the command's progress (<em>pending</em> → <em>sent</em> → <em>done</em> / <em>failed</em>). Only one collect is in flight per agent at a time.
        </div>
        <div class="callout warn">
          <strong>Scope.</strong> The agent enumerates <em>all</em> event channels and pulls every event at or after the start time; there is no rule filter. For wide time ranges this can be a large amount of data. Prefer a tight window (minutes to a few hours) around the event you're investigating.
        </div>

        <h2 id="doc-ui-groups">Groups tab</h2>
        <p>Every agent belongs to exactly one <strong>group</strong>. A group is a bundle of settings that its agents inherit:</p>
        <ul>
          <li><strong>Rules</strong>: which detection rules apply to agents in this group.</li>
          <li><strong>Destinations</strong>: named output targets (e.g. <code>siem</code>, <code>data_lake</code>, <code>alerts</code>) with their URLs.</li>
          <li><strong>Retention</strong>: how long events stay in the agent's in-memory buffer (seconds).</li>
          <li><strong>Poll interval</strong>: how often the agent checks the server for config/rule updates (seconds).</li>
          <li><strong>Mirror logs</strong>: when checked (the default), the agent also copies every forwarded log batch to the ELF server so it appears on the <a href="#doc-ui-logs" onclick="docScroll('ui-logs');return false">Logs tab</a>. Uncheck it to keep <em>alerts only</em>: the agent still forwards to your destinations and still reports alerts, but stops sending log batches to the server. Alerts always mirror regardless of this setting.</li>
        </ul>
        <p>Click a group card to expand its settings. You can edit destinations (add/remove named targets with <code>file://</code> or <code>http://</code> URLs), change retention and poll interval, and save. The <strong>Members</strong> column shows which agents are currently assigned to each group.</p>
        <div class="callout">
          <strong>Default group.</strong> A built-in <em>default</em> group always exists and cannot be deleted. New agents that don't specify a group land here. Deleting a group reassigns its agents to the default group.
        </div>

        <h2 id="doc-ui-rules">Rules tab</h2>
        <p>The Rules tab is a two-pane editor. The <strong>left pane</strong> lists rules for the selected group (use the dropdown at the top to switch groups). The <strong>right pane</strong> is a YAML editor where you author and edit rules.</p>
        <ul>
          <li><strong>+ New</strong>: create a new rule (starts from a template).</li>
          <li><strong>⬆ Import</strong>: import many Sigma rules at once from a zip or from SigmaHQ. See <a href="#doc-ui-import" onclick="docScroll('ui-import');return false">Importing rules in bulk</a> below.</li>
          <li><strong>Save Rule</strong>: validates the YAML on the server and saves it. The validation status appears below the editor.</li>
          <li><strong>Enable / Disable</strong>: a disabled rule is kept in the group but not sent to agents (agents skip it).</li>
          <li><strong>Delete</strong>: permanently removes the rule.</li>
        </ul>
        <p>Rules are saved as Sigma YAML. The full rule format is documented in the <a href="#doc-rules-intro" onclick="docScroll('rules-intro');return false">Building rules</a> section below.</p>
        <div class="callout">
          <strong>Rule identity.</strong> Each rule has a Sigma <code>id</code> (the YAML id you author) and a database <code>rule_id</code> (assigned by the server). Editing a rule updates it in place; no duplicates are created.
        </div>
        <div class="callout">
          <strong>Rule count.</strong> The number of rules in the selected group is shown as a badge next to the group dropdown and as a footer line under the rule list. Both update every time the list refreshes.
        </div>

        <h2 id="doc-ui-import">Importing rules in bulk</h2>
        <p>The <strong>⬆ Import</strong> button on the Rules tab lets you add many Sigma rules at once instead of authoring them one by one. This is useful for adopting a community ruleset like <a href="https://github.com/SigmaHQ/sigma" target="_blank" rel="noopener">SigmaHQ/sigma</a> or for rolling out your own collection of rules.</p>
        <h3>Two sources</h3>
        <ul>
          <li><strong>Upload a .zip</strong>: choose a <code>.zip</code> archive of Sigma <code>.yml</code> files (folders inside the zip are fine; the importer walks every <code>.yml</code>/<code>.yaml</code> file it finds). Use this for your own rule collections or a snapshot of a community repo.</li>
          <li><strong>Fetch from SigmaHQ</strong>: enter a release tag (default <code>r2026-07-01</code>), click <em>List assets</em>, and tick the release packages to import; the server downloads them from the GitHub release page (no git needed). The core packages nest (<code>sigma_core.zip</code> ⊂ <code>sigma_core+.zip</code> ⊂ <code>sigma_core++.zip</code> ⊂ <code>sigma_all_rules.zip</code>), so the picker lets you choose <strong>one tier</strong>; <code>sigma_emerging_threats_addon.zip</code> is a separate rule set you can add on top. A rule id that appears in more than one selected package (or twice in a zip) is imported once and reported as a duplicate in the preview.</li>
        </ul>
        <h3>How the elf: block is added</h3>
        <p>SigmaHQ rules are pure Sigma: they have no <code>elf:</code> block, so the agent would drop them (the agent rejects rules with zero actions). The importer <strong>injects an <code>elf:</code> block</strong> into each rule based on a <strong>severity → action map</strong> you fill out in the import form. For each Sigma severity level (<code>critical</code>, <code>high</code>, <code>medium</code>, <code>low</code>, <code>informational</code>) you check the actions to inject and the destination to send matches to.</p>
        <div class="callout">
          <strong>Example.</strong> A common mapping: <code>critical</code> → <code>alert</code> + <code>forward_buffer</code>; <code>high</code> → <code>alert</code>; <code>medium</code>/<code>low</code> → <code>forward_event</code>. Only severities with at least one checked action are imported; uncheck every action for a severity to skip it entirely.
        </div>
        <h3>Filters &amp; options</h3>
        <ul>
          <li><strong>Severity → action map</strong>: each severity has its own <strong>import</strong> checkbox. Check <em>import</em> for each severity you want to bring in (and pick the actions to inject for it); uncheck <em>import</em> to skip that severity entirely. This lets you select severities individually (e.g. import <em>only</em> <code>low</code>, or <code>critical</code> + <code>informational</code>) instead of being limited to a cascading "X and above" range.</li>
          <li><strong>Logsource product filter</strong>: only import rules whose <code>logsource.product</code> matches (defaults to <code>windows</code>). Set to <em>any</em> to import rules for other products.</li>
          <li><strong>Existing rules</strong>: <em>Skip (keep existing)</em> leaves rules already in the group untouched; <em>Overwrite in place</em> replaces them with the imported version (keyed by Sigma <code>id</code>).</li>
        </ul>
        <h3>Preview then Import (two steps)</h3>
        <p>The import is a two-step flow so you can review before committing:</p>
        <ol>
          <li><strong>Preview</strong> (the default): validates every candidate rule, injects the <code>elf:</code> block, runs it through the same validator the rule editor uses, and shows a <strong>count</strong> of rules ready to import plus a table of the first 25 (severity, name, rule id, source file). Rules that fail validation or are filtered out are counted as skipped with reasons. Nothing is saved.</li>
          <li><strong>Import</strong>: enabled after a successful preview with at least one planned rule. Commits the planned rules into the selected group. The rule list refreshes automatically and the count badge + footer update.</li>
        </ol>
        <div class="callout warn">
          <strong>SigmaHQ is large.</strong> The <code>rules/windows/</code> folder contains thousands of rules. A preview of the full set can take a minute (the server downloads ~50MB and parses every file). Use the severity and logsource filters to narrow the scope before previewing. The preview count is shown <em>before</em> you commit, so you always know how many rules will be added.
        </div>
        <div class="callout">
          <strong>What gets skipped.</strong> Rules without a Sigma <code>id</code>, whose severity has <em>import</em> unchecked (or no action checked), not matching the logsource filter, already present (when <em>Skip</em> is selected), or failing server validation after <code>elf:</code> injection are counted as skipped. Validation errors are listed in the preview so you can see exactly why a rule was rejected.
        </div>

        <h2 id="doc-ui-lists">Lists tab</h2>
        <p>The Lists tab manages <strong>reusable value lists</strong>: shared sets of values (like a list of sensitive process names) that you can reference from any rule with <code>@@name</code>. Lists are <strong>global</strong>; they are shared across all groups.</p>
        <p>Each list has a name and a set of values (one per line). Edit a list here and every rule that references it picks up the new values on the agents' next poll. See the <a href="#doc-lists" onclick="docScroll('lists');return false">Reusable lists</a> section for how to reference them from rules.</p>

        <h2 id="doc-ui-alerts">Alerts tab</h2>
        <p>The Alerts tab shows alerts raised by agents. An alert is produced when a rule with an <code>alert</code> action fires. Each row shows the alert ID, time, which agent raised it, which rule fired, a <strong>severity badge</strong>, and the alert message.</p>
        <p>Use the controls in the header to work the list:</p>
        <ul>
          <li><strong>Search box</strong>: filter alerts by a substring matched against the rule name, rule id, message, or agent id. The list refreshes (debounced) as you type.</li>
          <li><strong>Sort dropdown</strong>: <em>Newest first</em> (default; by received time) or <em>Severity first</em> (critical → high → medium → low → informational, then newest within each severity).</li>
          <li><strong>Rule link</strong>: the rule column shows the rule's display name (falling back to its id). Click it to jump straight to that rule in the Rules tab with the editor open, which is useful when an alert shows that the rule needs tuning.</li>
        </ul>
        <p>The severity badge is color-coded: <span style="color:#c62828;font-weight:bold">red = critical</span>, <span style="color:#ef6c00;font-weight:bold">orange = high</span>, <span style="color:#f9a825;font-weight:bold">yellow = medium</span>, <span style="color:#1565c0;font-weight:bold">blue = low</span>, and gray for informational/unknown. The severity comes from the rule's Sigma <code>level</code> field.</p>
        <p>Each alert has a <strong>▾</strong> button in the <strong>Details</strong> column that expands a dropdown showing the <strong>triggering event</strong>: a parsed field summary (EventID, Channel, Computer, TimeCreated, and the first few EventData fields) on top, with a collapsible <strong>Raw XML</strong> block below showing the event pretty-printed one tag per line. This is the same event the agent sent to its alert destination (file or SIEM), so you can see exactly what triggered the alarm.</p>
        <p>The list is <strong>paged</strong> (50 alerts per page) with <strong>Newer / Older</strong> buttons under the table, and the triggering event is fetched <em>on demand</em> only when you expand a row, so the page stays responsive even with thousands of stored alerts. Expanded rows stay open across the 5s auto-refresh.</p>
        <p><strong>Clear All</strong> deletes all stored alerts. This only clears the server's copy; it does not affect data already forwarded to your file/HTTP destinations.</p>

        <h2 id="doc-ui-metrics">Metrics tab</h2>
        <p>The Metrics tab shows what your agents are forwarding. It has two parts: a savings summary and a set of time-series charts.</p>
        <h3>Forwarding summary</h3>
        <p>Summary cards show totals across all agents: bytes sent vs. created, the percentage not forwarded, and events sent vs. created. Below them, a per-agent table breaks it down:</p>
        <table>
          <tr><th>Column</th><th>Meaning</th></tr>
          <tr><td>Events Created</td><td>Total events the agent saw on the host (cumulative since registration).</td></tr>
          <tr><td>Events Forwarded</td><td>Events the agent actually sent to a destination.</td></tr>
          <tr><td>% Forwarded</td><td><code>bytes_forwarded / bytes_created * 100</code>: the fraction of data sent. A bar graphic: <span style="color:#22c55e">green &lt;25%</span>, <span style="color:#f59e0b">amber 25–75%</span>, <span style="color:#ef4444">red &gt;75%</span>.</td></tr>
          <tr><td>Bytes Created / Forwarded</td><td>Same as events, but in bytes (the volume that actually hits your network/storage).</td></tr>
          <tr><td>% Not forwarded</td><td><code>(1 - bytes_forwarded / bytes_created) * 100</code>: the percentage of data your rules filtered out. A bar graphic: <span style="color:#22c55e">green &gt;50%</span>, <span style="color:#f59e0b">amber 0–50%</span>, <span style="color:#ef4444">red 0%</span>.</td></tr>
        </table>
        <p>The counters are cumulative since the agent first registered and are <strong>not</strong> filtered by the date range.</p>
        <h3>Time-series charts</h3>
        <p>Three stacked area charts show activity over a selectable time range:</p>
        <ul>
          <li><strong>Events forwarded</strong>: event counts per time bucket (blue).</li>
          <li><strong>Bytes forwarded</strong>: payload bytes per time bucket (green).</li>
          <li><strong>Alerts</strong>: alert counts per time bucket (amber).</li>
        </ul>
        <p>Controls above the charts:</p>
        <ul>
          <li><strong>Presets</strong>: one-click buttons for 1h, 24h, 7d, 30d, and All. The 24h preset is selected on your first visit to the tab.</li>
          <li><strong>From / To</strong>: custom date range pickers for an arbitrary window. While a preset is active the window <em>slides</em>: "To" follows the current time and "From" stays the preset span behind, so the charts always show the last N hours. Picking a custom date <strong>freezes</strong> the window: auto-refresh keeps updating the data inside your chosen range but never moves the range itself.</li>
          <li><strong>Agent</strong>: dropdown to filter all three charts to a single agent, or <em>All agents</em> for totals.</li>
        </ul>
        <p>Auto-refresh (every 5s) updates the charts <em>in place</em> (no flicker, no lost hover/tooltip) and pauses while you're interacting: selecting text, an open modal, or the date picker suspend refreshing until you're done.</p>
        <p><strong>Reset Metrics</strong> (admin-only) zeroes every agent's cumulative created/forwarded counters and deletes all stored forwarded-log batches (the Logs tab rows and the logs.txt file). Alerts are kept; they're the detection record. Use it to start a clean measurement window (e.g. after tuning rules). Note: agents report their counters cumulatively, so after a reset the savings view counts activity from the reset onward.</p>
        <p>Each chart is rendered with <a href="https://www.chartjs.org/" target="_blank" rel="noopener">Chart.js</a> (vendored locally at <code>/static/chart.umd.min.js</code>, so no internet access is required). Hover anywhere on a chart to see a crosshair and a tooltip with the exact value and timestamp. The bucket size is auto-scaled to the time span so the chart stays readable (1s for short spans up to 1h buckets for 30d+).</p>
        <div class="callout">The charts show what the server <em>received</em> (forwarded logs and alerts). The savings table above shows cumulative created-vs-forwarded counters per agent, but the agent only reports current snapshots; there is no historical "created over time" timeseries, so the charts cannot overlay created vs. forwarded.</div>

        <h2 id="doc-ui-logs">Logs tab</h2>
        <p>The Logs tab shows the <strong>newest 40</strong> forwarded log batches. When a rule with a <code>forward_buffer</code> action fires, the agent sends the batch to the server, which stores it here. Each row shows the batch ID, which agent sent it, which rule triggered it, and how many events were in the batch.</p>
        <p>Older batches are not lost: every event is also appended to the <strong>logs.txt text file</strong> (newline-separated raw event XML), the durable archive, and the server prunes the stored payloads of batches that age out of the newest 40, keeping the database small. The batch metadata (agent, rule, event count, received time) is kept for the Metrics charts over the full history.</p>
        <p>You can also view and download the raw logs text file and clear all stored logs. There are no date/time controls here; time filtering lives on the Metrics tab.</p>
        <p><strong>Max file size</strong>: the <em>Max file size (MB)</em> field caps how large the logs.txt text file may grow (default 100 MB, <code>0</code> = unlimited). When the file exceeds the cap the server trims the <strong>oldest</strong> lines after each append, so the newest data is always kept.</p>
        <p>Whether batches reach the server at all is controlled per group by the <strong>Mirror logs</strong> checkbox on the <a href="#doc-ui-groups" onclick="docScroll('ui-groups');return false">Groups tab</a>.</p>
        <p>Batches from the <a href="#doc-ui-collect" onclick="docScroll('ui-collect');return false">Collect logs</a> action are tagged with a <span class="badge info">collect</span> badge and use the rule id <code>__collect__</code>, so you can distinguish on-demand pulls from rule-forwarded batches.</p>

        <h2 id="doc-rules-intro">Sigma rules overview</h2>
        <p>ELF rules are <strong>standard Sigma YAML</strong> with an added top-level <code>elf:</code> block for ELF-specific features. A rule file must contain exactly <strong>one</strong> detection. Here's a complete rule:</p>
        <pre><code>title: Suspicious Process Launch (calc)
id: win_calc_susp
status: experimental
level: low
author: Your Team
date: 2026-10-01
description: Detects calc.exe being launched, a simple demo rule.
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4688
    Image|contains: calc.exe
  condition: selection
elf:
  actions:
    - type: alert
      destination: alerts
      message: "Suspicious process detected: calc.exe launched."
    - type: forward_buffer
      destination: data_lake</code></pre>
        <p>The top half (everything except <code>elf:</code>) is plain Sigma. The <code>elf:</code> block is where ELF's additions live: thresholding, sequencing, and the actions that make the rule <em>do</em> something.</p>

        <h2 id="doc-rules-fields">Standard Sigma fields</h2>
        <p>These are the required/standard Sigma fields. They're metadata shown in the UI and used for organization:</p>
        <table>
          <tr><th>Field</th><th>Required</th><th>Notes</th></tr>
          <tr><td><code>title</code></td><td>Yes</td><td>Display name shown in the UI rules list.</td></tr>
          <tr><td><code>id</code></td><td>Yes</td><td>Unique Sigma id. May differ from the server's DB <code>rule_id</code>.</td></tr>
          <tr><td><code>status</code></td><td>Yes</td><td><code>stable</code> | <code>test</code> | <code>experimental</code> | <code>deprecated</code> | <code>unsupported</code>.</td></tr>
          <tr><td><code>level</code></td><td>Yes</td><td><code>critical</code> | <code>high</code> | <code>medium</code> | <code>low</code> | <code>informational</code>. Shown as a badge.</td></tr>
          <tr><td><code>description</code></td><td>Recommended</td><td>What the rule detects.</td></tr>
          <tr><td><code>author</code> / <code>date</code> / <code>tags</code></td><td>Optional</td><td>Standard Sigma metadata. <code>tags</code> often hold MITRE ATT&amp;CK labels (e.g. <code>attack.t1110</code>).</td></tr>
          <tr><td><code>logsource</code></td><td>Yes</td><td><code>product: windows</code> + <code>service: &lt;channel&gt;</code> (e.g. <code>security</code>, <code>system</code>, <code>application</code>). The <code>service</code> is the Windows Event Log channel name.</td></tr>
          <tr><td><code>detection</code></td><td>Yes</td><td>The matching logic: named selections + a <code>condition</code>. See below.</td></tr>
          <tr><td><code>falsepositives</code></td><td>Optional</td><td>List of known false-positive causes.</td></tr>
        </table>

        <h2 id="doc-elf-block">The elf: extension block</h2>
        <p>The <code>elf:</code> block is what makes a Sigma rule an <strong>ELF rule</strong>. Without it, a rule matches silently and produces no output. The keys:</p>
        <table>
          <tr><th>Key</th><th>Required for</th><th>Description</th></tr>
          <tr><td><code>elf.actions</code></td><td><strong>All rules</strong></td><td>List of actions to take on match/fire. Without this, the rule does nothing.</td></tr>
          <tr><td><code>elf.threshold</code></td><td>Threshold rules</td><td>Integer count of matches required to fire.</td></tr>
          <tr><td><code>elf.timeframe</code></td><td>Threshold + Sequence</td><td>Sliding window duration, e.g. <code>60s</code>, <code>120s</code>.</td></tr>
          <tr><td><code>elf.group_by</code></td><td><strong>Threshold rules</strong> (mandatory)</td><td>Field(s) to scope the count per group. Scalar (<code>group_by: TargetUserName</code>) or list (<code>group_by: [User, Computer]</code>).</td></tr>
          <tr><td><code>elf.threshold_op</code></td><td>Threshold (optional)</td><td>Comparison operator: <code>gte</code> (default), <code>gt</code>, <code>eq</code>.</td></tr>
          <tr><td><code>elf.distinct</code></td><td>Threshold (optional)</td><td>Field(s) whose <strong>unique resolved values</strong> are counted instead of raw events. Scalar (<code>distinct: DestAddress</code>) or list (<code>distinct: [DestAddress, DestPort]</code>).</td></tr>
          <tr><td><code>elf.sequence</code></td><td>Sequence rules</td><td>Ordered list of stages (each a mini detection).</td></tr>
        </table>
        <div class="callout warn">
          <strong><code>group_by</code> is mandatory for threshold rules.</strong> A threshold rule without <code>group_by</code> is rejected at save time. This scopes the count to a specific field (e.g. <code>TargetUserName</code> or <code>Computer</code>) rather than counting matches globally.
        </div>
        <p>If <strong>none</strong> of <code>threshold</code>/<code>sequence</code> are present, the rule is a <strong>simple</strong> rule (fires on first match).</p>

        <h2 id="doc-rule-types">Rule types</h2>
        <p>ELF supports four rule patterns. The type is determined by which <code>elf:</code> keys are present.</p>

        <h3>1. Simple rule: fire on first match</h3>
        <p>Fires the moment a single event matches. No <code>threshold</code> or <code>sequence</code> keys.</p>
        <pre><code>detection:
  selection:
    EventID: 4688
    Image|contains: calc.exe
  condition: selection
elf:
  actions:
    - type: alert
      destination: alerts
      message: "Suspicious process detected: calc.exe launched."
    - type: forward_buffer
      destination: data_lake</code></pre>

        <h3>2. Threshold rule: fire after N matches in a window</h3>
        <p>Counts matching events within a sliding <code>timeframe</code> window and fires when the count meets <code>threshold</code> (using <code>threshold_op</code>). <code>group_by</code> scopes the count per group so the rule fires on N matches <em>for the same group</em> (e.g. the same user), not N matches globally.</p>
        <pre><code>elf:
  threshold: 5
  timeframe: 60s
  group_by: TargetUserName      # mandatory: count per user, not globally
  actions:
    - type: alert
      destination: alerts
      message: "Possible brute-force logon: 5 failed logons within 60s."
    - type: forward_buffer
      destination: siem</code></pre>
        <h4>group_by: per-group counting</h4>
        <p>Resolves each field against the event and keys the sliding window by <code>rule.id + group values</code>. Events with different group values maintain independent windows.</p>
        <ul>
          <li><strong>Scalar:</strong> <code>group_by: TargetUserName</code>, one window per username.</li>
          <li><strong>Sequence:</strong> <code>group_by: [TargetUserName, Computer]</code>, one window per (user, host) pair.</li>
          <li>If a group field is absent from an event, it lands in a <code>&lt;missing&gt;</code> sentinel bucket (not dropped).</li>
        </ul>
        <h4>threshold_op: the comparison operator</h4>
        <table>
          <tr><th>Operator</th><th>Fires when</th></tr>
          <tr><td><code>gte</code> (default)</td><td><code>count &gt;= threshold</code></td></tr>
          <tr><td><code>gt</code></td><td><code>count &gt; threshold</code></td></tr>
          <tr><td><code>eq</code></td><td><code>count == threshold</code></td></tr>
        </table>
        <p>After firing, the window resets so the rule re-arms for the next burst. <code>lt</code>/<code>lte</code>/<code>neq</code> are not supported (see <a href="#doc-limitations" onclick="docScroll('limitations');return false">Limitations</a>).</p>
        <h4>distinct: counting unique field values</h4>
        <p>By default a threshold rule counts <strong>matching events</strong>. <code>distinct</code> changes what it counts: the <strong>unique resolved values</strong> of the named field(s) within the window. Use it when N repeats of one value must not fire. The classic case is a <strong>ping sweep</strong>: <code>ping -n 10 &lt;onehost&gt;</code> produces 10 matching WFP 5156 events but they all target <strong>one</strong> destination IP, so a plain threshold-5 rule would fire even though the host only ever contacted a single IP. With <code>distinct: DestAddress</code> the rule counts unique destination IPs and stays silent.</p>
        <pre><code>elf:
  threshold: 5
  timeframe: 30s
  group_by: Computer
  distinct: DestAddress
  actions:
    - type: alert
      destination: alerts
      message: "Ping sweep: 5 unique destination IPs within 30s from one host."</code></pre>
        <ul>
          <li><strong>Insert-or-refresh:</strong> each new matching event updates its value's last-seen time; a value stays in the window while it keeps being seen within the <code>timeframe</code>, and expires otherwise.</li>
          <li><strong>Fire-then-reset:</strong> the window clears after a fire, so a 10-unique-IP sweep against a threshold-5 rule fires <em>twice</em> (at the 5th and again at the 10th unique IP).</li>
          <li>If the distinct field is absent, the event counts into a single <code>&lt;missing&gt;</code> bucket (mirroring <code>group_by</code>).</li>
          <li><code>group_by</code> still applies; unique values are counted <em>per group</em> (e.g. per host).</li>
        </ul>

        <h3>3. Sequence rule: fire when stages occur in order within a window</h3>
        <p>Fires when a series of stages occur in order within the <code>timeframe</code>. Each stage is a mini detection with its own <code>selection</code> and <code>condition</code>.</p>
        <pre><code>elf:
  timeframe: 120s
  sequence:
    - selection:
        EventID: 4625
      condition: selection
    - selection:
        EventID: 4624
      condition: selection
  actions:
    - type: alert
      destination: alerts
      message: "Failed logon followed by success: possible credential compromise."</code></pre>

        <h3>4. Continuous forward rule: forward every match</h3>
        <p>Uses <code>forward_event</code> to send every matching event as it happens, e.g. forwarding all logon events.</p>
        <pre><code>detection:
  selection:
    EventID: 4624
  condition: selection
elf:
  actions:
    - type: forward_event
      destination: siem</code></pre>

        <h2 id="doc-actions">Actions</h2>
        <p>Each action has a <code>type</code>, a <code>destination</code> (a name defined in the group's destinations), and (for alerts) a <code>message</code>:</p>
        <table>
          <tr><th>Type</th><th>Fires when</th><th>Sends</th></tr>
          <tr><td><code>forward_event</code></td><td>Every matching event (continuous)</td><td>The single matching event</td></tr>
          <tr><td><code>alert</code></td><td>Rule fires (threshold/sequence met, or simple match)</td><td>The triggering event, annotated with <code>message</code></td></tr>
          <tr><td><code>forward_buffer</code></td><td>Rule fires</td><td>The buffered events this rule has not sent before, as a batch (sent in chunks of at most 2,000 events)</td></tr>
        </table>
        <div class="callout">
          <strong>Destination must exist.</strong> The <code>destination</code> name must match a destination defined in the group's settings (or in the agent's <code>config.ini [destinations]</code>). An action naming a missing destination is skipped with an error line in the agent log.
        </div>
        <div class="callout">
          <strong><code>forward_buffer</code> does not clear the buffer.</strong> It sends a snapshot and leaves the events in place, so every other rule still evaluates them. Each rule keeps its own cursor into the buffer: a second fire shortly after the first sends only the events that arrived since.
        </div>
        <p>You can list multiple actions, e.g. raise an alert <em>and</em> forward the buffer to your data lake in the same rule.</p>
        <div class="callout">
          <strong>Combining <code>alert</code> + <code>forward_buffer</code>.</strong> When a rule declares both and they fire on the same event, the agent sends <strong>exactly one alert</strong> (from the <code>alert</code> action) plus <strong>one log batch</strong> (from the <code>forward_buffer</code> action). The <code>forward_buffer</code> action's own "fired" notification alert is suppressed in this case so the server doesn't record a duplicate alert for the same <code>EventRecordID</code>. A <code>forward_buffer</code>-only rule (no <code>alert</code> action) still produces its notification alert so it appears in the Alerts view.
        </div>

        <h3>Severity-based alert selection</h3>
        <p>When <strong>multiple Simple rules match the same event</strong>, only the <strong>highest-severity</strong> one fires its <code>alert</code> / <code>forward_buffer</code> actions. This prevents alert storms when a generic rule and a specific rule both match one event (e.g. a broad "process created" rule and a narrow "suspicious process" rule both fire on one 4688; only the higher-severity alert is sent).</p>
        <ul>
          <li>Severity ranking: <code>critical</code> &gt; <code>high</code> &gt; <code>medium</code> &gt; <code>low</code> &gt; <code>informational</code> &gt; unknown.</li>
          <li><strong>Ties are broken by rule order</strong>: the first-loaded matching rule wins.</li>
          <li><strong><code>forward_event</code> is never suppressed</strong>: every matching Simple rule still forwards its event stream. Only the <code>alert</code> and <code>forward_buffer</code> actions are subject to severity selection.</li>
          <li><strong>Threshold and Sequence rules are NOT subject to severity selection</strong>: they fire independently when their condition is met, even if a higher-severity Simple rule also matched the same event. This keeps correlation alerts (brute-force, failed&rarr;success) always firing on their own merit.</li>
          <li><strong>The losers are recorded.</strong> The winning alert carries the ids of the suppressed rules (<code>also_matched</code>), shown as links in the alert detail, so nothing a rule detected is invisible.</li>
        </ul>
        <p>The rule's <code>level</code> is sent to the server with each alert, so the <a href="#doc-ui-alerts" onclick="docScroll('ui-alerts');return false">Alerts tab</a> can sort and color-code alerts by severity.</p>

        <h2 id="doc-lists">Reusable lists</h2>
        <p>Reusable lists let you define a set of values once and reference them from any rule. For example, define a <code>sensitive_processes</code> list and reference it with <code>@@sensitive_processes</code>.</p>
        <h4>Referencing a list from a rule</h4>
        <p>Use the <code>@@</code> prefix. Because <code>@</code> is a reserved YAML indicator, <strong>always quote</strong> the reference:</p>
        <pre><code>detection:
  selection:
    EventID: 4688
    Image|contains: "@@sensitive_processes"
  condition: selection</code></pre>
        <p>You can combine a list reference with literal values:</p>
        <pre><code>detection:
  selection:
    EventID: 4688
    Image|contains:
      - "@@sensitive_processes"
      - mspaint.exe
  condition: selection</code></pre>
        <p>The loader expands <code>@@sensitive_processes</code> at <strong>load time</strong> into the field's value set, so the engine sees the same thing as if you wrote every value inline. Lists are managed on the <strong>Lists</strong> tab and are shared globally across all groups.</p>
        <div class="callout warn">
          <strong>Missing / empty list = matches nothing.</strong> If a rule references <code>@@name</code> and the list doesn't exist or is empty, the field matches <em>nothing</em> (not "exists"). A typo in the list name will not turn the field into a wildcard that matches everything.
        </div>

        <h2 id="doc-fields">Field resolution</h2>
        <p>Rules reference <strong>logical field names</strong> that the agent resolves against the rendered Windows event XML:</p>
        <table>
          <tr><th>Field name</th><th>Resolves to</th></tr>
          <tr><td><code>EventID</code></td><td><code>&lt;System&gt;&lt;EventID&gt;</code> text</td></tr>
          <tr><td><code>Channel</code></td><td><code>&lt;System&gt;&lt;Channel&gt;</code> text</td></tr>
          <tr><td><code>Computer</code></td><td><code>&lt;System&gt;&lt;Computer&gt;</code> text</td></tr>
          <tr><td><code>Provider</code></td><td><code>&lt;System&gt;&lt;Provider Name="..."&gt;</code> attribute</td></tr>
          <tr><td><code>TimeCreated</code></td><td><code>&lt;System&gt;&lt;TimeCreated SystemTime="..."&gt;</code> attribute</td></tr>
          <tr><td><em>any other</em></td><td><code>&lt;EventData&gt;&lt;Data Name="NAME"&gt;</code> text (e.g. <code>Image</code>, <code>CommandLine</code>, <code>ScriptBlockText</code>)</td></tr>
        </table>
        <p>A dotted name like <code>EventData.CommandLine</code> is also supported (last segment is the Data Name).</p>
        <h4>Field modifiers (Sigma subset)</h4>
        <p>Chained with <code>|</code> after the field name. All are <strong>case-insensitive</strong>.</p>
        <table>
          <tr><th>Modifier</th><th>Meaning</th></tr>
          <tr><td><em>(none)</em></td><td>equals</td></tr>
          <tr><td><code>contains</code></td><td>substring match</td></tr>
          <tr><td><code>startswith</code></td><td>prefix match</td></tr>
          <tr><td><code>endswith</code></td><td>suffix match</td></tr>
          <tr><td><code>re</code></td><td>regex (ECMAScript, case-insensitive)</td></tr>
          <tr><td><code>exists</code></td><td>field is present (value ignored)</td></tr>
          <tr><td><code>cidr</code></td><td>field is an IP address inside the CIDR range (IPv4 + IPv6)</td></tr>
          <tr><td><code>all</code></td><td>flag: every value in the list must match (AND); default is OR</td></tr>
        </table>
        <p>Example: <code>Image|endswith|all: [\calc.exe, \notepad.exe]</code>; both must match (AND).</p>
        <p><strong><code>|cidr</code></strong> does a real IP-in-network check (not a substring match). Use it in filter selections to exclude local/private IP ranges, e.g. <code>IpAddress|cidr: [10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, fc00::/7, fe80::/10]</code>. IPv4 and IPv6 are never cross-matched; an absent IP or <code>&quot;-&quot;</code> never matches a CIDR filter.</p>

        <h2 id="doc-conditions">Condition expressions</h2>
        <p>The <code>detection.condition</code> string combines named selections:</p>
        <ul>
          <li><strong>Selection names:</strong> <code>selection</code></li>
          <li><strong>Boolean:</strong> <code>and</code>, <code>or</code>, <code>not</code></li>
          <li><strong>Parentheses:</strong> <code>(a or b) and not c</code></li>
          <li><strong>Quantifiers:</strong> <code>1 of selection*</code>, <code>all of them</code></li>
        </ul>

        <h2 id="doc-destinations">Destinations</h2>
        <p>Destinations are <strong>named</strong> output targets. You define them per group (on the Groups tab) or in the agent's <code>config.ini [destinations]</code>. Rule actions reference them by name.</p>
        <table>
          <tr><th>URL scheme</th><th>Behavior</th></tr>
          <tr><td><code>file://output/siem.jsonl</code> (relative)</td><td>Append one event per line to that file <strong>under the agent's data directory</strong> (<code>%ProgramData%\ELFAgent\output\siem.jsonl</code>), the only tree the service account can write. A leading <code>./</code> is accepted.</td></tr>
          <tr><td><code>file:///C:/logs/siem.jsonl</code> (absolute)</td><td>Append to that exact path; the directory must grant the service account write access.</td></tr>
          <tr><td><code>http://host:port/path</code> / <code>https://…</code></td><td>POST via WinHTTP, through a disk-backed spool with retries so a slow SIEM never stalls the agent.</td></tr>
        </table>
        <p>Common destination names: <code>siem</code>, <code>data_lake</code>, <code>alerts</code>. The server also receives forwarded logs and alerts directly via <code>POST /logs</code> and <code>POST /alerts</code>, which is what populates the Logs and Alerts tabs.</p>
        <h3>Output format (<code>?format=</code>)</h3>
        <p>Append a query string to any destination URL to choose the document shape. The options are consumed by the agent and never sent to the endpoint.</p>
        <table>
          <tr><th>format</th><th>Document</th><th>Delivery</th><th>Auth option</th></tr>
          <tr><td><code>raw</code> (default)</td><td>Windows event XML, one per line; alerts as a text header + pretty XML</td><td>file append / one POST per action</td><td>none</td></tr>
          <tr><td><code>json</code></td><td>ELF flat JSON (<code>event_data.*</code> + <code>elf.rule_id/level/…</code>), NDJSON</td><td>chunked ≤1,000 docs / 2&nbsp;MB</td><td><code>token=</code> → <code>Authorization: Bearer</code></td></tr>
          <tr><td><code>ecs</code></td><td>Elastic Common Schema (winlogbeat shape, <code>process.*</code>, <code>user.*</code>, <code>threat.*</code>)</td><td>same</td><td>same</td></tr>
          <tr><td><code>hec</code></td><td>Splunk HTTP Event Collector envelope (<code>event=json|ecs</code> inside)</td><td>envelopes concatenated per POST</td><td><code>token=</code> → <code>Authorization: Splunk</code>; <code>index=</code>, <code>sourcetype=</code></td></tr>
          <tr><td><code>gelf</code></td><td>Graylog GELF 1.1 (flat <code>_elf_*</code> / <code>_event_data_*</code> fields)</td><td>one POST per message</td><td>none</td></tr>
          <tr><td><code>sentinel</code></td><td>Azure Monitor Logs Ingestion rows (<code>TimeGenerated</code>, <code>EventData</code>, …)</td><td>JSON array ≤1,000 rows / 1&nbsp;MB</td><td><code>tenant=</code>, <code>client=</code>, <code>secret=</code> (OAuth2 client credentials)</td></tr>
        </table>
        <p>Copy-paste starting points:</p>
        <pre>splunk   = https://splunk.example.com:8088/services/collector/event?format=hec&amp;token=&lt;HEC token&gt;&amp;index=elf
graylog  = http://graylog.example.com:12201/gelf?format=gelf
sentinel = https://&lt;dce&gt;.ingest.monitor.azure.com/dataCollectionRules/&lt;dcr-immutable-id&gt;/streams/Custom-ELF_CL?api-version=2023-01-01&amp;format=sentinel&amp;tenant=&lt;tenant-id&gt;&amp;client=&lt;app-id&gt;&amp;secret=env:ELF_SENTINEL_SECRET
ecsfile  = file://output/ecs.ndjson?format=ecs</pre>
        <p><code>token=env:VAR</code> / <code>secret=env:VAR</code> read the value from the agent service's environment instead of the URL. A secret over plain <code>http://</code> is rejected unless <code>insecure=1</code> is added (test environments only; it also disables TLS certificate checks on <code>https://</code>). Step-by-step setup for each SIEM, including the Sentinel table/DCR/app registration, is in <code>docs/SIEM.md</code>.</p>

        <h2 id="doc-metrics-data">Understanding metrics &amp; forwarding</h2>
        <p>The Metrics tab shows what your agents are forwarding.</p>
        <p>Every agent tracks four cumulative counters as it runs:</p>
        <ul>
          <li><code>events_created</code> / <code>bytes_created</code>: everything the host <em>generated</em> on the watched channels. The agent reads each channel's log metadata (oldest record number + record count) every poll and accumulates the delta of the newest record number, so this keeps counting even when a circular log wraps, and it includes all events, not just the rule-referenced subset that gets delivered. Events are exact; bytes are estimated from the average rendered size of delivered events.</li>
          <li><code>events_forwarded</code> / <code>bytes_forwarded</code>: what the agent actually <em>sent</em> to a destination.</li>
        </ul>
        <p>These are sent to the server on every poll. The two derived figures:</p>
        <div class="callout">
          <strong>% Forwarded = bytes_forwarded / bytes_created × 100</strong>: the fraction of data sent.<br>
          <strong>% Not forwarded = (1 − bytes_forwarded / bytes_created) × 100</strong>: the fraction filtered out by your rules.<br>
          If an agent created 100 MB of events and forwarded 8 MB, then 8% was forwarded and 92% was filtered out.
        </div>
        <p>The forwarded counters increment <strong>before</strong> the agent attempts to send, regardless of whether destination resolution succeeds. The created counters are measured from the Windows event log itself, so the figures always reflect everything the host generated vs. what was actually sent; even if a destination is misconfigured, the "created" side still grows.</p>
        <p>The color coding on both bars gives a quick visual read: green means little is being forwarded, red means most of what you see is being forwarded.</p>
        <p>The numbers are <strong>cumulative since agent registration</strong> and are not affected by the date range. The date range only controls the event-count and bytes graphs below the table. The <strong>Reset Metrics</strong> button (admin-only, top of the tab) zeroes the cumulative counters and deletes stored forwarded-log batches (alerts are kept) so you can start a fresh measurement window; agents keep counting from zero onward.</p>

        <h2 id="doc-alerts-logs">Understanding alerts &amp; logs</h2>
        <h3>Alerts</h3>
        <p>An <strong>alert</strong> is created when a rule with an <code>alert</code> action fires. The alert includes the triggering event, the rule id, and the message you wrote in the action. Alerts appear in the Alerts tab and are also sent to the destination you named (e.g. <code>output/alerts.jsonl</code> on the agent host, or an HTTP endpoint).</p>
        <p><code>forward_event</code> rules produce forwarded logs, not alerts. For <code>alert</code>/<code>forward_buffer</code> on threshold/sequence rules, the engine dedupes by EventRecordID per rule, so the same triggering event does not produce duplicate alerts. When a rule has BOTH <code>alert</code> AND <code>forward_buffer</code> actions, only the <code>alert</code> action sends an alert; the <code>forward_buffer</code> action sends just the log batch (its notification alert is suppressed to avoid a duplicate). Forwarded events are also deduplicated per destination: however many rules ask for an event, each destination and the server receive it once (the batch is attributed to the first rule that asked), so the Logs tab and the forwarded counters never show the same event twice.</p>
        <h3>Logs (forwarded batches)</h3>
        <p>The Logs tab shows <strong>forwarded buffer batches</strong>, produced by <code>forward_buffer</code> actions. When such an action fires, the agent grabs its current in-memory event buffer (everything it's holding up to <code>retention_seconds</code> old) and sends the whole batch to the server. This sends the recent events from the host as context around the alert.</p>
        <p>The <strong>Events</strong> column in the Logs table is how many events were in that batch. The raw text file view shows the full JSONL.</p>
        <h3>Investigation keys</h3>
        <p>Every rule fire gets a 16-character <strong>alert id</strong>. The agent writes it on the alert and on every event of the batch that fire forwarded: in the structured SIEM formats as <code>elf.rule_id</code> / <code>elf.alert_id</code> (<code>json</code>, <code>ecs</code>, <code>hec</code>), <code>_elf_rule_id</code> / <code>_elf_alert_id</code> (<code>gelf</code>) and <code>RuleId</code> / <code>AlertId</code> (<code>sentinel</code>), as the <code>alert_id:</code> header line of a <code>raw</code> alert, and here as the <em>Investigation keys</em> line of an alert's detail and the <strong>Alert ID</strong> column on the Logs tab. Searching the SIEM for one alert id returns the alert and its context events; searching a rule id returns everything that rule ever produced. <code>forward_event</code> streams carry the rule id only (there is no alert).</p>

        <h2 id="doc-ui-audit">Audit tab (admin-only)</h2>
        <p>The Audit tab records every privileged action taken through the server: logins (and failed attempts), user/role changes, rule and group edits, imports, collects, clears, and agent enrollment. Each row shows the time, the acting user (or <code>agent:&lt;id&gt;</code> for machine actions), the action verb, the target entity, and a JSON detail blob (e.g. the prior value for an update).</p>
        <p><strong>Clear</strong> deletes all stored audit entries. The clear action itself is recorded <em>after</em> truncating, so the trail always shows who cleared the log and when. Clearing is admin-only and irreversible.</p>

        <h2 id="doc-limitations">Limitations</h2>
        <ul>
          <li><strong><code>group_by</code> is threshold-only.</strong> It's mandatory for threshold rules and rejected on simple/sequence rules. Sequence rules use a single global window keyed by <code>rule.id</code> (per-user sequence grouping is not yet implemented).</li>
          <li><strong><code>threshold_op</code> supports <code>gte</code>/<code>gt</code>/<code>eq</code> only.</strong> <code>lt</code>/<code>lte</code>/<code>neq</code> are not supported; under the current fire-then-reset model they would fire on every event after a reset.</li>
          <li><strong><code>distinct</code> counts unique values, not events.</strong> Repeats of an already-seen value refresh its last-seen time but never increase the count, so a ping storm to one host will not fire a sweep rule. <code>distinct</code> is threshold-only (rejected on simple/sequence rules).</li>
          <li><strong><code>&lt;missing&gt;</code> sentinel for unresolved group fields.</strong> If a <code>group_by</code> field is absent from an event, the event lands in a <code>&lt;missing&gt;</code> bucket rather than being dropped. Events with missing group fields are counted together in that bucket.</li>
          <li><strong>No field-name validation.</strong> The server can't validate that a field name is resolvable (it doesn't know the agent's field resolver). An unresolvable field behaves as <code>&lt;missing&gt;</code> for every event, which is effectively global counting. Use the field names from the <a href="#doc-fields" onclick="docScroll('fields');return false">Field resolution</a> table.</li>
          <li><strong>Memory grows with group cardinality.</strong> Each distinct group value creates a state entry. The engine prunes stale per-group states periodically, but a noisy host with many distinct users can accumulate entries between prune cycles.</li>
          <li><strong>Security channel access.</strong> Reading the Security event channel requires <code>SeSecurityPrivilege</code> (granted to the dedicated <code>ELFAgent</code> service account on install); the agent does <strong>not</strong> run as Administrator. When run as a console app for development, an elevated prompt is still needed for the Security channel. The agent disables console QuickEdit mode at startup so a mouse click in the console window can't pause output (not relevant in service mode, which has no console).</li>
          <li><strong>Hot reload.</strong> The agent re-reads its local <code>rules/</code> directory every 60s and pulls fresh rules from the server every <code>poll_interval_seconds</code>. Edits in the UI reach agents within one poll cycle.</li>
          <li><strong>Linux needs systemd and, for process rules, auditd.</strong> The Linux agent reads the journal; hosts without systemd are not supported. Program executions only appear when an audit rule records them (the install script's audit option), and one execution produces several audit records, so a <code>service: auditd</code> rule without a <code>type</code> selection matches each of them.</li>
          <li><strong>One operating system per rule.</strong> A rule's <code>logsource.product</code> decides where it runs: an agent skips rules written for the other operating system (and logs how many). Rules without a product run everywhere.</li>
        </ul>

      </div>
    </div>
  </div>

  <!-- ===================== Users tab (admin-only) ===================== -->
  <div id="users" class="tab" style="display:none">
    <div class="card">
      <h3 style="display:flex;align-items:center;gap:12px;flex-wrap:wrap">Users
        <button class="btn secondary sm" onclick="loadUsers()" title="Refresh" style="margin-left:auto">↻ Refresh</button>
      </h3>
      <table id="users-table"><thead><tr><th>ID</th><th>Username</th><th>Role</th><th>Actions</th></tr></thead><tbody></tbody></table>
    </div>
    <div class="card" style="margin-top:16px">
      <h3>Create New User</h3>
      <div style="display:flex;flex-wrap:wrap;gap:12px;align-items:flex-end">
        <label style="display:flex;flex-direction:column;gap:4px;font-size:13px">Username
          <input id="new-user-name" type="text" placeholder="e.g. analyst1" style="padding:8px;min-width:180px;background:#0d1117;border:1px solid #30363d;border-radius:4px;color:#c9d1d9">
        </label>
        <label style="display:flex;flex-direction:column;gap:4px;font-size:13px">Password
          <input id="new-user-pass" type="password" placeholder="Min 8 chars" style="padding:8px;min-width:180px;background:#0d1117;border:1px solid #30363d;border-radius:4px;color:#c9d1d9">
        </label>
        <label style="display:flex;flex-direction:column;gap:4px;font-size:13px">Role
          <select id="new-user-role" style="padding:8px;background:#0d1117;border:1px solid #30363d;border-radius:4px;color:#c9d1d9">
            <option value="viewer">viewer</option>
            <option value="rule_contributor">rule_contributor</option>
            <option value="admin">admin</option>
          </select>
        </label>
        <button class="btn success" onclick="createUser()">Create User</button>
      </div>
      <p class="muted" style="font-size:12px;margin-top:12px">Password must be ≥8 chars with ≥1 uppercase, ≥1 lowercase, ≥1 digit, and ≥1 symbol (e.g. <code>!@#$%</code>).</p>
    </div>
  </div>

  <div id="audit" class="tab" style="display:none">
    <div class="card">
      <h3 style="display:flex;align-items:center;gap:12px;flex-wrap:wrap">Audit Log
        <button class="btn secondary sm" onclick="loadAudit()" title="Refresh" style="margin-left:auto">↻ Refresh</button>
        <button class="btn danger sm" onclick="clearAudit()" title="Delete all audit entries">Clear</button>
      </h3>
      <p class="muted" style="font-size:12px;margin-top:0">Every privileged action is recorded: logins, user/role changes, rule/group/agent/list mutations, file uploads, and bulk imports. Newest first.</p>
      <table id="audit-table" style="font-size:12px"><thead><tr><th style="width:160px">Time</th><th style="width:120px">Actor</th><th style="width:160px">Action</th><th style="width:160px">Target</th><th>Detail</th></tr></thead><tbody></tbody></table>
    </div>
  </div>
</main>
<script>
let groups = [];
let rules = [];
let currentRule = null;   // the rule object being edited (null = new rule)
let validateTimer = null;
let lastValidation = { valid: false };

const api = async (p, o) => {
  const r = await fetch(p, o);
  if (r.status === 401) { showLoginOverlay(); throw new Error('Authentication required'); }
  if (!r.ok) { const t = await r.text(); throw new Error(t || r.statusText); }
  return r.json();
};
const el = id => document.getElementById(id);

// --- Auth state ---
let _currentUser = null;   // {username, role} or null

async function checkAuth() {
  // Called on page load. If authenticated, hide the login overlay and
  // apply role-based UI. If not, show the login overlay.
  try {
    const r = await fetch('/auth/me');
    if (r.ok) {
      _currentUser = await r.json();
      applyAuth();
    } else {
      showLoginOverlay();
    }
  } catch (e) {
    showLoginOverlay();
  }
}

function showLoginOverlay() {
  _currentUser = null;
  const ov = el('login-overlay');
  if (ov) { ov.style.display = 'flex'; }
  const ui = el('user-info');
  if (ui) ui.style.display = 'none';
}

function applyAuth() {
  // Hide the login overlay, show the user info, and apply role-based
  // visibility to nav tabs and action buttons.
  const ov = el('login-overlay');
  if (ov) ov.style.display = 'none';
  const ui = el('user-info');
  if (ui && _currentUser) {
    ui.style.display = 'flex';
    el('user-name').textContent = _currentUser.username;
    el('user-role').textContent = _currentUser.role;
  }
  // Users tab: admin-only
  const usersTab = el('tab-users');
  if (usersTab) usersTab.style.display = (_currentUser && _currentUser.role === 'admin') ? '' : 'none';
  // Audit tab: admin-only
  const auditTab = el('tab-audit');
  if (auditTab) auditTab.style.display = (_currentUser && _currentUser.role === 'admin') ? '' : 'none';
  // Role-based action visibility. admin can do everything; rule_contributor
  // can edit rules/lists but not agents/groups/binary; viewer is read-only.
  // The body gets exactly ONE role class so the CSS hiding rules don't
  // collide: role-admin (no hiding rule matches -> everything visible),
  // role-editor (admin-only hidden, editor-only visible), role-viewer (both
  // hidden). Do NOT add role-editor for admins; that would trigger the
  // `body.role-editor .admin-only { display:none }` rule and hide every
  // admin-only button (Add Agent, Create Group, Clear All, Delete, etc.).
  const isAdmin = _currentUser && _currentUser.role === 'admin';
  const isRuleContributor = _currentUser && _currentUser.role === 'rule_contributor';
  const canEditRules = isAdmin || isRuleContributor;
  document.body.classList.toggle('role-admin', isAdmin);
  document.body.classList.toggle('role-editor', isRuleContributor);
  document.body.classList.toggle('role-viewer', !canEditRules);
}

async function doLogin(event) {
  event.preventDefault();
  const u = el('login-user').value;
  const p = el('login-pass').value;
  const errEl = el('login-error');
  errEl.style.display = 'none';
  try {
    const r = await fetch('/auth/login', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({username: u, password: p}),
    });
    if (!r.ok) {
      const t = await r.text();
      errEl.textContent = t || 'Login failed';
      errEl.style.display = 'block';
      return false;
    }
    _currentUser = await r.json();
    applyAuth();
    // Reload current tab data now that we're authenticated
    showTab(_activeTab || 'agents');
  } catch (e) {
    errEl.textContent = e.message;
    errEl.style.display = 'block';
  }
  return false;
}

async function doLogout() {
  try { await fetch('/auth/logout', {method: 'POST'}); } catch (e) {}
  _currentUser = null;
  showLoginOverlay();
}

// --- Users tab (admin-only) ---
async function loadUsers() {
  if (!_currentUser || _currentUser.role !== 'admin') return;
  try {
    const users = await api('/users');
    const tb = el('users-table').querySelector('tbody');
    tb.innerHTML = users.map(u => `<tr>
      <td>${u.id}</td>
      <td>${esc(u.username)}</td>
      <td><select onchange="changeUserRole(${u.id}, this.value)" style="padding:4px;background:#0d1117;border:1px solid #30363d;border-radius:4px;color:#c9d1d9">
        <option value="viewer" ${u.role==='viewer'?'selected':''}>viewer</option>
        <option value="rule_contributor" ${u.role==='rule_contributor'?'selected':''}>rule_contributor</option>
        <option value="admin" ${u.role==='admin'?'selected':''}>admin</option>
      </select></td>
      <td>${u.username === _currentUser.username ? '<span class="muted">(you)</span>' : `<button class="btn danger sm" onclick="deleteUser(${u.id}, ${jsArg(u.username)})">Delete</button>`}</td>
    </tr>`).join('');
  } catch (e) {
    console.error('loadUsers:', e);
  }
}

async function createUser() {
  const username = el('new-user-name').value.trim();
  const password = el('new-user-pass').value;
  const role = el('new-user-role').value;
  if (!username || !password) { alert('Username and password are required'); return; }
  try {
    await api('/users', {method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({username, password, role})});
    el('new-user-name').value = '';
    el('new-user-pass').value = '';
    loadUsers();
  } catch (e) {
    alert('Failed to create user: ' + e.message);
  }
}

async function deleteUser(id, name) {
  if (!confirm(`Delete user "${name}"?`)) return;
  try {
    await api('/users/' + id, {method: 'DELETE'});
    loadUsers();
  } catch (e) {
    alert('Failed to delete user: ' + e.message);
  }
}

async function changeUserRole(id, role) {
  try {
    await api('/users/' + id + '/role', {method: 'PUT', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({role})});
    loadUsers();
  } catch (e) {
    alert('Failed to update role: ' + e.message);
    loadUsers();
  }
}

// --- Audit tab (admin-only) ---
async function loadAudit() {
  if (!_currentUser || _currentUser.role !== 'admin') return;
  try {
    const entries = await api('/audit?limit=500');
    const tb = el('audit-table').querySelector('tbody');
    if (!entries.length) {
      tb.innerHTML = '<tr><td colspan="5" class="muted" style="text-align:center;padding:16px">No audit entries yet.</td></tr>';
      return;
    }
    tb.innerHTML = entries.map(a => `<tr>
      <td>${fmtTime(a.ts)}</td>
      <td>${esc(a.actor || '')}</td>
      <td>${esc(a.action || '')}</td>
      <td>${esc(a.target || '')}</td>
      <td style="font-family:monospace;font-size:11px;word-break:break-all">${esc(a.detail || '')}</td>
    </tr>`).join('');
  } catch (e) {
    console.error('loadAudit:', e);
  }
}

// Clear the audit log (admin-only; the endpoint enforces the role too).
// The server records an audit.clear entry AFTER truncating, so the trail
// shows who cleared it.
async function clearAudit() {
  if (!_currentUser || _currentUser.role !== 'admin') return;
  if (!confirm('Delete ALL audit entries? This cannot be undone.')) return;
  try {
    const j = await api('/audit', { method: 'DELETE' });
    await loadAudit();
    alert('Deleted ' + j.deleted + ' audit entr' + (j.deleted === 1 ? 'y' : 'ies') + '.');
  } catch (e) { alert('Clear failed: ' + e.message); }
}

let _activeTab = null;
function showTab(t) {
  if (!el('tab-' + t) || !el(t)) t = 'agents';
  document.querySelectorAll('.tab').forEach(e => e.style.display = 'none');
  document.querySelectorAll('nav button').forEach(b => b.classList.remove('active'));
  el('tab-' + t).classList.add('active');
  el(t).style.display = '';
  _activeTab = t;
  // Remember the active tab so a manual browser refresh returns to it.
  try { sessionStorage.setItem('elf-tab', t); } catch (e) {}
  if (t === 'agents') loadAgents();
  if (t === 'groups') loadGroups();
  if (t === 'rules') { loadGroups().then(() => loadRules()); }
  if (t === 'lists') loadLists();
  if (t === 'alerts') loadAlerts();
  if (t === 'metrics') loadMetricsView();
  if (t === 'logs') loadLogsView();
  if (t === 'users') loadUsers();
  if (t === 'audit') loadAudit();
  if (t === 'docs') docScroll(null);
}
function fmtTime(ts) { return ts ? new Date(ts * 1000).toLocaleString() : '-'; }
// Scroll the Docs content to a section (by id suffix). Called by the TOC
// links and by showTab('docs'). Pass null to scroll to the top.
function docScroll(anchor) {
  const content = el('docs-content');
  if (!content) return;
  if (!anchor) { content.scrollTop = 0; docHighlightToc(null); return; }
  const target = el('doc-' + anchor);
  if (target) target.scrollIntoView({ block: 'start' });
  docHighlightToc(anchor);
}
function docHighlightToc(anchor) {
  document.querySelectorAll('#docs-toc a').forEach(a => a.classList.remove('active'));
  if (!anchor) return;
  const link = document.querySelector('#docs-toc a[href="#doc-' + anchor + '"]');
  if (link) link.classList.add('active');
}
function sevBadge(s) { return `<span class="badge ${s}">${s}</span>`; }
// HTML-escape for text AND attribute contexts: quotes are escaped too, so a
// value interpolated into title="..." or onclick="f('...')" can never break
// out of the attribute (agent-supplied strings such as a collect error or a
// hostname reach these templates).
function esc(s) { return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#39;'); }
// A value passed as an argument inside an inline handler, e.g.
// onclick="delAgent(${jsArg(id)})": JSON-quoted for JavaScript, then
// HTML-escaped for the attribute. Safe for any id/hostname the API accepts.
function jsArg(s) { return esc(JSON.stringify(String(s == null ? '' : s))); }

// --- Agents ---
// Cached agent rows so the search filter can re-render without refetching.
let _agentsCache = [];
async function loadAgents() {
  // Ensure groups are loaded so the group dropdown can be populated.
  if (!groups.length) { await loadGroups(); }
  _agentsCache = await api('/agents');
  renderAgents();
}
function renderAgents() {
  const q = (el('agents-search') ? el('agents-search').value : '').trim().toLowerCase();
  const rows = _agentsCache.filter(a => {
    if (!q) return true;
    return ((a.hostname || '').toLowerCase().includes(q) || (a.ip_address || '').toLowerCase().includes(q));
  });
  const tb = document.querySelector('#agents-table tbody');
  // A collect-logs date the operator has typed must survive the 5 s
  // auto-refresh re-render: remember every panel input's value, restore after.
  const savedStarts = {};
  tb.querySelectorAll('input[id^="collect-start-"]').forEach(i => { if (i.value) savedStarts[i.id] = i.value; });
  if (!rows.length) { tb.innerHTML = `<tr><td colspan="9" class="muted">${_agentsCache.length ? 'No agents match your search.' : 'No agents registered yet.'}</td></tr>`; return; }
  // Single-pass render: build the rows as one string and assign once
  // (`tb.innerHTML +=` per row re-parses the whole table on every row).
  const parts = [];
  rows.forEach(a => {
    const opts = groups.map(g => `<option value="${g.id}"${g.id === a.group_id ? ' selected' : ''}>${esc(g.name)}</option>`).join('');
    const sel = `<select onchange="setAgentGroup(${jsArg(a.agent_id)}, this.value)" style="padding:4px;font-size:12px;width:auto">${opts}</select>`;
    // Per-agent command status badge from the latest command (pending/sent/done/failed).
    const pc = a.pending_command;
    let statusCell = '<span class="muted">-</span>';
    if (pc) {
      const st = pc.status;
      const cls = st === 'done' ? 'ok' : (st === 'failed' ? 'danger' : (st === 'pending' ? 'warn' : 'info'));
      let label = st;
      if (st === 'done' && pc.result) { try { const r = JSON.parse(pc.result); if (r && r.events_collected != null) label = 'done (' + r.events_collected + ' evts)'; } catch (e) {} }
      if (st === 'failed' && pc.error) label = 'failed';
      statusCell = `<span class="badge ${cls}" title="${st === 'failed' ? esc(pc.error || '') : ''}">${esc(label)}</span>`;
    }
    const open = _agentExpanded.has(a.agent_id);
    parts.push(`<tr id="arow-${esc(a.agent_id)}"><td>${esc(a.agent_id)}</td><td>${esc(a.hostname)||'-'}</td><td>${esc(a.ip_address)||'-'}</td><td>${esc(a.os_name)||'-'}</td><td>${sel}</td><td>${fmtTime(a.last_seen)}</td><td>${fmtTime(a.first_seen)}</td><td>${statusCell}</td><td style="white-space:nowrap"><button class="btn secondary sm" onclick="toggleAgentPanel(${jsArg(a.agent_id)})" title="Collect logs / actions">${open ? '&#9650;' : '&#9660;'}</button> <button class="btn danger sm admin-only" onclick="delAgent(${jsArg(a.agent_id)})">Delete</button></td></tr>`);
    // Expandable actions panel (hidden by default). Holds the collect-logs form.
    if (open) {
      parts.push(`<tr class="agent-panel-row"><td colspan="9">${renderAgentPanel(a)}</td></tr>`);
    }
  });
  tb.innerHTML = parts.join('');
  for (const id in savedStarts) { const i = el(id); if (i) i.value = savedStarts[id]; }
}
function renderAgentPanel(a) {
  const pc = a.pending_command;
  const inFlight = pc && (pc.status === 'pending' || pc.status === 'sent');
  let statusLine = '';
  if (pc) {
    if (pc.status === 'pending') statusLine = '<span class="badge warn">pending</span> <span class="muted">waiting for the agent to poll</span>';
    else if (pc.status === 'sent') statusLine = '<span class="badge info">collecting</span> <span class="muted">agent is pulling events</span>';
    else if (pc.status === 'done') {
      let n = '?';
      try { const r = JSON.parse(pc.result || '{}'); if (r && r.events_collected != null) n = r.events_collected; } catch (e) {}
      statusLine = `<span class="badge ok">done</span> <span class="muted">${n} event${n === 1 ? '' : 's'} collected; see the Logs tab (rule = __collect__)</span>`;
    } else if (pc.status === 'failed') statusLine = `<span class="badge danger">failed</span> <span class="muted">${esc(pc.error || 'error')}</span>`;
  }
  return `
    <div style="padding:10px 12px;background:#0f172a;border:1px solid #334155;border-radius:6px;margin:4px 0">
      <div style="font-weight:600;margin-bottom:8px">Collect logs</div>
      <div class="muted" style="font-size:12px;margin-bottom:8px">Pull every Windows event from this host starting at the date below. Events appear in the Logs tab tagged <code>__collect__</code>. One in-flight collection per agent.</div>
      <div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap">
        <label style="font-size:13px">Start date (required):</label>
        <input id="collect-start-${esc(a.agent_id)}" type="datetime-local" style="padding:5px 8px;font-size:13px;background:#0f172a;border:1px solid #334155;border-radius:6px;color:#e2e8f0" />
        <button class="btn primary sm" onclick="collectLogs(${jsArg(a.agent_id)})" ${inFlight ? 'disabled title="A collection is already in progress"' : ''}>Collect logs</button>
      </div>
      <div id="collect-status-${esc(a.agent_id)}" style="margin-top:8px;font-size:13px">${statusLine}</div>
    </div>`;
}
let _agentExpanded = new Set();
function toggleAgentPanel(id) {
  if (_agentExpanded.has(id)) _agentExpanded.delete(id); else _agentExpanded.add(id);
  renderAgents();
}
async function collectLogs(id) {
  const input = el('collect-start-' + id);
  if (!input || !input.value) { alert('Please pick a start date.'); return; }
  const status = el('collect-status-' + id);
  if (status) status.innerHTML = '<span class="muted">Sending request…</span>';
  try {
    const res = await api('/agents/' + encodeURIComponent(id) + '/collect', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ start_time: input.value }) });
    if (status) status.innerHTML = `<span class="badge warn">pending</span> <span class="muted">command #${res.command_id} queued, waiting for the agent to poll</span>`;
    // Refresh so the row status badge updates and the button disables.
    loadAgents();
  } catch (e) {
    if (status) status.innerHTML = `<span class="badge danger">error</span> <span class="muted">${esc(e.message)}</span>`;
  }
}
function filterAgents() { renderAgents(); }
function exportAgentsCsv() {
  const rows = _agentsCache;
  if (!rows.length) { alert('No agents to export.'); return; }
  const header = ['Agent ID','Hostname','IP Address','OS','Group','Last Seen','First Seen'];
  const lines = [header.join(',')];
  rows.forEach(a => {
    const grp = (groups.find(g => g.id === a.group_id) || {}).name || '';
    const cells = [a.agent_id, a.hostname||'', a.ip_address||'', a.os_name||'', grp, a.last_seen||'', a.first_seen||'']
      .map(v => {
        const s = String(v == null ? '' : v);
        // Quote cells that contain a comma, quote, or newline.
        return /[",\n]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s;
      });
    lines.push(cells.join(','));
  });
  const csv = lines.join('\n');
  const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url; a.download = 'agents.csv'; document.body.appendChild(a); a.click(); document.body.removeChild(a);
  URL.revokeObjectURL(url);
}
async function setAgentGroup(id, gid) {
  try { await api('/agents/' + encodeURIComponent(id) + '/group', { method:'PUT', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ group_id: parseInt(gid) }) }); }
  catch (e) { alert('Update group failed: ' + e.message); loadAgents(); }
}
async function delAgent(id) {
  if (!confirm('Delete agent "' + id + '"?')) return;
  // Ask separately before removing the agent's historical logs/alerts;
  // those may be needed for investigation even after the agent is gone.
  const cascade = confirm('Also delete this agent\'s logs and alerts?\nClick Cancel to keep them (recommended).');
  try { await api('/agents/' + encodeURIComponent(id) + (cascade ? '?cascade=true' : ''), { method:'DELETE' }); loadAgents(); }
  catch (e) { alert('Delete failed: ' + e.message); }
}

// --- Groups ---
let _gAgents = [];   // cached agents for membership counts
let _gExpanded = new Set();  // ids of expanded group cards
async function loadGroups() {
  groups = await api('/groups');
  // Fetch agents so we can show group membership counts.
  try { _gAgents = await api('/agents'); } catch (e) { _gAgents = []; }
  const host = document.getElementById('groups-list'); host.innerHTML = '';
  groups.forEach(g => {
    const members = _gAgents.filter(a => a.group_id === g.id);
    const card = document.createElement('div'); card.className = 'g-card'; card.id = 'g-card-' + g.id;
    const open = _gExpanded.has(g.id);
    const head = document.createElement('div'); head.className = 'g-card-head'; head.onclick = () => toggleGroupCard(g.id);
    head.innerHTML =
      `<span class="g-chev" id="g-chev-${g.id}">${open ? '&#9660;' : '&#9654;'}</span>` +
      `<span class="g-name">${esc(g.name)}</span>` +
      `<span class="g-desc">${esc(g.description) || ''}</span>` +
      `<span class="g-count" title="Number of agents in this group">${members.length} host${members.length === 1 ? '' : 's'}</span>`;
    card.appendChild(head);
    const body = document.createElement('div'); body.className = 'g-card-body' + (open ? ' open' : ''); body.id = 'g-body-' + g.id;
    body.innerHTML = renderGroupBody(g, members);
    card.appendChild(body);
    host.appendChild(card);
  });
  // populate the rules group filter
  const sel = el('rule-group-filter');
  const prev = sel.value;
  sel.innerHTML = groups.map(g => `<option value="${g.id}">${esc(g.name)}</option>`).join('');
  if (prev && groups.some(g => String(g.id) === prev)) sel.value = prev;
}
function renderGroupBody(g, members) {
  // Settings section: retention, poll, destinations editor, save button.
  const dests = g.destinations || [];
  let destRows = dests.map((d, i) =>
    `<div class="g-dest-row" data-i="${i}">
       <input class="g-dn" value="${esc(d.name)}" placeholder="name" />
       <input class="g-du" value="${esc(d.url)}" placeholder="file://output/x.jsonl?format=ecs" title="file://, http:// or https://; add ?format=json|ecs|hec|gelf|sentinel (see Docs → Destinations)" />
       <button class="g-dx" onclick="removeDestRow(${g.id}, this)" title="Remove destination">&times;</button>
     </div>`).join('');
  if (!destRows) destRows = '<div class="muted" style="font-size:12px;margin-bottom:6px">No destinations configured.</div>';
  const destHint = '<div class="muted" style="font-size:11px;margin:4px 0 6px">Formats: raw (default), json, ecs, hec (Splunk), gelf (Graylog), sentinel (see <a href="#" onclick="showTab(\'docs\');docScroll(\'destinations\');return false">docs &amp; copy-paste URLs</a>)</div>';
  const memberTbl = members.length
    ? `<table style="margin:6px 0 12px;font-size:12px;background:transparent;width:100%">
         <thead><tr><th style="padding:4px 8px;text-align:left">Hostname</th><th style="padding:4px 8px;text-align:left">IP Address</th><th style="padding:4px 8px;text-align:left">OS</th><th style="padding:4px 8px;text-align:left">Last Seen</th></tr></thead>
         <tbody>${members.map(a => `<tr><td style="padding:4px 8px">${esc(a.agent_id)}</td><td style="padding:4px 8px">${esc(a.ip_address)||'-'}</td><td style="padding:4px 8px">${esc(a.os_name)||'-'}</td><td style="padding:4px 8px">${fmtTime(a.last_seen)}</td></tr>`).join('')}</tbody>
       </table>`
    : '<div class="muted" style="font-size:12px;margin:6px 0 12px">No agents in this group.</div>';
  return `
    <div style="font-size:12px;color:#64748b;margin-bottom:6px">Agents</div>
    ${memberTbl}
    <div style="font-size:12px;color:#64748b;margin-bottom:6px">Settings</div>
    <div class="row" style="margin-bottom:8px">
      <div><label>Retention (seconds)</label><input id="g-ret-${g.id}" type="number" min="1" value="${g.retention_seconds}" /></div>
      <div><label>Poll interval (seconds)</label><input id="g-poll-${g.id}" type="number" min="1" value="${g.poll_interval_seconds}" /></div>
    </div>
    <label style="display:flex;align-items:center;gap:6px;font-size:13px;font-weight:normal;cursor:pointer;margin-bottom:8px">
      <input type="checkbox" id="g-mirror-${g.id}" ${g.mirror_logs === 0 ? '' : 'checked'} style="width:auto;margin:0" />
      Mirror logs to the ELF server
      <span class="muted" style="font-size:11px">(uncheck to keep alerts only)</span>
    </label>
    <div style="font-size:12px;color:#64748b;margin-bottom:6px">Destinations</div>
    <div id="g-dests-${g.id}">${destRows}</div>
    ${destHint}
    <button class="btn secondary sm" onclick="addDestRow(${g.id})" style="margin-bottom:10px">+ Add destination</button>
    <div style="display:flex;gap:8px;justify-content:flex-end">
      ${g.id !== 1 ? `<button class="btn danger admin-only" onclick="delGroup(${g.id})">Delete Group</button>` : ''}
      <button class="btn admin-only" onclick="saveGroup(${g.id})">Save</button>
    </div>`;
}
function toggleGroupCard(id) {
  const body = el('g-body-' + id);
  const chev = el('g-chev-' + id);
  if (!body) return;
  const open = body.classList.toggle('open');
  if (chev) chev.innerHTML = open ? '&#9660;' : '&#9654;';
  if (open) _gExpanded.add(id); else _gExpanded.delete(id);
}
function addDestRow(gid) {
  const host = el('g-dests-' + gid);
  const i = host.querySelectorAll('.g-dest-row').length;
  const div = document.createElement('div');
  div.className = 'g-dest-row'; div.setAttribute('data-i', i);
  div.innerHTML = `<input class="g-dn" placeholder="name" /><input class="g-du" placeholder="file://output/x.jsonl?format=ecs" title="file://, http:// or https://; add ?format=json|ecs|hec|gelf|sentinel (see Docs → Destinations)" /><button class="g-dx" onclick="removeDestRow(${gid}, this)" title="Remove destination">&times;</button>`;
  host.appendChild(div);
  div.querySelector('.g-dn').focus();
}
function removeDestRow(gid, btn) {
  const host = el('g-dests-' + gid);
  const row = btn.closest('.g-dest-row');
  if (row) row.remove();
  // If no rows remain, show the empty placeholder.
  if (!host.querySelectorAll('.g-dest-row').length) {
    host.innerHTML = '<div class="muted" style="font-size:12px;margin-bottom:6px">No destinations configured.</div>';
  }
}
function collectDestRows(gid) {
  const host = el('g-dests-' + gid);
  const out = [];
  host.querySelectorAll('.g-dest-row').forEach(row => {
    const name = row.querySelector('.g-dn').value.trim();
    const url = row.querySelector('.g-du').value.trim();
    if (name && url) out.push({ name, url });
  });
  return out;
}
function toggleGroupForm() {
  const form = el('g-form');
  const open = form.style.display !== 'none';
  form.style.display = open ? 'none' : 'block';
  if (!open) {
    // Reset the form fields when revealing it.
    el('g-name').value = ''; el('g-desc').value = '';
    el('g-retention').value = '30'; el('g-poll').value = '30';
    el('g-dests').value = '';
    el('g-name').focus();
  }
}
function parseDestTextareas(text) {
  // Parse "name = url" lines (one destination per line). Ignores blanks/comments.
  const out = [];
  (text || '').split('\n').forEach(line => {
    line = line.trim();
    if (!line || line.startsWith('#')) return;
    const eq = line.indexOf('=');
    if (eq < 0) return;
    const name = line.slice(0, eq).trim();
    const url = line.slice(eq + 1).trim();
    if (name && url) out.push({ name, url });
  });
  return out;
}
async function createGroup() {
  const name = el('g-name').value.trim();
  if (!name) { alert('Group name is required.'); el('g-name').focus(); return; }
  // Validate the numeric fields are positive integers.
  const retention = parseInt(el('g-retention').value, 10);
  const poll = parseInt(el('g-poll').value, 10);
  if (!retention || retention < 1) { alert('Retention must be a positive number of seconds.'); el('g-retention').focus(); return; }
  if (!poll || poll < 1) { alert('Poll interval must be a positive number of seconds.'); el('g-poll').focus(); return; }
  const destinations = parseDestTextareas(el('g-dests').value);
  // Build the group with all config fields. The server accepts the basic
  // name/description on create; destinations/retention/poll are set via the
  // update endpoint right after so a single click creates a fully-configured
  // group.
  try {
    const created = await api('/groups', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ name, description: el('g-desc').value.trim() }) });
    // Apply the configuration options in the same save.
    await api('/groups/'+created.id, { method:'PUT', headers:{'Content-Type':'application/json'}, body: JSON.stringify({
      retention_seconds: retention,
      poll_interval_seconds: poll,
      destinations
    }) });
    toggleGroupForm();
    // Refresh the groups list in place and make sure we stay on the groups tab.
    await loadGroups();
    showTab('groups');
  } catch (e) {
    alert('Create group failed: ' + e.message);
  }
}
async function saveGroup(id) {
  const retention = parseInt(el('g-ret-' + id).value, 10);
  const poll = parseInt(el('g-poll-' + id).value, 10);
  if (!retention || retention < 1) { alert('Retention must be a positive number of seconds.'); el('g-ret-' + id).focus(); return; }
  if (!poll || poll < 1) { alert('Poll interval must be a positive number of seconds.'); el('g-poll-' + id).focus(); return; }
  const destinations = collectDestRows(id);
  // Always send mirror_logs (a real false is meaningful: it stops log
  // batches for this group). The server uses exclude_none, so omitting it
  // would leave the stored value untouched, but the checkbox always has a
  // definite state here.
  const mirror = el('g-mirror-' + id) ? el('g-mirror-' + id).checked : true;
  try {
    await api('/groups/'+id, { method:'PUT', headers:{'Content-Type':'application/json'}, body: JSON.stringify({
      retention_seconds: retention,
      poll_interval_seconds: poll,
      destinations,
      mirror_logs: mirror
    }) });
    await loadGroups();
  } catch (e) {
    alert('Save failed: ' + e.message);
  }
}
async function delGroup(id) { if (confirm('Delete group? Agents move to default.')) { await api('/groups/'+id, { method:'DELETE' }); _gExpanded.delete(id); loadGroups(); } }

// --- Rules ---
async function loadRules() {
  const gid = el('rule-group-filter').value || (groups[0] && groups[0].id) || 1;
  el('rule-group-filter').value = gid;
  rules = await api('/rules?group_id=' + gid);
  renderRulesList();
}
// Render the rules list from the cached `rules` array, filtered by the
// search box. Split from loadRules so typing in the search box re-renders
// instantly without a server round-trip. Also called by loadRules after a
// fetch and by toggleRuleSelectMode (rows must pick up select mode).
function renderRulesList() {
  const list = el('rules-list');
  list.innerHTML = '';
  // Client-side filter: match name, rule_id, sigma_id, severity, or the
  // enabled/disabled state text. Case-insensitive substring.
  const q = (el('rules-search') && el('rules-search').value || '').trim().toLowerCase();
  const shown = !q ? rules : rules.filter(r =>
    (r.name || '').toLowerCase().includes(q) ||
    (r.rule_id || '').toLowerCase().includes(q) ||
    (r.sigma_id || '').toLowerCase().includes(q) ||
    (r.severity || '').toLowerCase().includes(q) ||
    ((r.enabled ? 'enabled' : 'disabled').includes(q)));
  // The rule count is shown in a header badge (next to the group dropdown)
  // and in a footer under the rule list. When filtering, show "N of M" so
  // the operator knows the filter hid some.
  const n = shown.length;
  const total = rules.length;
  const filter = el('rule-group-filter');
  // Update or create the count badge next to the dropdown.
  let badge = document.getElementById('rule-count-badge');
  if (!badge) {
    badge = document.createElement('span');
    badge.id = 'rule-count-badge';
    badge.className = 'rule-count-badge';
    filter.parentNode.insertBefore(badge, filter.nextSibling);
  }
  badge.textContent = (q && n !== total ? n + ' of ' + total : n) + (total === 1 ? ' rule' : ' rules');
  // Footer count under the list.
  const footer = el('rules-count-footer');
  if (footer) {
    footer.style.display = total ? '' : 'none';
    footer.textContent = (q && n !== total ? n + ' of ' + total + ' rules match' : n + (n === 1 ? ' rule' : ' rules') + ' in this group');
  }
  if (!total) {
    list.innerHTML = '<div class="empty-state" style="height:auto;padding:20px;">No rules in this group.<br>Click + New or ⬆ Import.</div>';
    return;
  }
  if (!shown.length) {
    list.innerHTML = '<div class="empty-state" style="height:auto;padding:20px;">No rules match "' + esc(q) + '".</div>';
    return;
  }
  const inSelectMode = el('rule-select-bar').style.display !== 'none';
  // One HTML string assigned once, and a single delegated click handler on
  // the list (installed below) instead of a DOM node + closure per rule; a
  // 3,000-rule SigmaHQ group re-renders on every keystroke in the search
  // box, so per-item work matters here.
  const parts = [];
  for (const r of shown) {
    const active = currentRule && currentRule.rule_id === r.rule_id ? ' active' : '';
    const meta = `<div class="ri-name">${esc(r.name || r.rule_id)}</div><div class="ri-id">${esc(r.sigma_id || r.rule_id)}</div><div class="ri-meta">${sevBadge(r.severity)} <span class="muted">${r.enabled?'enabled':'disabled'}</span></div>`;
    if (inSelectMode) {
      // Select mode: a checkbox in front; clicking anywhere on the row
      // toggles it (the editor is not opened).
      parts.push(`<div class="rule-item sel" data-rule-id="${esc(r.rule_id)}" data-gid="${r.group_id}"><input type="checkbox" data-role="rule-select" data-rule-id="${esc(r.rule_id)}"><div class="ri-body">${meta}</div></div>`);
    } else {
      parts.push(`<div class="rule-item${active}" data-rule-id="${esc(r.rule_id)}" data-gid="${r.group_id}" tabindex="0">${meta}</div>`);
    }
  }
  list.innerHTML = parts.join('');
  // If we're in select mode, sync the select-all checkbox to the freshly
  // rendered rows (a reload while in select mode shouldn't lose the user's
  // place, but the new rows start unchecked).
  if (inSelectMode) syncSelectAllCheckbox();
}
// One delegated handler for every rule row (see renderRulesList).
(function() {
  const list = el('rules-list');
  if (!list) return;
  const activate = e => {
    const item = e.target.closest('.rule-item');
    if (!item) return;
    if (item.classList.contains('sel')) {
      const cb = item.querySelector('input[data-role=rule-select]');
      if (cb && e.target !== cb) cb.checked = !cb.checked;
      updateRuleSelectCount();
    } else {
      openRule(item.dataset.ruleId, parseInt(item.dataset.gid, 10));
    }
  };
  list.addEventListener('click', activate);
  list.addEventListener('keydown', e => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); activate(e); } });
})();
// Move the "active" highlight without re-fetching or re-rendering the list.
function setActiveRuleItem(ruleId) {
  document.querySelectorAll('#rules-list .rule-item.active').forEach(i => i.classList.remove('active'));
  if (ruleId == null) return;
  const item = document.querySelector('#rules-list .rule-item[data-rule-id="' + CSS.escape(String(ruleId)) + '"]');
  if (item) item.classList.add('active');
}

// --- Bulk rule selection / deletion ---
// A "Select" toggle on the rules toolbar flips the list into select mode:
// each rule row gets a checkbox, a select-all control appears, and a
// Delete button shows the live count. Deleting prompts a confirmation that
// lists the rule ids being removed, then calls POST /rules/bulk-delete.
let _ruleSelectMode = false;

function toggleRuleSelectMode() {
  _ruleSelectMode = !_ruleSelectMode;
  el('rule-select-bar').style.display = _ruleSelectMode ? 'flex' : 'none';
  el('rule-select-toggle').classList.toggle('active', _ruleSelectMode);
  // Re-render the list so rows pick up (or drop) their checkboxes.
  renderRulesList();
}

function toggleAllRuleCheckboxes(checked) {
  document.querySelectorAll('#rules-list input[data-role=rule-select]').forEach(cb => {
    cb.checked = checked;
  });
  updateRuleSelectCount();
}

function getSelectedRuleIds() {
  return Array.from(document.querySelectorAll('#rules-list input[data-role=rule-select]:checked'))
    .map(cb => cb.dataset.ruleId);
}

function updateRuleSelectCount() {
  const ids = getSelectedRuleIds();
  const n = ids.length;
  el('rule-select-count').textContent = n + (n === 1 ? ' selected' : ' selected');
  el('rule-bulk-delete-btn').disabled = n === 0;
  el('rule-bulk-delete-btn').textContent = n ? `Delete (${n})` : 'Delete';
  syncSelectAllCheckbox();
}

function syncSelectAllCheckbox() {
  const cbs = document.querySelectorAll('#rules-list input[data-role=rule-select]');
  const all = el('rule-select-all');
  if (!cbs.length) { all.checked = false; all.indeterminate = false; return; }
  const checked = document.querySelectorAll('#rules-list input[data-role=rule-select]:checked');
  all.checked = checked.length === cbs.length;
  all.indeterminate = checked.length > 0 && checked.length < cbs.length;
  el('rule-select-all-label').textContent = all.checked ? 'Deselect all' : 'Select all';
}

async function confirmBulkDeleteRules() {
  const ids = getSelectedRuleIds();
  if (!ids.length) return;
  const gid = el('rule-group-filter').value || (groups[0] && groups[0].id) || 1;
  // Build a warning that names the count and lists the first few rule ids so
  // the operator can sanity-check what's about to go. Long lists are
  // truncated with a "... and N more" tail.
  const preview = ids.slice(0, 8).map(id => '  • ' + id).join('\n');
  const tail = ids.length > 8 ? `\n  ... and ${ids.length - 8} more` : '';
  const msg = `You are about to permanently delete ${ids.length} rule${ids.length === 1 ? '' : 's'} from this group.\n\nRules:\n${preview}${tail}\n\nThis cannot be undone. Continue?`;
  if (!confirm(msg)) return;
  try {
    const res = await api('/rules/bulk-delete?group_id=' + gid, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ rule_ids: ids }),
    });
    // If the editor was open on a rule we just deleted, drop it.
    if (currentRule && ids.includes(currentRule.rule_id)) cancelEdit();
    loadRules();
    // Surface a result if the count differs from what was requested (e.g.
    // another user deleted some in parallel).
    if (res.deleted !== ids.length) {
      alert(`Deleted ${res.deleted} of ${ids.length} requested (some may have been removed already).`);
    }
  } catch (e) {
    alert('Bulk delete failed: ' + e.message);
  }
}

function openRule(ruleId, gid) {
  // The /rules list returns a lightweight summary (no yaml_body) so 2600
  // rules render fast. Fetch the full rule (with yaml_body) on demand when
  // the user actually opens one for editing.
  el('rules-empty').style.display = 'none';
  el('rules-editor-pane').style.display = 'flex';
  el('r-yaml').value = 'Loading...';
  el('save-rule-btn').disabled = true;
  setValidation('muted', 'Loading rule...');
  setActiveRuleItem(ruleId);   // highlight now; no list refetch (3k rules = a big payload)
  api('/rules/' + encodeURIComponent(ruleId) + '?group_id=' + gid).then(r => {
    currentRule = r;
    el('r-yaml').value = r.yaml_body || '';
    el('save-rule-btn').disabled = true;
    setValidation('muted', 'Type to validate YAML...');
    scheduleValidate(true);
  }).catch(e => {
    setValidation('error', 'Failed to load rule: ' + e.message);
    el('r-yaml').value = '';
  });
}

function newRule() {
  currentRule = null;
  el('rules-empty').style.display = 'none';
  el('rules-editor-pane').style.display = 'flex';
  el('r-yaml').value = 'title: New Rule\nid: win_new_rule\nstatus: stable\ndescription: Detects ...\nauthor: ELF\ndate: 2026-10-01\nlevel: medium\nlogsource:\n  product: windows\n  service: security\ndetection:\n  selection:\n    EventID: 4624\n  condition: selection\nfalsepositives:\n  - None\nelf:\n  actions:\n    - type: forward_event\n      destination: siem\n';
  el('save-rule-btn').disabled = true;
  setActiveRuleItem(null);
  scheduleValidate(true);
}

function cancelEdit() {
  currentRule = null;
  el('rules-editor-pane').style.display = 'none';
  el('rules-empty').style.display = 'flex';
  setActiveRuleItem(null);
}

function setValidation(cls, msg) {
  const s = el('validation-status');
  s.className = 'validation-status ' + cls;
  s.textContent = msg;
}

function scheduleValidate(immediate) {
  if (validateTimer) clearTimeout(validateTimer);
  const delay = immediate ? 0 : 400;
  validateTimer = setTimeout(validateYaml, delay);
  if (!immediate) setValidation('checking', 'Checking...');
}

async function validateYaml() {
  const yamlBody = el('r-yaml').value;
  if (!yamlBody.trim()) { setValidation('err', 'YAML body is empty.'); el('save-rule-btn').disabled = true; lastValidation = {valid:false}; return; }
  try {
    const res = await api('/rules/validate', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ yaml_body: yamlBody }) });
    lastValidation = res;
    if (res.valid) {
      setValidation('ok', '✓ Valid YAML' + (res.rule_id ? ': ' + res.rule_id : ''));
      el('save-rule-btn').disabled = false;
    } else {
      setValidation('err', '✗ ' + (res.error || 'Invalid YAML'));
      el('save-rule-btn').disabled = true;
    }
  } catch (e) {
    setValidation('err', '✗ Validation request failed: ' + e.message);
    el('save-rule-btn').disabled = true;
    lastValidation = {valid:false};
  }
}

async function saveRule() {
  if (!lastValidation.valid) { alert('Fix YAML errors before saving.'); return; }
  const gid = parseInt(el('rule-group-filter').value);
  // Derive name, severity, and enabled from the validated YAML (the server's
  // /rules/validate already parsed these from the body). The rule_id used as
  // the database key is the ORIGINAL rule_id when editing (so the existing
  // record is updated in place), or the YAML `id` field when creating a new
  // rule. This prevents a mismatched YAML id from spawning a duplicate rule.
  const yamlRuleId = lastValidation.rule_id;
  if (!yamlRuleId) { alert('Rule ID (YAML id field) is required.'); return; }
  const editingId = currentRule ? currentRule.rule_id : null;
  const keyRuleId = editingId || yamlRuleId;
  const body = {
    rule_id: keyRuleId,
    name: lastValidation.name || yamlRuleId,
    description: lastValidation.description || '',
    severity: lastValidation.severity || 'medium',
    enabled: lastValidation.enabled !== false,
    yaml_body: el('r-yaml').value,
  };
  try {
    if (editingId) {
      // Update the existing rule in place by its original rule_id.
      await api('/rules/' + encodeURIComponent(editingId) + '?group_id=' + gid, { method:'PUT', headers:{'Content-Type':'application/json'}, body: JSON.stringify(body) });
    } else {
      // Create a new rule keyed by the YAML id.
      await api('/rules?group_id=' + gid, { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify(body) });
    }
    currentRule = { rule_id: keyRuleId, group_id: gid };
    await loadRules();
    openRule(keyRuleId, gid);
  } catch (e) { alert('Save failed: ' + e.message); }
}

async function deleteCurrentRule() {
  if (!currentRule) { alert('No rule selected (new rules are not saved yet).'); return; }
  if (!confirm('Delete rule "' + currentRule.rule_id + '"?')) return;
  try {
    await api('/rules/' + encodeURIComponent(currentRule.rule_id) + '?group_id=' + currentRule.group_id, { method:'DELETE' });
    cancelEdit();
    loadRules();
  } catch (e) { alert('Delete failed: ' + e.message); }
}

// --- Bulk rule import (zip upload + SigmaHQ fetch) ---
// Two-step flow: Preview (dry_run=true) validates + counts without saving,
// then Import (dry_run=false) commits. The rule count is shown both in the
// preview summary (before the import completes) and in the rules list
// header badge + footer (after).
let _importLastSource = null;  // 'zip' | 'sigmahq'; remembers which source the preview ran on
let _importLastParams = null;  // the params used for the last preview (for commit)
let _importCommitToken = '';   // server-side cache token from a successful preview

// The severity→action form. Each severity has checkboxes for the three
// action types plus a destination input. At least one action must be
// checked for a severity to be imported.
const _IMPORT_SEVERITIES = ['critical', 'high', 'medium', 'low', 'informational'];
const _IMPORT_ACTIONS = ['alert', 'forward_event', 'forward_buffer'];

function renderImportSeverityMap() {
  const container = el('import-severity-map');
  container.innerHTML = '';
  _IMPORT_SEVERITIES.forEach(sev => {
    const row = document.createElement('div');
    row.style.cssText = 'display:flex;gap:8px;align-items:center;flex-wrap:wrap;padding:6px 8px;background:#0f172a;border:1px solid #334155;border-radius:6px';
    row.innerHTML = `<span class="badge ${sev}" style="min-width:80px;text-align:center">${sev}</span>`;
    // Per-severity "import" checkbox. Unchecked = skip this severity entirely.
    // Each severity is chosen independently rather than through a cascading
    // "minimum severity" threshold, so e.g. high + low can be imported
    // without medium.
    const importLbl = document.createElement('label');
    importLbl.style.cssText = 'display:flex;align-items:center;gap:4px;font-size:12px;cursor:pointer;font-weight:600;color:#e2e8f0';
    const importCb = document.createElement('input');
    importCb.type = 'checkbox';
    importCb.dataset.severity = sev;
    importCb.dataset.role = 'import';
    importCb.checked = true; // default: import every severity (operator unchecks to skip)
    importLbl.appendChild(importCb);
    importLbl.appendChild(document.createTextNode('import'));
    row.appendChild(importLbl);
    _IMPORT_ACTIONS.forEach(act => {
      const lbl = document.createElement('label');
      lbl.style.cssText = 'display:flex;align-items:center;gap:4px;font-size:12px;cursor:pointer';
      const cb = document.createElement('input');
      cb.type = 'checkbox';
      cb.dataset.severity = sev;
      cb.dataset.action = act;
      // Sensible defaults: critical/high → alert + forward_buffer; medium/low → forward_event.
      if ((sev === 'critical' || sev === 'high') && (act === 'alert' || act === 'forward_buffer')) cb.checked = true;
      if ((sev === 'medium' || sev === 'low' || sev === 'informational') && act === 'forward_event') cb.checked = true;
      lbl.appendChild(cb);
      lbl.appendChild(document.createTextNode(act));
      row.appendChild(lbl);
    });
    // Destination for this severity. Offer a dropdown of the currently
    // selected group's destination names (the agent only knows those),
    // falling back to a free-text input when the group has none defined.
    const destLbl = document.createElement('span');
    destLbl.className = 'muted';
    destLbl.style.cssText = 'font-size:11px;margin-left:4px';
    destLbl.textContent = '→ dest:';
    const group = groups.find(x => String(x.id) === String(el('rule-group-filter').value));
    const destNames = (group && Array.isArray(group.destinations) ? group.destinations : [])
      .map(d => (d && d.name ? String(d.name) : '')).filter(nm => nm);
    let destInput;
    if (destNames.length) {
      destInput = document.createElement('select');
      destNames.forEach(nm => {
        const opt = document.createElement('option');
        opt.value = nm;
        opt.textContent = nm;
        destInput.appendChild(opt);
      });
      // Default to 'siem' when the group defines it, else the first name.
      destInput.value = destNames.includes('siem') ? 'siem' : destNames[0];
    } else {
      // No destinations on this group: fall back to a free-text input so the
      // operator can still type any name (it will fail at the agent until a
      // destination with that name exists, but that's their call).
      destInput = document.createElement('input');
      destInput.type = 'text';
      destInput.placeholder = 'siem';
      destInput.value = 'siem';
      destInput.style.cssText = 'padding:3px 6px;width:90px;font-size:12px;background:#1e293b;border:1px solid #334155;border-radius:4px;color:#e2e8f0';
    }
    destInput.dataset.severity = sev;
    destInput.dataset.role = 'destination';
    row.appendChild(destLbl);
    row.appendChild(destInput);
    container.appendChild(row);
  });
}

function collectSeverityMap() {
  // Build {severity: [{type, destination}]} from the checkbox form. A severity
  // is only included if its per-row "import" checkbox is checked AND it has at
  // least one action checked. Severities omitted from the map are skipped by
  // the server (the existing `if lvl not in severity_map` guard).
  const map = {};
  _IMPORT_SEVERITIES.forEach(sev => map[sev] = []);
  // First, find which severities the operator chose to import.
  const importOn = new Set();
  document.querySelectorAll('#import-severity-map input[data-role=import]').forEach(cb => {
    if (cb.checked) importOn.add(cb.dataset.severity);
  });
  // Then collect the action checkboxes for those severities.
  document.querySelectorAll('#import-severity-map input[type=checkbox][data-action]').forEach(cb => {
    if (cb.checked && importOn.has(cb.dataset.severity)) {
      const sev = cb.dataset.severity;
      const act = cb.dataset.action;
      // Tag-agnostic selector: the destination control is a <select> when the
      // group defines destinations, else a free-text <input>.
      const destInput = document.querySelector(`#import-severity-map [data-role=destination][data-severity="${sev}"]`);
      const dest = destInput ? destInput.value.trim() || 'siem' : 'siem';
      map[sev].push({ type: act, destination: dest });
    }
  });
  return map;
}

function openImportModal() {
  el('import-rules-modal').style.display = 'flex';
  renderImportSeverityMap();
  el('import-status').textContent = '';
  el('import-results').style.display = 'none';
  el('import-commit-btn').disabled = true;
  el('import-commit-count').textContent = '';
  el('import-progress').style.display = 'none';
  el('import-sigmahq-assets').style.display = 'none';
  el('import-sigmahq-asset-list').innerHTML = '';
  el('import-sigmahq-assets-status').textContent = '';
  _importLastSource = null;
  _importLastParams = null;
  _importCommitToken = '';
}
function closeImportModal() {
  el('import-rules-modal').style.display = 'none';
}

// --- SigmaHQ release-asset picker ---
// Lists the assets attached to a SigmaHQ release (default r2026-07-01) so the
// operator can choose which curated packages to import via checkboxes.
async function loadSigmaAssets() {
  const tag = (el('import-sigmahq-tag').value || '').trim() || 'r2026-07-01';
  const box = el('import-sigmahq-assets');
  const list = el('import-sigmahq-asset-list');
  const statusEl = el('import-sigmahq-assets-status');
  box.style.display = '';
  list.innerHTML = '<div class="muted" style="padding:6px;font-size:12px">Loading assets for ' + esc(tag) + ' …</div>';
  statusEl.textContent = '';
  el('import-sigmahq-tag-label').textContent = '(' + tag + ')';
  try {
    const res = await fetch('/rules/import/sigmahq/assets?tag=' + encodeURIComponent(tag));
    if (!res.ok) { const t = await res.text(); throw new Error(t || res.statusText); }
    const data = await res.json();
    if (!data.assets || !data.assets.length) {
      list.innerHTML = '<div class="muted" style="padding:6px;font-size:12px">No assets found for tag ' + esc(tag) + '.</div>';
      return;
    }
    // The core packages nest: core ⊂ core+ ⊂ core++ ⊂ all_rules. Picking two
    // of them would only re-import the same rule ids (the server counts a
    // rule once regardless), so that family is a single choice; the
    // emerging-threats addon is a separate rule set and stays a checkbox.
    const tiered = a => /^sigma_(core|all)/i.test(a.name);
    let html = '';
    data.assets.forEach(a => {
      const sizeMb = (a.size / 1048576).toFixed(2);
      const checked = a.name === 'sigma_core.zip' ? 'checked' : '';
      const note = tiered(a) ? '<span class="muted" style="font-size:11px">tier: choose one</span>' : '<span class="muted" style="font-size:11px">separate rule set</span>';
      html += `<label style="display:flex;align-items:center;gap:8px;padding:5px 0;font-size:13px;cursor:pointer;border-bottom:1px solid #1e293b">
        <input type="checkbox" class="sigmahq-asset-cb" value="${esc(a.name)}" data-tier="${tiered(a) ? '1' : '0'}" ${checked} onchange="onSigmaAssetToggle(this)" />
        <span style="flex:1">${esc(a.name)}</span>${note}
        <span class="muted" style="font-size:11px;min-width:56px;text-align:right">${sizeMb} MB</span>
      </label>`;
    });
    list.innerHTML = html;
    statusEl.textContent = data.assets.length + ' asset(s). sigma_core.zip is the recommended starter set; core ⊂ core+ ⊂ core++ ⊂ all_rules, so pick one tier (plus the emerging-threats addon if wanted).';
  } catch (e) {
    list.innerHTML = '<div style="padding:6px;font-size:12px;color:#ef4444">✗ ' + esc(e.message || 'Failed to list assets.') + '</div>';
  }
}

// Keep at most one tiered package checked (see loadSigmaAssets).
function onSigmaAssetToggle(cb) {
  if (cb.dataset.tier !== '1' || !cb.checked) return;
  document.querySelectorAll('.sigmahq-asset-cb[data-tier="1"]').forEach(o => { if (o !== cb) o.checked = false; });
}

function _collectSigmaAssets() {
  // Return a comma-separated list of checked asset names.
  const cbs = document.querySelectorAll('.sigmahq-asset-cb:checked');
  return Array.from(cbs).map(cb => cb.value).join(',');
}

async function importFromZip(preview) {
  const f = el('import-file').files[0];
  if (!f) { alert('Choose a .zip file first.'); return; }
  const gid = parseInt(el('rule-group-filter').value) || 1;
  const smap = collectSeverityMap();
  const params = {
    group_id: gid, dry_run: preview,
    // The per-severity "import" checkboxes in the severity→action map
    // drive selection. Send the lowest level so the server's cascading
    // min_severity filter is a no-op (it never excludes anything the
    // operator didn't already exclude via the import checkboxes).
    min_severity: 'informational',
    logsource_filter: el('import-logsource-filter').value,
    overwrite: el('import-overwrite').value === '1',
    severity_map: JSON.stringify(smap),
  };
  _importLastSource = 'zip';
  _importLastParams = params;
  await _runImport('/rules/import', params, preview, 'zip');
}

async function importFromSigmaHQ(preview) {
  const assets = _collectSigmaAssets();
  if (!assets) { alert('List the SigmaHQ assets and check at least one package.'); return; }
  const gid = parseInt(el('rule-group-filter').value) || 1;
  const smap = collectSeverityMap();
  const tag = (el('import-sigmahq-tag').value || '').trim() || 'r2026-07-01';
  const params = {
    group_id: gid, dry_run: preview,
    // The per-severity "import" checkboxes in the severity→action map
    // drive selection. Send the lowest level so the server's cascading
    // min_severity filter is a no-op.
    min_severity: 'informational',
    logsource_filter: el('import-logsource-filter').value,
    overwrite: el('import-overwrite').value === '1',
    severity_map: JSON.stringify(smap),
    assets: assets,
    tag: tag,
  };
  _importLastSource = 'sigmahq';
  _importLastParams = params;
  await _runImport('/rules/import/sigmahq', params, preview, 'sigmahq');
}

// --- Progress bar helpers ---
// The zip upload uses an XHR so we can show upload progress. The server-side
// parse/validate step has no progress signal, so we show an indeterminate
// animated bar during that phase. SigmaHQ downloads happen server-side, so we
// show an indeterminate bar for the whole request.
function _showProgress(label, pct) {
  el('import-progress').style.display = '';
  el('import-progress-label').textContent = label;
  const bar = el('import-progress-bar');
  if (pct >= 0) {
    bar.style.width = pct + '%';
    el('import-progress-pct').textContent = Math.round(pct) + '%';
  } else {
    // Indeterminate: animate a bouncing bar.
    bar.style.width = '30%';
    bar.style.animation = 'importBarSlide 1.1s ease-in-out infinite';
    el('import-progress-pct').textContent = '';
  }
}
function _hideProgress() {
  el('import-progress').style.display = 'none';
  el('import-progress-bar').style.animation = '';
  el('import-progress-bar').style.width = '0%';
}

async function _runImport(endpoint, params, preview, sourceLabel) {
  const status = el('import-status');
  const btn = preview ? null : el('import-commit-btn');
  if (preview) {
    status.textContent = 'Validating ' + sourceLabel + ' …';
  } else {
    status.textContent = 'Importing ' + sourceLabel + ' …';
    if (btn) btn.disabled = true;
  }
  el('import-results').style.display = 'none';
  try {
    let res;
    if (sourceLabel === 'zip') {
      // Multipart upload with XHR so we can show upload progress, then an
      // indeterminate bar during server-side parse/validate.
      const fd = new FormData();
      fd.append('file', el('import-file').files[0]);
      const qs = new URLSearchParams({ group_id: params.group_id, dry_run: params.dry_run ? 'true' : 'false', min_severity: params.min_severity, logsource_filter: params.logsource_filter, overwrite: params.overwrite ? 'true' : 'false', severity_map: params.severity_map });
      res = await _xhrWithProgress(endpoint + '?' + qs.toString(), fd, 'Uploading zip');
    } else {
      // SigmaHQ fetch: no body, all params in query string. The download
      // happens server-side, so we show an indeterminate bar.
      _showProgress('Fetching & validating SigmaHQ assets', -1);
      const qs = new URLSearchParams({ group_id: String(params.group_id), dry_run: params.dry_run ? 'true' : 'false', min_severity: params.min_severity, logsource_filter: params.logsource_filter, overwrite: params.overwrite ? 'true' : 'false', severity_map: params.severity_map, assets: params.assets || '', tag: params.tag || '' });
      const r = await fetch(endpoint + '?' + qs.toString(), { method: 'POST' });
      if (!r.ok) { const t = await r.text(); throw new Error(t || r.statusText); }
      res = await r.json();
    }
    _hideProgress();
    _renderImportResults(res, preview);
  } catch (e) {
    _hideProgress();
    status.textContent = '✗ ' + (e.message || 'Import failed.');
    el('import-results').style.display = 'none';
    el('import-commit-btn').disabled = true;
    el('import-commit-count').textContent = '';
  }
}

// XHR wrapper that reports upload progress, then switches to an
// indeterminate bar while the server parses/validates. Resolves to the
// parsed JSON response (or rejects on error).
function _xhrWithProgress(url, formData, uploadLabel) {
  return new Promise((resolve, reject) => {
    const xhr = new XMLHttpRequest();
    xhr.open('POST', url);
    // Upload progress (bytes leaving the browser).
    xhr.upload.onprogress = (ev) => {
      if (ev.lengthComputable) {
        _showProgress(uploadLabel, (ev.loaded / ev.total) * 100);
      }
    };
    // Once the upload finishes, the server parses/validates, with no progress
    // signal for that, so show an indeterminate bar.
    xhr.upload.onload = () => {
      _showProgress('Validating rules', -1);
    };
    xhr.onload = () => {
      if (xhr.status >= 200 && xhr.status < 300) {
        try { resolve(JSON.parse(xhr.responseText)); }
        catch (e) { reject(new Error('Bad JSON response from server.')); }
      } else {
        reject(new Error(xhr.responseText || xhr.statusText || ('HTTP ' + xhr.status)));
      }
    };
    xhr.onerror = () => { reject(new Error('Network error during upload.')); };
    xhr.send(formData);
  });
}

function _renderImportResults(res, preview) {
  const status = el('import-status');
  const results = el('import-results');
  const summary = el('import-summary');
  const errorsEl = el('import-errors');
  const tableEl = el('import-preview-table');
  const commitBtn = el('import-commit-btn');
  const commitCount = el('import-commit-count');

  status.textContent = '';
  results.style.display = '';

  // Summary line with the count (shown before the import completes).
  const parts = [];
  if (preview) {
    parts.push(`<strong>${res.planned}</strong> rule(s) ready to import.`);
  } else {
    parts.push(`<strong>${res.written}</strong> rule(s) imported.`);
  }
  const skipped = [];
  if (res.skipped_no_id) skipped.push(`${res.skipped_no_id} no id`);
  if (res.skipped_severity) skipped.push(`${res.skipped_severity} severity filtered`);
  if (res.skipped_logsource) skipped.push(`${res.skipped_logsource} logsource filtered`);
  if (res.skipped_existing) skipped.push(`${res.skipped_existing} already exist`);
  if (res.skipped_duplicate) skipped.push(`${res.skipped_duplicate} duplicate${res.skipped_duplicate === 1 ? '' : 's'} across packages (counted once)`);
  if (res.skipped_invalid) skipped.push(`${res.skipped_invalid} invalid`);
  if (skipped.length) parts.push(`Skipped: ${skipped.join(', ')}.`);
  if (res.total_errors) parts.push(`${res.total_errors} error(s) (see below).`);
  summary.innerHTML = parts.join(' ');

  // Errors block.
  if (res.errors && res.errors.length) {
    errorsEl.style.display = '';
    errorsEl.innerHTML = res.errors.map(e => `<div style="margin-bottom:4px"><span class="badge danger">${esc(e.rule_id || '?')}</span> <span class="muted">${esc(e.file || '')}</span>: ${esc(e.error)}</div>`).join('');
  } else {
    errorsEl.style.display = 'none';
  }

  // Preview table.
  if (res.preview && res.preview.length) {
    let html = '<table style="width:100%;border-collapse:collapse;font-size:12px"><thead><tr style="background:#1e293b"><th style="text-align:left;padding:6px 8px;border-bottom:1px solid #334155">Severity</th><th style="text-align:left;padding:6px 8px;border-bottom:1px solid #334155">Name</th><th style="text-align:left;padding:6px 8px;border-bottom:1px solid #334155">Rule ID</th><th style="text-align:left;padding:6px 8px;border-bottom:1px solid #334155">File</th></tr></thead><tbody>';
    res.preview.forEach(p => {
      html += `<tr><td style="padding:4px 8px;border-bottom:1px solid #1e293b"><span class="badge ${p.severity}">${p.severity}</span></td><td style="padding:4px 8px;border-bottom:1px solid #1e293b">${esc(p.name)}</td><td style="padding:4px 8px;border-bottom:1px solid #1e293b;font-family:monospace;font-size:11px">${esc(p.rule_id)}</td><td style="padding:4px 8px;border-bottom:1px solid #1e293b;font-size:11px;color:#64748b">${esc(p.file)}</td></tr>`;
    });
    html += '</tbody></table>';
    tableEl.innerHTML = html;
  } else {
    tableEl.innerHTML = '<div class="muted" style="padding:10px;font-size:12px">No rules in the preview.</div>';
  }

  // Enable the Import button only after a successful preview with planned > 0.
  // Stash the commit token so the commit step doesn't re-upload/re-download.
  if (preview && res.planned > 0) {
    _importCommitToken = res.commit_token || '';
    commitBtn.disabled = false;
    commitCount.textContent = '(' + res.planned + ')';
  } else if (!preview) {
    // After a real import, disable the button and refresh the rule list so
    // the header badge + footer count update.
    _importCommitToken = '';
    commitBtn.disabled = true;
    commitCount.textContent = '';
    loadRules();
  } else {
    _importCommitToken = '';
    commitBtn.disabled = true;
    commitCount.textContent = '';
  }
}

async function importCommit() {
  // Commit the cached preview plan via the commit endpoint. This avoids
  // re-uploading the zip / re-downloading from SigmaHQ, which is what caused
  // the "failed to fetch" errors when the commit request timed out.
  if (!_importCommitToken) { alert('Run a preview first.'); return; }
  const status = el('import-status');
  status.textContent = 'Importing …';
  el('import-commit-btn').disabled = true;
  el('import-results').style.display = 'none';
  _showProgress('Writing rules to the database', -1);
  try {
    const res = await api('/rules/import/commit', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ commit_token: _importCommitToken }) });
    _hideProgress();
    _renderImportResults(res, false);
  } catch (e) {
    _hideProgress();
    status.textContent = '✗ ' + (e.message || 'Import failed.');
    el('import-results').style.display = 'none';
    el('import-commit-btn').disabled = false;  // let them retry
  }
}

// --- Lists (reusable value lists, global across all groups) ---
let lists = [];
let currentList = null;  // null = creating new

async function loadLists() {
  try { lists = await api('/lists'); } catch (e) { return; }
  renderLists();
}
// Render from the cached `lists` (opening a list only needs the highlight
// moved, not a refetch).
function renderLists() {
  const listEl = el('lists-list');
  if (!lists.length) {
    listEl.innerHTML = '<div class="empty-state" style="height:auto;padding:20px;">No lists yet.<br>Click + New.</div>';
    return;
  }
  listEl.innerHTML = lists.map(l => {
    const active = currentList && currentList.name === l.name ? ' active' : '';
    const lineCount = (l.content || '').split('\n').filter(x => x.trim() && !x.trim().startsWith('#')).length;
    return `<div class="rule-item${active}" data-name="${esc(l.name)}" tabindex="0"><div class="ri-name">${esc(l.name)}</div><div class="ri-id">${lineCount} value${lineCount === 1 ? '' : 's'}</div></div>`;
  }).join('');
}
(function() {
  const listEl = el('lists-list');
  if (!listEl) return;
  const activate = e => { const item = e.target.closest('.rule-item'); if (item) openList(item.dataset.name); };
  listEl.addEventListener('click', activate);
  listEl.addEventListener('keydown', e => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); activate(e); } });
})();

function openList(name) {
  const l = lists.find(x => x.name === name);
  if (!l) return;
  currentList = l;
  el('lists-empty').style.display = 'none';
  el('lists-editor-pane').style.display = 'flex';
  el('l-name').value = l.name || '';
  el('l-name').disabled = true;  // name is the key; can't rename via UI
  el('l-content').value = l.content || '';
  setListStatus('muted', 'Edit content and click Save List.');
  renderLists();  // refresh active highlight
}

function newList() {
  currentList = null;
  el('lists-empty').style.display = 'none';
  el('lists-editor-pane').style.display = 'flex';
  el('l-name').value = '';
  el('l-name').disabled = false;
  el('l-content').value = '# One value per line. Lines starting with # are comments.\n';
  setListStatus('muted', 'Enter a name and content.');
  renderLists();
}

function cancelListEdit() {
  currentList = null;
  el('lists-editor-pane').style.display = 'none';
  el('lists-empty').style.display = 'flex';
  renderLists();
}

function setListStatus(cls, msg) {
  const s = el('list-status');
  s.className = 'validation-status ' + cls;
  s.textContent = msg;
}

async function saveList() {
  const name = el('l-name').value.trim();
  const content = el('l-content').value;
  if (!name) { setListStatus('err', 'List name is required.'); return; }
  try {
    if (currentList) {
      // Update existing list (name is the key).
      await api('/lists/' + encodeURIComponent(currentList.name), { method:'PUT', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ name: currentList.name, content }) });
    } else {
      // Create new list.
      await api('/lists', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ name, content }) });
    }
    await loadLists();
    openList(name);
    setListStatus('ok', 'Saved.');
  } catch (e) { setListStatus('err', 'Save failed: ' + e.message); }
}

async function deleteCurrentList() {
  if (!currentList) { alert('No list selected (new lists are not saved yet).'); return; }
  if (!confirm('Delete list "' + currentList.name + '"? Rules referencing @@' + currentList.name + ' will match nothing until recreated.')) return;
  try {
    await api('/lists/' + encodeURIComponent(currentList.name), { method: 'DELETE' });
    cancelListEdit();
  } catch (e) { alert('Delete failed: ' + e.message); }
}

// --- Alerts / Logs ---
const AUTO_REFRESH_INTERVAL_MS = 5000;  // 5 seconds
let autoRefreshTimer = null;
let autoRefreshInFlight = false;  // guard against overlapping refreshes

// Refresh whichever tab is currently visible. Errors are swallowed so a
// transient server error never stops the timer or spams the console.
function autoRefreshVisible() {
  if (autoRefreshInFlight) return;  // previous refresh still running
  if (!_activeTab) return;
  // Pause auto-refresh while the user is interacting: a non-collapsed text
  // selection (they're copying something), any open modal, or the datetime
  // picker popup. Re-rendering under the user's cursor loses their state.
  try {
    const sel = window.getSelection();
    if (sel && !sel.isCollapsed) return;
  } catch (e) {}
  for (const m of document.querySelectorAll('.modal-overlay')) {
    if (m.style.display !== 'none') return;
  }
  if (_dtState) return;  // datetime picker is open
  // A focused control inside a re-rendered region (an agent's group
  // dropdown, a collect-logs date, a group's destination row) would be
  // destroyed mid-edit; wait until the operator moves on.
  const ae = document.activeElement;
  if (ae && /^(SELECT|INPUT|TEXTAREA)$/.test(ae.tagName) && ae.closest &&
      ae.closest('tbody, .g-card-body, .agent-panel-row')) return;
  const fn = _activeTab === 'alerts' ? loadAlerts
           : _activeTab === 'metrics' ? refreshMetricsView
           : _activeTab === 'logs' ? refreshLogsView
           : _activeTab === 'agents' ? loadAgents : null;
  if (!fn) return;
  autoRefreshInFlight = true;
  Promise.resolve(fn()).catch(() => {}).finally(() => { autoRefreshInFlight = false; });
}

// Global auto-refresh toggle. Persisted in localStorage so it survives
// browser refresh and applies to whatever tab is currently visible.
function setAutoRefresh(on) {
  const statusEl = el('global-autorefresh-status');
  try { localStorage.setItem('elf-autorefresh', on ? '1' : '0'); } catch (e) {}
  if (on) {
    if (autoRefreshTimer) clearInterval(autoRefreshTimer);
    autoRefreshTimer = setInterval(autoRefreshVisible, AUTO_REFRESH_INTERVAL_MS);
    if (statusEl) statusEl.textContent = '(every ' + (AUTO_REFRESH_INTERVAL_MS / 1000) + 's)';
  } else {
    if (autoRefreshTimer) { clearInterval(autoRefreshTimer); autoRefreshTimer = null; }
    if (statusEl) statusEl.textContent = '';
  }
}

// Pretty-print a single-line XML string: one tag per line, 2-space indent.
// Uses DOMParser to parse, then a recursive serializer with indentation.
// Falls back to the raw string if parsing fails.
function prettyPrintXml(s) {
  if (!s) return '';
  let doc;
  try { doc = new DOMParser().parseFromString(s, 'text/xml'); }
  catch (e) { return s; }
  if (doc.getElementsByTagName('parsererror').length) return s;
  const out = [];
  (function walk(n, d) {
    for (let c = n.firstChild; c; c = c.nextSibling) {
      if (c.nodeType === 3) { // text
        const t = (c.textContent || '').trim();
        if (t) { out.push('  '.repeat(d) + t); }
      } else if (c.nodeType === 1) { // element
        const attrs = Array.from(c.attributes || []).map(a => a.name + '="' + a.value + '"').join(' ');
        const tag = attrs ? c.nodeName + ' ' + attrs : c.nodeName;
        const selfClose = !c.childNodes.length;
        out.push('  '.repeat(d) + (selfClose ? '<' + tag + '/>' : '<' + tag + '>'));
        if (!selfClose) walk(c, d + 1);
      }
    }
  })(doc.documentElement, 0);
  return out.join('\n');
}

// Extract a summary of key fields from the event XML for the alert dropdown.
function extractEventSummary(s) {
  if (!s) return null;
  let doc;
  try { doc = new DOMParser().parseFromString(s, 'text/xml'); }
  catch (e) { return null; }
  if (doc.getElementsByTagName('parsererror').length) return null;
  const get = (tag) => { const e = doc.querySelector(tag); return e ? (e.textContent || '').trim() : ''; };
  const attr = (tag, attrName) => { const e = doc.querySelector(tag); return e && e.getAttribute(attrName) ? e.getAttribute(attrName) : ''; };
  const ed = {};
  doc.querySelectorAll('EventData Data').forEach(d => {
    const name = d.getAttribute('Name');
    if (name) ed[name] = (d.textContent || '').trim();
  });
  return {
    event_id: get('EventID'),
    channel: get('Channel'),
    computer: get('Computer'),
    time_created: attr('TimeCreated', 'SystemTime'),
    event_data: ed,
  };
}

// Render the alert detail dropdown content: field summary table + collapsible raw XML.
// For sequence rules, `seqEvents` carries the prior-stage events that formed
// the sequence (the full attack chain). They are rendered as a labeled list
// above the trigger so the analyst sees the progression that led to the alert.
// For threshold rules, `winEvents` carries the events that filled the sliding
// window (all counted events, or one representative per unique value for
// `distinct` rules), rendered the same way so the analyst sees every event
// that contributed to the threshold, not just the trigger.
// `extra` (optional) carries the agent's bookkeeping about the evidence:
//   seqTruncated / winTruncated: how many older evidence events the agent
//     left out of the payload (it keeps the most recent N).
//   alsoMatched: ids of lower-severity Simple rules that matched the same
//     event but were suppressed by severity selection; shown as links so
//     the analyst can see every rule that detected the event.
function renderAlertDetail(xml, seqEvents, winEvents, extra) {
  extra = extra || {};
  let h = '<div class="alert-detail">';
  // Investigation keys: the same rule id / alert id are on the forwarded
  // events in the SIEM (elf.rule_id / elf.alert_id) and on the log batch
  // this fire produced (Logs tab), so one search pulls the whole incident.
  if (extra.alertId || extra.ruleId) {
    h += '<div class="seq-label" style="width:100%">Investigation keys: ' +
      (extra.ruleId ? 'rule_id <code>' + esc(extra.ruleId) + '</code>' : '') +
      (extra.alertId ? (extra.ruleId ? ' · ' : '') + 'alert_id <code>' + esc(extra.alertId) + '</code>' : '') +
      '</div>';
  }
  if (Array.isArray(extra.alsoMatched) && extra.alsoMatched.length > 0) {
    h += '<div class="seq-label">Also matched (suppressed by severity): ' +
      extra.alsoMatched.map(id =>
        // jsArg, not a bare JSON.stringify: the double quotes JSON produces
        // would terminate the onclick="..." attribute and the link did nothing.
        '<a href="#" onclick="openRuleFromAlert(' + jsArg(id) + ');return false;">' + esc(id) + '</a>'
      ).join(', ') + '</div>';
  }
  const truncNote = n => (n > 0 ? ' <span class="muted">(' + n + ' older not shown)</span>' : '');
  // Sequence events (prior stages), shown first so the chain reads top-down.
  if (seqEvents && seqEvents.length > 0) {
    h += '<div class="seq-events"><div class="seq-label">Sequence events (' + seqEvents.length + ')' + truncNote(extra.seqTruncated | 0) + ':</div>';
    seqEvents.forEach((sx, i) => {
      const s = extractEventSummary(sx);
      h += '<div class="seq-item"><div class="seq-item-head">Stage ' + (i + 1) + '</div>';
      if (s) {
        h += '<table class="alert-summary"><tbody>';
        if (s.event_id) h += '<tr><th>EventID</th><td>' + esc(s.event_id) + '</td></tr>';
        if (s.channel) h += '<tr><th>Channel</th><td>' + esc(s.channel) + '</td></tr>';
        if (s.computer) h += '<tr><th>Computer</th><td>' + esc(s.computer) + '</td></tr>';
        if (s.time_created) h += '<tr><th>TimeCreated</th><td>' + esc(s.time_created) + '</td></tr>';
        Object.keys(s.event_data).forEach(k => {
          h += '<tr><th>' + esc(k) + '</th><td>' + esc(s.event_data[k]) + '</td></tr>';
        });
        h += '</tbody></table>';
      }
      h += '<details><summary>Raw XML</summary><pre class="xml-raw">' + esc(prettyPrintXml(sx)) + '</pre></details>';
      h += '</div>';
    });
    h += '<div class="seq-label">Trigger event:</div></div>';
  }
  // Window events (threshold evidence): the events that filled the sliding
  // window. Same layout as sequence events, labeled "Event N" (a window has
  // no stages; it is an unordered set of contributing events).
  if (winEvents && winEvents.length > 0) {
    h += '<div class="seq-events"><div class="seq-label">Window events (' + winEvents.length + ')' + truncNote(extra.winTruncated | 0) + ':</div>';
    winEvents.forEach((sx, i) => {
      const s = extractEventSummary(sx);
      h += '<div class="seq-item"><div class="seq-item-head">Event ' + (i + 1) + '</div>';
      if (s) {
        h += '<table class="alert-summary"><tbody>';
        if (s.event_id) h += '<tr><th>EventID</th><td>' + esc(s.event_id) + '</td></tr>';
        if (s.channel) h += '<tr><th>Channel</th><td>' + esc(s.channel) + '</td></tr>';
        if (s.computer) h += '<tr><th>Computer</th><td>' + esc(s.computer) + '</td></tr>';
        if (s.time_created) h += '<tr><th>TimeCreated</th><td>' + esc(s.time_created) + '</td></tr>';
        Object.keys(s.event_data).forEach(k => {
          h += '<tr><th>' + esc(k) + '</th><td>' + esc(s.event_data[k]) + '</td></tr>';
        });
        h += '</tbody></table>';
      }
      h += '<details><summary>Raw XML</summary><pre class="xml-raw">' + esc(prettyPrintXml(sx)) + '</pre></details>';
      h += '</div>';
    });
    h += '<div class="seq-label">Trigger event:</div></div>';
  }
  if (xml) {
    const sum = extractEventSummary(xml);
    if (sum) {
      h += '<table class="alert-summary"><tbody>';
      if (sum.event_id) h += '<tr><th>EventID</th><td>' + esc(sum.event_id) + '</td></tr>';
      if (sum.channel) h += '<tr><th>Channel</th><td>' + esc(sum.channel) + '</td></tr>';
      if (sum.computer) h += '<tr><th>Computer</th><td>' + esc(sum.computer) + '</td></tr>';
      if (sum.time_created) h += '<tr><th>TimeCreated</th><td>' + esc(sum.time_created) + '</td></tr>';
      // Render every EventData field, not a truncated prefix: the detail row
      // is collapsed by default (toggle button), so showing all of them is
      // cheap, and the analyst needs the full event context when expanding.
      Object.keys(sum.event_data).forEach(k => {
        h += '<tr><th>' + esc(k) + '</th><td>' + esc(sum.event_data[k]) + '</td></tr>';
      });
      h += '</tbody></table>';
    } else {
      h += '<span class="muted">No parseable event summary.</span>';
    }
    h += '<details><summary>Raw XML</summary><pre class="xml-raw">' + esc(prettyPrintXml(xml)) + '</pre></details>';
  } else if ((!seqEvents || !seqEvents.length) && (!winEvents || !winEvents.length)) {
    h += '<span class="muted">No event data.</span>';
  }
  h += '</div>';
  return h;
}

// --- Alerts rendering (windowed + lazy detail) ---
// This view is built to stay light on a 5s auto-refresh:
//   - the list endpoint omits payloads (they embed full event XML, megabytes
//     per 200 rows); one page (50 rows) is built as a single string and
//     assigned to innerHTML once (`innerHTML +=` per row re-parses the whole
//     table on every row, an O(n²) cost);
//   - a detail row is fetched (GET /alerts/{id}) and rendered only when the
//     analyst expands it (a DOMParser pass per event), then cached so the
//     auto-refresh re-inserts it without a refetch and never collapses what
//     is being read;
//   - Newer/Older buttons page through history with `offset`, so thousands
//     of stored alerts never hit the DOM at once.
const ALERTS_PAGE_SIZE = 50;
let _alertsOffset = 0;             // current page start (rows skipped)
let _alertsHasOlder = false;       // whether an older page exists (PAGE+1 probe)
const _alertsExpanded = new Set();  // alert ids whose detail row is open
const _alertDetailCache = new Map(); // alert id -> rendered detail HTML (bounded)

async function loadAlerts() {
  // Build the query from the search box + sort dropdown. Debounced search
  // input (onAlertsSearchInput) calls this 300ms after the user stops typing.
  const q = (el('alerts-search') && el('alerts-search').value || '').trim();
  const sort = (el('alerts-sort') && el('alerts-sort').value) || 'recency';
  // Fetch one extra row to learn whether an older page exists; this avoids a
  // separate count query on every refresh.
  const rows = await api('/alerts?limit=' + (ALERTS_PAGE_SIZE + 1) + '&offset=' + _alertsOffset +
                         '&sort=' + encodeURIComponent(sort) +
                         (q ? '&q=' + encodeURIComponent(q) : ''));
  _alertsHasOlder = rows.length > ALERTS_PAGE_SIZE;
  const page = _alertsHasOlder ? rows.slice(0, ALERTS_PAGE_SIZE) : rows;
  // Single-pass render: build the whole page as one string, assign once.
  const parts = [];
  for (const a of page) {
    // Rule cell: show the rule's display name when known (the server JOINs
    // the rules table for rule_name), fall back to the raw rule_id. Clicking
    // jumps to the rule in the Rules tab (openRuleFromAlert).
    const ruleLabel = a.rule_name || a.rule_id;
    const ruleCell = `<a href="#" onclick="openRuleFromAlert(${jsArg(a.rule_id)});return false" title="Open this rule in the Rules tab" style="color:#93c5fd;text-decoration:none">${esc(ruleLabel)}</a>`;
    parts.push(`<tr id="alert-row-${a.id}"><td>${a.id}</td><td>${fmtTime(a.received_at)}</td><td>${esc(a.agent_id)}</td><td>${ruleCell}</td><td>${severityBadge(a.severity)}</td><td>${esc(a.message)}</td>` +
      `<td><button class="btn sm" onclick="toggleAlertRow(${a.id})" title="Show the triggering event">▾</button></td></tr>`);
    // Rows the analyst expanded are re-rendered from the detail cache so
    // auto-refresh never collapses them. Evicted cache entries are
    // backfilled below.
    if (_alertsExpanded.has(a.id)) {
      const html = _alertDetailCache.get(a.id) || '<span class="muted">Loading event…</span>';
      parts.push(`<tr id="alert-detail-${a.id}" class="alert-detail-row"><td colspan="7">${html}</td></tr>`);
    }
  }
  const tb = document.querySelector('#alerts-table tbody');
  tb.innerHTML = page.length
    ? parts.join('')
    : `<tr><td colspan="7" class="muted">${q ? 'No alerts match "' + esc(q) + '".' : 'No alerts yet.'}</td></tr>`;
  renderAlertsPager(page.length);
  // Backfill expanded rows whose cache entry was evicted (bounded cache).
  for (const a of page) {
    if (_alertsExpanded.has(a.id) && !_alertDetailCache.has(a.id)) fetchAlertDetail(a.id);
  }
}
function renderAlertsPager(shown) {
  const pager = document.getElementById('alerts-pager');
  if (!pager) return;
  const from = _alertsOffset + 1, to = _alertsOffset + shown;
  pager.innerHTML =
    `<button class="btn secondary sm" onclick="alertsPageNewer()" ${_alertsOffset === 0 ? 'disabled' : ''}>← Newer</button>` +
    `<span class="muted" style="font-size:12px">Showing ${shown ? from + '–' + to : '0'}${_alertsHasOlder ? '+' : ''}</span>` +
    `<button class="btn secondary sm" onclick="alertsPageOlder()" ${_alertsHasOlder ? '' : 'disabled'}>Older →</button>`;
}
function alertsPageOlder() { _alertsOffset += ALERTS_PAGE_SIZE; loadAlerts(); }
function alertsPageNewer() { _alertsOffset = Math.max(0, _alertsOffset - ALERTS_PAGE_SIZE); loadAlerts(); }
function onAlertsSortChange() { _alertsOffset = 0; loadAlerts(); }
// Fetch ONE alert's payload and render its detail dropdown. Called on
// first expand (toggleAlertRow) and to backfill expanded rows after a
// cache eviction. The cache is bounded (oldest entry dropped) so hours of
// clicking through alerts can't grow it without limit.
async function fetchAlertDetail(id) {
  try {
    const a = await api('/alerts/' + id);
    let xml = '', seqEvents = [], winEvents = [], extra = {};
    try {
      const p = a.payload ? JSON.parse(a.payload) : {};
      xml = p.event_xml || '';
      seqEvents = Array.isArray(p.sequence_events) ? p.sequence_events : [];
      winEvents = Array.isArray(p.window_events) ? p.window_events : [];
      extra = {
        seqTruncated: p.sequence_events_truncated | 0,
        winTruncated: p.window_events_truncated | 0,
        alsoMatched: Array.isArray(p.also_matched) ? p.also_matched : [],
        alertId: p.alert_id || '',
        ruleId: p.rule_id || a.rule_id || '',
      };
    } catch (e) {}
    const html = renderAlertDetail(xml, seqEvents, winEvents, extra);
    if (_alertDetailCache.size >= 100) {
      _alertDetailCache.delete(_alertDetailCache.keys().next().value);
    }
    _alertDetailCache.set(id, html);
    const row = document.getElementById('alert-detail-' + id);
    if (row && _alertsExpanded.has(id)) row.querySelector('td').innerHTML = html;
  } catch (e) { /* alert cleared while open; leave the placeholder */ }
}
function toggleAlertRow(id) {
  const existing = document.getElementById('alert-detail-' + id);
  if (existing) {
    const open = existing.style.display !== 'none';
    existing.style.display = open ? 'none' : 'table-row';
    if (open) _alertsExpanded.delete(id); else _alertsExpanded.add(id);
    return;
  }
  // First expand: create the detail row lazily under the alert's row and
  // fetch the payload on demand. The list endpoint strips payloads (they
  // embed full event XML), so nothing is parsed until the analyst asks.
  _alertsExpanded.add(id);
  const main = document.getElementById('alert-row-' + id);
  if (!main) return;
  const cached = _alertDetailCache.get(id);
  const tr = document.createElement('tr');
  tr.id = 'alert-detail-' + id;
  tr.className = 'alert-detail-row';
  tr.innerHTML = `<td colspan="7">${cached || '<span class="muted">Loading event…</span>'}</td>`;
  main.after(tr);
  if (!cached) fetchAlertDetail(id);
}

// Map a Sigma severity level to a colored badge. The server sorts alerts
// by severity (critical first), so the color reinforces the sort order and
// lets the analyst spot critical/high alerts at a glance.
function severityBadge(level) {
  const l = (level || '').toLowerCase();
  const colors = {
    critical:     '#ef4444',  // red
    high:         '#f97316',  // orange
    medium:       '#eab308',  // yellow
    low:          '#3b82f6',  // blue
    informational:'#94a3b8',  // gray
  };
  const c = colors[l] || '#64748b';  // unknown -> slate
  const label = l || 'unknown';
  return `<span class="sev-badge" style="background:${c};color:#fff;padding:2px 8px;border-radius:4px;font-size:11px;text-transform:capitalize;font-weight:600">${esc(label)}</span>`;
}

// Debounce the alerts search box: only re-fetch 300ms after the last
// keystroke so typing a long query doesn't fire a request per character.
// A new search always restarts from the first page.
let _alertsSearchTimer = null;
function onAlertsSearchInput() {
  if (_alertsSearchTimer) clearTimeout(_alertsSearchTimer);
  _alertsSearchTimer = setTimeout(() => { _alertsOffset = 0; loadAlerts(); }, 300);
}
// Jump from an alert's rule link to that rule in the Rules tab. The rule
// may live in any group, so fetch ALL groups' rules, find the hit, point
// the group filter at it, and open the editor. showTab('rules') fires its
// own async loadGroups().then(loadRules()); we await our own loads after
// it and re-assert the filter value in case the tab's load raced us.
async function openRuleFromAlert(ruleId) {
  let all = [];
  try { all = await api('/rules'); }  // no group_id = every group
  catch (e) { alert('Failed to load rules: ' + e.message); return; }
  const hit = all.find(r => r.rule_id === ruleId);
  if (!hit) { alert('Rule "' + ruleId + '" is not in any group (it may have been deleted or renamed).'); return; }
  if (_activeTab !== 'rules') showTab('rules');
  await loadGroups();
  const sel = el('rule-group-filter');
  if (sel) sel.value = String(hit.group_id);
  await loadRules();
  openRule(hit.rule_id, hit.group_id);
}
async function clearAlerts() {
  if (!confirm('Delete ALL stored alerts? This cannot be undone.')) return;
  try {
    const r = await fetch('/alerts', { method: 'DELETE' });
    const j = await r.json();
    _alertsOffset = 0;
    _alertsExpanded.clear();
    _alertDetailCache.clear();
    await loadAlerts();
    alert('Deleted ' + j.deleted + ' alert(s).');
  } catch (e) { alert('Clear failed: ' + e.message); }
}
// Reset the Metrics page: zero every agent's cumulative created/forwarded
// counters and delete all stored forwarded-log batches (alerts are kept;
// they're the detection record). Useful to start a clean measurement window
// after tuning rules. Admin-only (the endpoint enforces the role too).
async function resetMetrics() {
  if (!confirm('Reset metrics? This zeroes every agent\'s created/forwarded counters and deletes all stored forwarded logs (alerts are kept). This cannot be undone.')) return;
  try {
    const j = await api('/metrics/reset', { method: 'DELETE' });
    refreshMetricsView();
    alert('Metrics reset. Deleted ' + j.logs_deleted + ' forwarded log batch(es).');
  } catch (e) { alert('Reset failed: ' + e.message); }
}
// --- Metrics view (savings + event count graph + bytes graph, all on one page) ---
// ---- Metrics charts (Chart.js) ----
// Chart instances are kept in a map so we can update/destroy them across
// refreshes without leaking canvases.
const _metricsCharts = {};
// The currently active preset span (seconds) or null when a custom range is
// in use. Controls whether the To field auto-follows "now" on refresh.
let _metricsPresetSpan = 86400;
// Whether loadMetricsView has run once in this page session. The preset
// (which sets the From/To fields + refreshes charts) is only applied on the
// FIRST visit to the Metrics tab; subsequent visits keep whatever range the
// user last chose (custom or preset) instead of snapping back to 24h.
let _metricsRangeInit = false;

function loadMetricsView() {
  // First visit: default to the 24h preset (which sets the From/To fields
  // and refreshes the charts), then load the savings + agent filter.
  // Later visits: keep the user's current range and just refresh.
  if (!_metricsRangeInit) {
    _metricsRangeInit = true;
    applyMetricsPreset(el('metrics-presets').querySelector('.metrics-preset[data-span="86400"]'), 86400);
    loadMetricsSavings();
    loadMetricsAgentFilter();
  } else {
    refreshMetricsView();
  }
}
function refreshMetricsView() {
  // When a preset is active, slide the window so "To" follows "now" and
  // "From" stays span seconds behind. A custom range (set via the date
  // pickers) is frozen: the operator pinned it, so auto-refresh must not
  // move it.
  if (_metricsPresetSpan && _metricsPresetSpan > 0) {
    const now = new Date();
    el('metrics-date-from').value = fmtLocal(new Date(now.getTime() - _metricsPresetSpan * 1000));
    el('metrics-date-to').value = fmtLocal(now);
  }
  loadMetricsSavings();
  refreshMetricsCharts();
  // The agent dropdown is refetched at most once a minute (see
  // loadMetricsAgentFilter); the agent roster changes rarely, so hitting
  // /agents on every 5s refresh would be wasted requests.
  loadMetricsAgentFilter();
}
function refreshMetricsCharts() {
  // One /metrics/stats fetch feeds BOTH the events and bytes charts (they
  // read the same data; fetching twice would double the server load on
  // every refresh). The alerts chart uses a separate endpoint.
  loadMetricsStatsGraphs();
  loadMetricsAlertsGraph();
}
function applyMetricsPreset(btn, spanSeconds) {
  // Highlight the clicked preset and set the From/To fields to [now-span, now].
  // spanSeconds=0 means "All": from 0 (epoch) to now, which the server treats
  // as "no lower bound".
  document.querySelectorAll('#metrics-presets .metrics-preset').forEach(b => b.classList.remove('active'));
  if (btn) btn.classList.add('active');
  _metricsPresetSpan = spanSeconds;
  const now = new Date();
  if (spanSeconds > 0) {
    el('metrics-date-from').value = fmtLocal(new Date(now.getTime() - spanSeconds * 1000));
    el('metrics-date-to').value = fmtLocal(now);
  } else {
    // "All": leave From blank (server defaults to end-1h if start=0, but we
    // want everything; set To to now and From to a very early date).
    el('metrics-date-from').value = '2000-01-01 00:00';
    el('metrics-date-to').value = fmtLocal(now);
  }
  el('metrics-date-error').style.display = 'none';
  refreshMetricsCharts();
}
let _metricsAgentsFetchedAt = 0;  // epoch ms of the last /agents fetch
async function loadMetricsAgentFilter() {
  // The agent roster changes rarely, so the dropdown is refetched at most
  // once every 60s instead of on every 5s auto-refresh. The first call
  // (tab entry) always fetches.
  const now = Date.now();
  if (_metricsAgentsFetchedAt && now - _metricsAgentsFetchedAt < 60000) return;
  _metricsAgentsFetchedAt = now;
  let agents;
  try { agents = await api('/agents'); }
  catch (e) { return; }
  const sel = el('metrics-agent-filter');
  const cur = sel.value;
  sel.innerHTML = '<option value="">All agents</option>' +
    agents.map(a => `<option value="${esc(a.agent_id)}">${esc(a.hostname || a.agent_id)}</option>`).join('');
  if (cur) sel.value = cur;
}
let _lastSavingsJson = '';  // last rendered savings payload (skip unchanged)
async function loadMetricsSavings() {
  let data;
  try { data = await api('/metrics/savings'); }
  catch (e) { return; }
  // Skip the DOM rebuild when the numbers haven't moved; the savings view
  // changes only when agents poll new counters, so most 5s refreshes would
  // otherwise re-render identical HTML for nothing.
  const sig = JSON.stringify(data);
  if (sig === _lastSavingsJson) return;
  _lastSavingsJson = sig;
  // Summary cards: savings = (1 - bytes sent / bytes created) * 100
  const bfwd = data.total_bytes_forwarded, bcre = data.total_bytes_created;
  const pct = bcre > 0 ? ((1 - bfwd / bcre) * 100).toFixed(1) : '0.0';
  el('metrics-savings-summary').innerHTML =
    `<div style="text-align:center"><div style="font-size:28px;font-weight:bold;color:#3b82f6">${formatBytes(bfwd)} / ${formatBytes(bcre)}</div><div class="muted" style="font-size:12px">Sent / Created (bytes)</div></div>` +
    `<div style="text-align:center"><div style="font-size:28px;font-weight:bold;color:${pct > 50 ? '#10b981' : '#f59e0b'}">${pct}%</div><div class="muted" style="font-size:12px">Savings</div></div>` +
    `<div style="text-align:center"><div style="font-size:20px;font-weight:bold">${(data.total_events_forwarded||0).toLocaleString()} / ${(data.total_events_created||0).toLocaleString()}</div><div class="muted" style="font-size:12px">Sent / Created (events)</div></div>`;
  // Per-agent table, single-pass render: the rows are joined into one
  // string and assigned once (`tb.innerHTML +=` per row is an O(n²)
  // re-parse that visibly janks the tab with many agents).
  const parts = [];
  if (!data.agents.length) {
    parts.push('<tr><td colspan="8" class="muted">No agents registered yet.</td></tr>');
  } else {
    for (const a of data.agents) {
      const bc = a.bytes_created || 0, bf = a.bytes_forwarded || 0;
      // % forwarded = bytes_forwarded / bytes_created * 100 (complement of savings)
      const fwdPct = bc > 0 ? (bf / bc * 100) : 0;
      const fwdPctStr = fwdPct.toFixed(1);
      // Low % forwarded = good (green); high = poor (red/orange)
      const fwdColor = fwdPct < 25 ? '#10b981' : fwdPct < 75 ? '#f59e0b' : '#ef4444';
      const fwdBar = `<div style="background:#1e293b;border-radius:4px;height:8px;width:80px;overflow:hidden;display:inline-block;vertical-align:middle"><div style="background:${fwdColor};height:100%;width:${Math.min(fwdPct,100)}%"></div></div> <span style="font-size:12px">${fwdPctStr}%</span>`;
      // Savings = (1 - bytes_forwarded / bytes_created) * 100
      const savPct = bc > 0 ? ((1 - bf / bc) * 100) : 0;
      const savPctStr = savPct.toFixed(1);
      const savColor = savPct > 50 ? '#10b981' : savPct > 0 ? '#f59e0b' : '#ef4444';
      const savBar = `<div style="background:#1e293b;border-radius:4px;height:8px;width:80px;overflow:hidden;display:inline-block;vertical-align:middle"><div style="background:${savColor};height:100%;width:${Math.min(savPct,100)}%"></div></div> <span style="font-size:12px">${savPctStr}%</span>`;
      parts.push(`<tr><td>${esc(a.agent_id)}</td><td>${esc(a.hostname)||'-'}</td><td>${(a.events_created||0).toLocaleString()}</td><td>${(a.events_forwarded||0).toLocaleString()}</td><td>${fwdBar}</td><td>${formatBytes(bc)}</td><td>${formatBytes(bf)}</td><td>${savBar}</td></tr>`);
    }
  }
  document.querySelector('#metrics-savings-table tbody').innerHTML = parts.join('');
}
// Fetch /metrics/stats ONCE and feed both the events and bytes charts.
// They read the same buckets (event_count and bytes), so a single request
// halves the refresh cost.
async function loadMetricsStatsGraphs() {
  const range = validateMetricsDateRange();
  if (!range) return;
  const span = range.end - range.start;
  const bucket = autoBucketSize(span);
  const agent = el('metrics-agent-filter').value;
  let data;
  try { data = await api(`/metrics/stats?start=${range.start}&end=${range.end}&bucket=${bucket}&agent_id=${encodeURIComponent(agent)}`); }
  catch (e) {
    el('metrics-count-total').textContent = 'Error: ' + e.message;
    el('metrics-bytes-total').textContent = 'Error: ' + e.message;
    return;
  }
  el('metrics-count-total').textContent = `${data.total_events.toLocaleString()} events · ${formatBytes(data.total_bytes)} · ${bucket}s buckets`;
  el('metrics-bytes-total').textContent = `${formatBytes(data.total_bytes)} · ${data.total_events.toLocaleString()} events · ${bucket}s buckets`;
  renderMetricsAreaChart('count', 'metrics-count-canvas', data.buckets, 'event_count', '#3b82f6', 'Events', false);
  renderMetricsAreaChart('bytes', 'metrics-bytes-canvas', data.buckets, 'bytes', '#10b981', 'Bytes', true);
}
async function loadMetricsAlertsGraph() {
  const range = validateMetricsDateRange();
  if (!range) return;
  const span = range.end - range.start;
  const bucket = autoBucketSize(span);
  const agent = el('metrics-agent-filter').value;
  let data;
  try { data = await api(`/metrics/alerts?start=${range.start}&end=${range.end}&bucket=${bucket}&agent_id=${encodeURIComponent(agent)}`); }
  catch (e) { el('metrics-alerts-total').textContent = 'Error: ' + e.message; return; }
  el('metrics-alerts-total').textContent = `${data.total_alerts.toLocaleString()} alerts · ${bucket}s buckets`;
  renderMetricsAreaChart('alerts', 'metrics-alerts-canvas', data.buckets, 'alert_count', '#f59e0b', 'Alerts', false);
}
// Shared Chart.js area-chart renderer. `chartKey` is the key into the
// _metricsCharts map so we can destroy+recreate on each refresh. `isBytes`
// switches the Y-axis tick formatter to formatBytes.
function renderMetricsAreaChart(chartKey, canvasId, buckets, valueKey, color, label, isBytes) {
  if (typeof Chart === 'undefined') {
    el(canvasId).parentElement.innerHTML = '<div class="muted" style="text-align:center;padding:40px">Chart.js failed to load (check /static/chart.umd.min.js).</div>';
    return;
  }
  // Compute the new labels/values first, then update in place when a chart
  // instance already exists. Destroying + recreating on every 5s refresh
  // replayed the 600ms grow animation and killed any active hover/tooltip;
  // updating data + update('none') is non-destructive (no animation, hover
  // state preserved). Only the FIRST render creates a new Chart.
  const labels = buckets.map(b => new Date(b.bucket_ts * 1000).toLocaleString());
  const values = buckets.map(b => b[valueKey] || 0);
  const existing = _metricsCharts[chartKey];
  if (existing) {
    existing.data.labels = labels;
    existing.data.datasets[0].data = values;
    existing.update('none');
    return;
  }
  const canvas = el(canvasId);
  if (!canvas) return;
  const ctx = canvas.getContext('2d');
  // Vertical gradient fill under the line for a polished area look.
  const grad = ctx.createLinearGradient(0, 0, 0, 280);
  grad.addColorStop(0, color + '66');
  grad.addColorStop(1, color + '08');
  const chart = new Chart(ctx, {
    type: 'line',
    data: {
      labels: labels,
      datasets: [{
        label: label,
        data: values,
        borderColor: color,
        backgroundColor: grad,
        borderWidth: 2,
        fill: true,
        tension: 0.35,
        pointRadius: 0,           // hide points; hover reveals them
        pointHoverRadius: 5,
        pointHoverBackgroundColor: color,
        pointHoverBorderColor: '#e2e8f0',
        pointHoverBorderWidth: 2,
      }],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      animation: { duration: 600, easing: 'easeOutQuart' },
      interaction: { mode: 'index', intersect: false },   // crosshair-style hover
      plugins: {
        legend: { display: false },
        tooltip: {
          backgroundColor: '#1e293b',
          borderColor: '#334155',
          borderWidth: 1,
          titleColor: '#e2e8f0',
          bodyColor: '#cbd5e1',
          padding: 10,
          cornerRadius: 6,
          displayColors: false,
          callbacks: {
            label: function(ctx) {
              const v = ctx.parsed.y;
              return label + ': ' + (isBytes ? formatBytes(v) : v.toLocaleString());
            },
          },
        },
      },
      scales: {
        x: {
          ticks: {
            color: '#64748b',
            maxRotation: 0,
            autoSkip: true,
            maxTicksLimit: 8,
            font: { size: 11 },
          },
          grid: { color: '#1e293b', drawBorder: false },
        },
        y: {
          beginAtZero: true,
          ticks: {
            color: '#64748b',
            font: { size: 11 },
            callback: function(v) { return isBytes ? formatBytes(v) : (v >= 1000 ? (v/1000).toFixed(1)+'k' : v); },
          },
          grid: { color: '#1e293b', drawBorder: false },
        },
      },
    },
  });
  _metricsCharts[chartKey] = chart;
}
function validateMetricsDateRange() {
  const fromVal = el('metrics-date-from').value;
  const toVal = el('metrics-date-to').value;
  const errEl = el('metrics-date-error');
  if (!fromVal || !toVal) { errEl.style.display = 'none'; return null; }
  const fromD = parseLocal(fromVal), toD = parseLocal(toVal);
  if (!fromD || !toD) { errEl.textContent = 'Invalid date format.'; errEl.style.display = ''; return null; }
  const from = fromD.getTime() / 1000;
  const to = toD.getTime() / 1000;
  if (from > to) {
    errEl.textContent = 'Start date must be before end date.';
    errEl.style.display = '';
    return null;
  }
  errEl.style.display = 'none';
  return { start: from, end: to };
}
// ---- Custom datetime picker ("Now" button lives inside the calendar) ----
let _dtState = null; // { targetId, view: Date, sel: Date|null }
function pad2(n) { return String(n).padStart(2, '0'); }
function fmtLocal(d) { return d.getFullYear() + '-' + pad2(d.getMonth()+1) + '-' + pad2(d.getDate()) + ' ' + pad2(d.getHours()) + ':' + pad2(d.getMinutes()); }
function parseLocal(s) { // 'YYYY-MM-DD HH:MM' -> Date (local)
  const m = /^(\d{4})-(\d{2})-(\d{2}) (\d{2}):(\d{2})$/.exec(s||'');
  if (!m) return null;
  return new Date(+m[1], +m[2]-1, +m[3], +m[4], +m[5]);
}
function closeDtPicker() {
  const p = document.getElementById('dt-pop'); if (p) p.remove();
  _dtState = null;
}
function openDtPicker(targetId) {
  closeDtPicker();
  const inp = el(targetId);
  const sel = parseLocal(inp.value) || new Date();
  _dtState = { targetId, view: new Date(sel.getFullYear(), sel.getMonth(), 1), sel };
  const pop = document.createElement('div');
  pop.id = 'dt-pop'; pop.className = 'dt-pop';
  // Position below the input.
  const r = inp.getBoundingClientRect();
  pop.style.left = r.left + 'px';
  pop.style.top = (r.bottom + 4) + 'px';
  document.body.appendChild(pop);
  // Stop clicks inside the picker from bubbling to the document-level
  // outside-click handler. Without this, re-rendering the picker (e.g. when
  // the Now button or a day is clicked) detaches the click target from the
  // pop, so pop.contains(target) returns false and the handler immediately
  // closes the picker, making the Now button appear to do nothing.
  pop.addEventListener('click', e => e.stopPropagation());
  renderDtPicker();
}
function renderDtPicker() {
  if (!_dtState) return;
  const pop = document.getElementById('dt-pop'); if (!pop) return;
  const v = _dtState.view, sel = _dtState.sel;
  const months = ['January','February','March','April','May','June','July','August','September','October','November','December'];
  const dows = ['Mo','Tu','We','Th','Fr','Sa','Su'];
  const first = new Date(v.getFullYear(), v.getMonth(), 1);
  const startDow = (first.getDay() + 6) % 7; // Monday-first
  const daysInMonth = new Date(v.getFullYear(), v.getMonth()+1, 0).getDate();
  const prevDays = new Date(v.getFullYear(), v.getMonth(), 0).getDate();
  const today = new Date();
  let html = '<div class="dt-pop-head"><button type="button" onclick="dtShiftMonth(-1)" title="Previous month">‹</button>';
  html += '<span class="dt-label">' + months[v.getMonth()] + ' ' + v.getFullYear() + '</span>';
  html += '<button type="button" onclick="dtShiftMonth(1)" title="Next month">›</button></div>';
  html += '<div class="dt-pop-grid">';
  dows.forEach(d => html += '<div class="dt-dow">' + d + '</div>');
  for (let i = 0; i < startDow; i++) {
    const d = prevDays - startDow + i + 1;
    html += '<div class="dt-day other">' + d + '</div>';
  }
  for (let d = 1; d <= daysInMonth; d++) {
    const cd = new Date(v.getFullYear(), v.getMonth(), d);
    let cls = 'dt-day';
    if (cd.toDateString() === today.toDateString()) cls += ' today';
    if (sel && cd.toDateString() === sel.toDateString()) cls += ' sel';
    html += '<div class="' + cls + '" onclick="dtPickDay(' + d + ')">' + d + '</div>';
  }
  const tail = (7 - ((startDow + daysInMonth) % 7)) % 7;
  for (let d = 1; d <= tail; d++) html += '<div class="dt-day other">' + d + '</div>';
  html += '</div>';
  html += '<div class="dt-pop-time">Time <input type="text" id="dt-hour" value="' + pad2(sel ? sel.getHours() : 0) + '" maxlength="2" oninput="dtSetTime()" />:<input type="text" id="dt-min" value="' + pad2(sel ? sel.getMinutes() : 0) + '" maxlength="2" oninput="dtSetTime()" /></div>';
  html += '<div class="dt-pop-actions">';
  html += '<button type="button" class="btn secondary sm" onclick="dtNow()">Now</button>';
  html += '<button type="button" class="btn sm" onclick="dtApply()">Apply</button>';
  html += '</div>';
  pop.innerHTML = html;
}
function dtShiftMonth(delta) {
  if (!_dtState) return;
  _dtState.view = new Date(_dtState.view.getFullYear(), _dtState.view.getMonth() + delta, 1);
  renderDtPicker();
}
function dtPickDay(d) {
  if (!_dtState) return;
  const v = _dtState.view;
  const h = _dtState.sel ? _dtState.sel.getHours() : 0, m = _dtState.sel ? _dtState.sel.getMinutes() : 0;
  _dtState.sel = new Date(v.getFullYear(), v.getMonth(), d, h, m);
  renderDtPicker();
}
function dtSetTime() {
  if (!_dtState || !_dtState.sel) return;
  const h = parseInt(el('dt-hour').value, 10) || 0;
  const m = parseInt(el('dt-min').value, 10) || 0;
  _dtState.sel.setHours(Math.min(23, Math.max(0, h)), Math.min(59, Math.max(0, m)));
}
function dtNow() {
  // Set the picker to the current local time but do NOT apply; the user
  // must click Apply to confirm, just like picking a day or editing the time.
  if (!_dtState) return;
  _dtState.sel = new Date();
  _dtState.view = new Date(_dtState.sel.getFullYear(), _dtState.sel.getMonth(), 1);
  renderDtPicker();
}
function dtApply() {
  if (!_dtState || !_dtState.sel) { closeDtPicker(); return; }
  // Capture the target BEFORE closeDtPicker nulls _dtState.
  const targetId = _dtState.targetId;
  el(targetId).value = fmtLocal(_dtState.sel);
  closeDtPicker();
  // Dispatch on which control the picker was attached to. The Metrics tab
  // has its own date range; applying a custom date there must refresh the
  // metrics charts (and freeze the sliding preset window, since the operator
  // chose a fixed range). The Logs tab has no date controls, so nothing
  // else to do.
  if (targetId.indexOf('metrics-date') === 0) {
    _metricsPresetSpan = null;  // custom range: stop auto-sliding
    document.querySelectorAll('#metrics-presets .metrics-preset').forEach(b => b.classList.remove('active'));
    refreshMetricsCharts();
  }
}
// Close the picker when clicking outside of it or its input.
document.addEventListener('click', (e) => {
  if (!_dtState) return;
  const pop = document.getElementById('dt-pop');
  const t = e.target;
  if (pop && pop.contains(t)) return;
  if (t && t.classList && t.classList.contains('dt-input')) return;
  closeDtPicker();
});
// Escape closes the date picker or whichever modal is open.
document.addEventListener('keydown', (e) => {
  if (e.key !== 'Escape') return;
  if (_dtState) { closeDtPicker(); return; }
  for (const m of document.querySelectorAll('.modal-overlay')) {
    if (m.style.display !== 'none') { m.style.display = 'none'; return; }
  }
});
function refreshLogsView() {
  loadLogs();
}
// Called by showTab('logs') on tab activation / browser refresh restore.
// The Logs page has no date controls; just load the list + file size + the
// max-size setting input.
function loadLogsView() {
  refreshLogsView();
  loadLogsSettings();
}
async function loadLogs() {
  // Single-pass render (rows joined into one string and assigned once;
  // `tb.innerHTML +=` per row is an O(n²) re-parse) and the server defaults
  // to the newest 40 batches; older batches' events live on in the
  // logs.txt text file (their DB payloads are pruned), so the page stays
  // light no matter how much has been forwarded.
  const rows = await api('/logs');
  const tb = document.querySelector('#logs-table tbody');
  loadLogsSize();
  if (!rows.length) { tb.innerHTML = '<tr><td colspan="5" class="muted">No forwarded logs yet.</td></tr>'; return; }
  const parts = [];
  for (const l of rows) {
    const rid = l.rule_id || '';
    const isCollect = rid === '__collect__';
    const ruleCell = isCollect ? `<span class="badge info" title="On-demand collection">collect</span>` : esc(rid);
    // The fire id links this batch to the alert that produced it (same value
    // in the alert's detail and on the events in the SIEM).
    const alertCell = l.alert_id ? `<code title="Search this id in the SIEM or the alert detail">${esc(l.alert_id)}</code>` : '<span class="muted">-</span>';
    parts.push(`<tr><td>${l.id}</td><td>${esc(l.agent_id)}</td><td>${ruleCell}</td><td>${alertCell}</td><td>${l.event_count}</td></tr>`);
  }
  tb.innerHTML = parts.join('');
}
async function loadLogsSize() {
  try {
    const r = await fetch('/logs/size');
    const j = await r.json();
    const mb = (j.bytes / 1048576);
    const txt = j.bytes === 0 ? '0 MB (empty)' : (mb < 0.01 ? (j.bytes + ' B') : (mb.toFixed(2) + ' MB'));
    const el2 = el('logs-file-size'); if (el2) el2.textContent = txt;
  } catch (e) { /* ignore */ }
}
// Load the max logs.txt size setting into the input on the Logs tab.
async function loadLogsSettings() {
  try {
    const j = await api('/settings');
    const inp = el('logs-max-size');
    if (inp && typeof j.max_logs_text_mb === 'number') inp.value = j.max_logs_text_mb;
  } catch (e) { /* ignore */ }
}
// Save the max logs.txt size (MB). 0 = unlimited. The server enforces the
// cap by trimming the OLDEST lines from logs.txt after each append.
async function saveLogsMaxSize() {
  const inp = el('logs-max-size');
  if (!inp) return;
  const v = parseInt(inp.value, 10);
  if (isNaN(v) || v < 0 || v > 10240) { alert('Max size must be between 0 (unlimited) and 10240 MB.'); return; }
  try {
    await api('/settings', { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ max_logs_text_mb: v }) });
    loadLogsSize();
    alert('Saved. logs.txt is capped at ' + (v === 0 ? 'unlimited' : v + ' MB') + '.');
  } catch (e) { alert('Save failed: ' + e.message); }
}
function autoBucketSize(spanSeconds) {
  // Choose a bucket size that yields ~60-120 buckets for readability.
  // Minimum 1 second.
  if (spanSeconds <= 120) return 1;
  if (spanSeconds <= 600) return 5;
  if (spanSeconds <= 3600) return 30;
  if (spanSeconds <= 21600) return 120;
  if (spanSeconds <= 86400) return 300;
  if (spanSeconds <= 604800) return 1800;
  return 3600;
}
function formatBytes(b) {
  if (!b) return '0 B';
  if (b < 1024) return b + ' B';
  if (b < 1048576) return (b / 1024).toFixed(1) + ' KB';
  if (b < 1073741824) return (b / 1048576).toFixed(2) + ' MB';
  return (b / 1073741824).toFixed(2) + ' GB';
}
async function clearLogs() {
  if (!confirm('Delete ALL stored logs and truncate the text file? This cannot be undone.')) return;
  try {
    const r = await fetch('/logs', { method: 'DELETE' });
    const j = await r.json();
    refreshLogsView();
    alert('Deleted ' + j.deleted + ' log(s).');
  } catch (e) { alert('Clear failed: ' + e.message); }
}

// --- Add New Agent (offline install) ---
async function openAddAgent() {
  // Populate the group dropdown from the current groups list.
  if (!groups.length) { await loadGroups(); }
  const sel = el('add-agent-group');
  sel.innerHTML = groups.map(g => `<option value="${esc(g.name)}">${esc(g.name)}</option>`).join('');
  el('add-agent-script').value = '';
  el('add-agent-copy').disabled = true;
  el('add-agent-download').disabled = true;
  el('cleanup-script').value = '';
  el('cleanup-copy').disabled = true;
  el('cleanup-download').disabled = true;
  addAgentOsShown = selectedInstallOs();
  toggleInstallMode();
  await checkAgentBinary();
  el('add-agent-modal').style.display = 'flex';
  // The cleanup script is static, so populate it immediately so the operator
  // can copy it without an extra Generate click.
  loadCleanupScript();
}
function closeAddAgent() { el('add-agent-modal').style.display = 'none'; }
// The OS the modal currently shows; switching clears the generated script
// and reloads the binary status and cleanup script for the other OS.
let addAgentOsShown = null;
function selectedInstallOs() {
  return el('add-agent-os-linux').checked ? 'linux' : 'windows';
}
function toggleInstallMode() {
  const os = selectedInstallOs();
  const linux = os === 'linux';
  el('add-agent-windows-account').style.display = linux ? 'none' : '';
  el('add-agent-linux-account').style.display = linux ? '' : 'none';
  // Show/hide the DOMAIN\username fields based on the selected radio.
  const domain = el('add-agent-mode-domain').checked;
  el('add-agent-domain-fields').style.display = domain ? '' : 'none';
  const existing = el('add-agent-linux-mode-existing').checked;
  el('add-agent-linux-user-fields').style.display = existing ? '' : 'none';
  const ext = linux ? '.sh' : '.ps1';
  el('add-agent-download').textContent = 'Download ' + ext;
  el('cleanup-download').textContent = 'Download ' + ext;
  el('add-agent-script').placeholder = 'Click Generate to build the install script (' + ext + ')...';
  if (addAgentOsShown !== os) {
    addAgentOsShown = os;
    el('add-agent-script').value = '';
    el('add-agent-copy').disabled = true;
    el('add-agent-download').disabled = true;
    checkAgentBinary();
    loadCleanupScript();
  }
}
function selectedInstallMode() {
  if (selectedInstallOs() === 'linux') {
    return el('add-agent-linux-mode-existing').checked ? 'existing' : 'local';
  }
  return el('add-agent-mode-domain').checked ? 'domain' : 'local';
}
async function checkAgentBinary() {
  try {
    const os = selectedInstallOs();
    const r = await fetch('/agent/binary/status?os=' + os + '&_=' + Date.now());
    const j = await r.json();
    const warn = el('add-agent-binary-warn');
    if (j.available) {
      warn.style.display = 'none';
    } else {
      warn.style.display = '';
      warn.textContent = 'No ' + (os === 'linux' ? 'Linux' : 'Windows') + ' agent binary on the server. Rebuild the Docker image with server/agent/' + j.name + ' staged and redeploy before generating the script.';
    }
  } catch (e) { /* ignore */ }
}
async function generateInstallScript() {
  const group = el('add-agent-group').value;
  if (!group) { alert('Select a group first.'); return; }
  const os = selectedInstallOs();
  const mode = selectedInstallMode();
  const body = { group: group, os: os, account_mode: mode };
  if (mode === 'domain') {
    const domain = el('add-agent-domain').value.trim();
    const username = el('add-agent-username').value.trim();
    if (!domain || !username) { alert('Enter both the domain and the username of the service account.'); return; }
    body.domain = domain;
    body.username = username;
  }
  if (os === 'linux') {
    body.audit_execve = el('add-agent-audit-execve').checked;
    if (mode === 'existing') {
      const username = el('add-agent-linux-user').value.trim();
      if (!username) { alert('Enter the username of the existing account.'); return; }
      body.username = username;
    }
  }
  try {
    const r = await fetch('/install-script', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body)
    });
    if (!r.ok) { const t = await r.text(); alert('Failed: ' + t); return; }
    const text = await r.text();
    el('add-agent-script').value = text;
    el('add-agent-copy').disabled = false;
    el('add-agent-download').disabled = false;
  } catch (e) { alert('Request failed: ' + e.message); }
}
function downloadInstallScript() {
  // Save the generated script as a .ps1 file. The script is multi-line, so
  // downloading it as a file is more reliable than copy-paste (no clipboard
  // mangling, no terminal reflow issues).
  const text = el('add-agent-script').value;
  if (!text) return;
  const blob = new Blob([text], { type: 'text/plain' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = selectedInstallOs() === 'linux' ? 'install-elf-agent.sh' : 'install-elf-agent.ps1';
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(a.href);
}
function copyInstallScript() {
  const text = el('add-agent-script').value;
  // Try the modern Clipboard API first (requires a secure context: https
  // or localhost). The server runs on plain HTTP, so this may be undefined.
  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(text).then(flashCopyBtn).catch(() => fallbackCopy(text));
  } else {
    fallbackCopy(text);
  }
}
function fallbackCopy(text) {
  // Use a temporary non-readonly textarea so execCommand('copy') works on
  // plain HTTP. The readonly install-script textarea can't be focused/copied
  // in some browsers.
  const tmp = document.createElement('textarea');
  tmp.value = text;
  tmp.style.position = 'fixed';
  tmp.style.left = '-9999px';
  document.body.appendChild(tmp);
  tmp.focus();
  tmp.select();
  tmp.setSelectionRange(0, text.length);
  try { document.execCommand('copy'); } catch (e) {}
  document.body.removeChild(tmp);
  flashCopyBtn();
}
function flashCopyBtn() {
  const btn = el('add-agent-copy');
  const orig = btn.textContent;
  btn.textContent = 'Copied!';
  setTimeout(() => { btn.textContent = orig; }, 1500);
}
// --- Cleanup script (troubleshooting) ---
// The cleanup script is static (no server params), so it's auto-populated
// when the Add Agent modal opens; no Generate button needed.
async function loadCleanupScript() {
  try {
    const r = await fetch('/cleanup-script?os=' + selectedInstallOs());
    if (!r.ok) { el('cleanup-script').value = 'Failed to load cleanup script.'; return; }
    const text = await r.text();
    el('cleanup-script').value = text;
    el('cleanup-copy').disabled = false;
    el('cleanup-download').disabled = false;
  } catch (e) { el('cleanup-script').value = 'Request failed: ' + e.message; }
}
function copyCleanupScript() {
  const text = el('cleanup-script').value;
  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(text).then(flashCleanupBtn).catch(() => fallbackCopyCleanup(text));
  } else {
    fallbackCopyCleanup(text);
  }
}
function fallbackCopyCleanup(text) {
  const tmp = document.createElement('textarea');
  tmp.value = text;
  tmp.style.position = 'fixed';
  tmp.style.left = '-9999px';
  document.body.appendChild(tmp);
  tmp.focus();
  tmp.select();
  tmp.setSelectionRange(0, text.length);
  try { document.execCommand('copy'); } catch (e) {}
  document.body.removeChild(tmp);
  flashCleanupBtn();
}
function flashCleanupBtn() {
  const btn = el('cleanup-copy');
  const orig = btn.textContent;
  btn.textContent = 'Copied!';
  setTimeout(() => { btn.textContent = orig; }, 1500);
}
function downloadCleanupScript() {
  const text = el('cleanup-script').value;
  if (!text) return;
  const blob = new Blob([text], { type: 'text/plain' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = selectedInstallOs() === 'linux' ? 'cleanup-elf-agent.sh' : 'cleanup-elf-agent.ps1';
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(a.href);
}

// Restore the tab the user was on (so a browser refresh doesn't jump back
// to Agents). Defaults to 'agents' on a fresh session.
(function() {
  let t = 'agents';
  try { t = sessionStorage.getItem('elf-tab') || 'agents'; } catch (e) {}
  if (!['agents','groups','rules','lists','alerts','metrics','logs','users','audit','docs'].includes(t)) t = 'agents';
  // Restore the global auto-refresh setting (persists across browser refresh).
  let ar = false;
  try { ar = localStorage.getItem('elf-autorefresh') === '1'; } catch (e) {}
  const cb = el('global-autorefresh');
  if (cb) cb.checked = ar;
  setAutoRefresh(ar);
  // Check auth first. If authenticated, showTab loads the data. If not,
  // the login overlay is shown and showTab is deferred until login.
  checkAuth().then(() => {
    if (_currentUser) showTab(t);
  });
})();
</script>
</body>
</html>"""
