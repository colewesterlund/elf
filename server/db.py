"""SQLite-backed storage for the ELF management server.

Four tables:
  agents   - one row per registered agent (hostname + group membership).
  groups   - named groups of agents; each group has its own rules + settings.
  rules    - detection rules (YAML body stored as text), scoped to a group.
  lists    - reusable value lists (newline-separated text), shared globally
             across all groups. Rules reference a list with `@@name`; the
             agent expands the reference at load time.

The server is the source of truth. Agents pull their effective ruleset and
config from here on every poll. An agent belongs to exactly one group; the
group's rules and settings are what the agent receives. Lists are global so
a single list (e.g. "sensitive_processes") can be reused by rules in any
group and managed centrally.
"""

import sqlite3
import threading
import time
import os
import hashlib
import secrets
import json
from contextlib import contextmanager
from typing import Any

DB_PATH = "elf.db"

_lock = threading.Lock()


def _hash_password(password: str) -> str:
    """Bcrypt-hash a password. Returns the hash string (includes salt).
    bcrypt reads at most 72 bytes; longer input raises rather than being
    silently truncated (the request models reject it first)."""
    import bcrypt
    raw = password.encode("utf-8")
    if len(raw) > 72:
        raise ValueError("password longer than 72 bytes")
    return bcrypt.hashpw(raw, bcrypt.gensalt()).decode("utf-8")


def _verify_password(password: str, password_hash: str) -> bool:
    """Verify a password against a stored bcrypt hash."""
    import bcrypt
    raw = password.encode("utf-8")
    if len(raw) > 72:
        return False   # cannot be a stored password; bcrypt would raise
    try:
        return bcrypt.checkpw(raw, password_hash.encode("utf-8"))
    except (ValueError, TypeError):
        return False


def _hash_token(token: str) -> str:
    """SHA-256 hex digest of a raw agent token. We store only the hash so a
    DB leak doesn't expose enrollment tokens."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


@contextmanager
def get_conn(db_path: str = DB_PATH) -> Any:
    """Thread-safe connection context manager. SQLite connections are not
    shareable across threads by default, so we open one per call."""
    conn = sqlite3.connect(db_path, timeout=10.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init_db(db_path: str = DB_PATH) -> None:
    """Create tables if they don't exist and seed defaults."""
    with _lock, get_conn(db_path) as conn:
        # Write-ahead logging: readers (agent polls, the UI) do not block
        # behind a writer, which matters when a 3,000-rule import commits as
        # one transaction. The mode is persistent in the database file, so
        # setting it here on every start is idempotent. synchronous=NORMAL
        # is the documented WAL pairing (durable across process crashes,
        # not across power loss mid-checkpoint, acceptable for this data).
        try:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=NORMAL")
        except sqlite3.DatabaseError:
            pass  # e.g. a read-only or in-memory DB; journaling is not critical
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS groups (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                name          TEXT NOT NULL UNIQUE,
                description   TEXT DEFAULT '',
                retention_seconds      INTEGER DEFAULT 30,
                poll_interval_seconds  INTEGER DEFAULT 30,
                siem_destination       TEXT DEFAULT '',
                data_lake_destination   TEXT DEFAULT '',
                alerts_destination     TEXT DEFAULT '',
                -- Mirror forwarded logs to the ELF server (per-group toggle).
                -- 1 = mirror log batches + alerts (default); 0 = alerts only.
                -- The agent receives this via GET /config and gates its
                -- reportLogs call on it.
                mirror_logs            INTEGER DEFAULT 1,
                created_at    REAL DEFAULT (strftime('%s','now'))
            );

            CREATE TABLE IF NOT EXISTS agents (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                agent_id      TEXT NOT NULL UNIQUE,
                hostname      TEXT DEFAULT '',
                ip_address    TEXT DEFAULT '',
                os_name       TEXT DEFAULT '',
                group_id      INTEGER DEFAULT 1,
                last_seen     REAL DEFAULT 0,
                first_seen    REAL DEFAULT (strftime('%s','now')),
                events_created    INTEGER DEFAULT 0,
                bytes_created     INTEGER DEFAULT 0,
                events_forwarded  INTEGER DEFAULT 0,
                bytes_forwarded   INTEGER DEFAULT 0,
                FOREIGN KEY (group_id) REFERENCES groups(id)
            );

            CREATE TABLE IF NOT EXISTS rules (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                rule_id       TEXT NOT NULL,
                group_id      INTEGER NOT NULL,
                name          TEXT DEFAULT '',
                description   TEXT DEFAULT '',
                severity      TEXT DEFAULT 'medium',
                enabled       INTEGER DEFAULT 1,
                yaml_body     TEXT NOT NULL,
                created_at    REAL DEFAULT (strftime('%s','now')),
                updated_at    REAL DEFAULT (strftime('%s','now')),
                UNIQUE (rule_id, group_id),
                FOREIGN KEY (group_id) REFERENCES groups(id)
            );

            CREATE TABLE IF NOT EXISTS lists (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                name          TEXT NOT NULL UNIQUE,
                content       TEXT DEFAULT '',
                created_at    REAL DEFAULT (strftime('%s','now')),
                updated_at    REAL DEFAULT (strftime('%s','now'))
            );

            CREATE TABLE IF NOT EXISTS group_destinations (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                group_id      INTEGER NOT NULL,
                name          TEXT NOT NULL,
                url           TEXT NOT NULL,
                position      INTEGER DEFAULT 0,
                UNIQUE (group_id, name),
                FOREIGN KEY (group_id) REFERENCES groups(id) ON DELETE CASCADE
            );

            -- On-demand commands queued for an agent (e.g. "collect logs").
            -- Delivered to the agent via the `commands` array in the
            -- /config response; the agent ACKs by POSTing a result back.
            CREATE TABLE IF NOT EXISTS agent_commands (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                agent_id      TEXT NOT NULL,
                command_type  TEXT NOT NULL,
                params        TEXT NOT NULL DEFAULT '{}',
                status        TEXT NOT NULL DEFAULT 'pending',
                created_at    REAL NOT NULL DEFAULT (strftime('%s','now')),
                sent_at       REAL,
                completed_at  REAL,
                result        TEXT,
                error         TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_agent_commands_agent
                ON agent_commands(agent_id, status);

            -- Authentication: human users with RBAC roles.
            CREATE TABLE IF NOT EXISTS users (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                username      TEXT NOT NULL UNIQUE,
                password_hash  TEXT NOT NULL,
                role          TEXT NOT NULL DEFAULT 'viewer',
                created_at    REAL DEFAULT (strftime('%s','now'))
            );

            -- Authentication: per-agent enrollment tokens (machine auth).
            -- One active token per agent; replace on re-enroll. The agent
            -- sends the raw token as `Authorization: Bearer <token>`; we
            -- store only the SHA-256 hash so a DB leak doesn't expose them.
            CREATE TABLE IF NOT EXISTS agent_tokens (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                agent_id      TEXT NOT NULL UNIQUE,
                token_hash    TEXT NOT NULL,
                created_at    REAL DEFAULT (strftime('%s','now')),
                last_used     REAL,
                FOREIGN KEY (agent_id) REFERENCES agents(agent_id) ON DELETE CASCADE
            );

            -- Audit trail of every mutation (who did what to what).
            -- actor = username or 'agent:<agent_id>'; action is a dotted
            -- verb (rule.create, agent.delete, auth.login, ...); target is
            -- the affected entity id; detail is a JSON blob.
            CREATE TABLE IF NOT EXISTS audit_log (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                ts            REAL DEFAULT (strftime('%s','now')),
                actor         TEXT NOT NULL DEFAULT '',
                action        TEXT NOT NULL DEFAULT '',
                target        TEXT DEFAULT '',
                detail        TEXT DEFAULT ''
            );
            CREATE INDEX IF NOT EXISTS idx_audit_log_ts ON audit_log(ts DESC);

            -- Server-wide key/value settings (e.g. max_logs_text_mb).
            -- Written via PUT /settings; read on every relevant path.
            CREATE TABLE IF NOT EXISTS settings (
                key   TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );

            -- Counter snapshots taken at Metrics reset. Agents report
            -- CUMULATIVE counters on every poll, so zeroing the agents row
            -- alone would be undone within one poll cycle. Instead, the
            -- reset snapshots each agent's current counters here, and
            -- savings_report subtracts the baseline (clamped at 0) so the
            -- view shows activity from the reset onward.
            CREATE TABLE IF NOT EXISTS counter_baselines (
                agent_id         TEXT PRIMARY KEY,
                events_created   INTEGER NOT NULL DEFAULT 0,
                bytes_created    INTEGER NOT NULL DEFAULT 0,
                events_forwarded INTEGER NOT NULL DEFAULT 0,
                bytes_forwarded  INTEGER NOT NULL DEFAULT 0
            );
            """
        )
        # Migrate legacy per-group destination columns (siem_destination,
        # data_lake_destination, alerts_destination) into the
        # group_destinations table. This runs once on databases created
        # before the multi-destination schema. The legacy columns are left
        # in place (SQLite can't easily DROP COLUMN in older versions) but
        # are never read or written.
        gcols = {r["name"] for r in conn.execute("PRAGMA table_info(groups)").fetchall()}
        if "siem_destination" in gcols:
            existing = conn.execute(
                "SELECT 1 FROM group_destinations LIMIT 1"
            ).fetchone()
            if not existing:
                for g in conn.execute("SELECT * FROM groups").fetchall():
                    pos = 0
                    for col, dname in (
                        ("siem_destination", "siem"),
                        ("data_lake_destination", "data_lake"),
                        ("alerts_destination", "alerts"),
                    ):
                        url = g[col] if col in g.keys() else ""
                        if url:
                            conn.execute(
                                "INSERT OR IGNORE INTO group_destinations "
                                "(group_id, name, url, position) VALUES (?, ?, ?, ?)",
                                (g["id"], dname, url, pos),
                            )
                            pos += 1
        # Seed a default group if none exists.
        row = conn.execute("SELECT COUNT(*) AS c FROM groups").fetchone()
        if row["c"] == 0:
            conn.execute(
                "INSERT INTO groups (name, description) VALUES (?, ?)",
                ("default", "All agents that are not assigned to another group."),
            )
        # Migrate older databases: add ip_address / os_name columns if the
        # agents table was created before these columns existed. SQLite's
        # ALTER TABLE ADD COLUMN is idempotent-safe when guarded by a PRAGMA
        # table_info check.
        cols = {r["name"] for r in conn.execute("PRAGMA table_info(agents)").fetchall()}
        if "ip_address" not in cols:
            conn.execute("ALTER TABLE agents ADD COLUMN ip_address TEXT DEFAULT ''")
        if "os_name" not in cols:
            conn.execute("ALTER TABLE agents ADD COLUMN os_name TEXT DEFAULT ''")
        # Migrate older databases: add the cumulative event/byte counter
        # columns used by the logs savings view. The agent reports these on
        # every poll; the server stores them so the UI can compute the
        # fraction of host-generated events that were actually forwarded.
        for col in ("events_created", "bytes_created", "events_forwarded", "bytes_forwarded"):
            if col not in cols:
                conn.execute(f"ALTER TABLE agents ADD COLUMN {col} INTEGER DEFAULT 0")
        # Seed a default reusable list so the feature is demoable out of the
        # box. Rules can reference it as `@@sensitive_processes`.
        row = conn.execute("SELECT COUNT(*) AS c FROM lists").fetchone()
        if row["c"] == 0:
            conn.execute(
                "INSERT INTO lists (name, content) VALUES (?, ?)",
                ("sensitive_processes",
                 "# Sensitive processes to alert on (one per line).\n"
                 "# Lines starting with # are comments.\n"
                 "calc.exe\n"
                 "notepad.exe\n"
                 "mspaint.exe\n"),
            )
        # Migrate older databases: add the `enrolled` column to agents so
        # the UI can show which agents have been issued an enrollment token.
        # Backfill-safe via the PRAGMA table_info guard used elsewhere.
        cols = {r["name"] for r in conn.execute("PRAGMA table_info(agents)").fetchall()}
        if "enrolled" not in cols:
            conn.execute("ALTER TABLE agents ADD COLUMN enrolled INTEGER DEFAULT 0")
        # Migrate older databases: add the per-group mirror_logs toggle.
        # ALTER TABLE ADD COLUMN with a DEFAULT backfills existing rows with
        # that default (1 = mirror on), so pre-existing groups keep mirroring.
        gcols = {r["name"] for r in conn.execute("PRAGMA table_info(groups)").fetchall()}
        if "mirror_logs" not in gcols:
            conn.execute("ALTER TABLE groups ADD COLUMN mirror_logs INTEGER DEFAULT 1")
        # Seed the default admin user from env vars (idempotent upsert on
        # username). The password is bcrypt-hashed. If the password is the
        # default 'admin' or unset, log a prominent startup warning + an
        # audit event; no forced change, just visibility.
        _seed_admin(conn)
        # Seed the max logs.txt size setting from the environment (used by
        # _enforce_logs_text_cap). INSERT OR IGNORE keeps an operator's
        # saved value on restart; the env var only provides the initial
        # default. 0 = unlimited.
        import os as _os
        conn.execute(
            "INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)",
            ("max_logs_text_mb", _os.environ.get("ELF_MAX_LOGS_TEXT_MB", "100")),
        )


# --- Groups -----------------------------------------------------------------

def _attach_destinations(group: dict, conn) -> dict:
    """Attach the group's destinations (ordered list of {name, url}) to a
    group dict. Called from list_groups/get_group/get_group_by_name."""
    if group is None:
        return group
    rows = conn.execute(
        "SELECT name, url FROM group_destinations WHERE group_id = ? "
        "ORDER BY position, id",
        (group["id"],),
    ).fetchall()
    group["destinations"] = [{"name": r["name"], "url": r["url"]} for r in rows]
    return group


def list_groups(db_path: str = DB_PATH) -> list[dict]:
    with get_conn(db_path) as conn:
        rows = conn.execute("SELECT * FROM groups ORDER BY name").fetchall()
        return [_attach_destinations(dict(r), conn) for r in rows]


def get_group(group_id: int, db_path: str = DB_PATH) -> dict | None:
    with get_conn(db_path) as conn:
        row = conn.execute("SELECT * FROM groups WHERE id = ?", (group_id,)).fetchone()
        return _attach_destinations(dict(row), conn) if row else None


def get_group_by_name(name: str, db_path: str = DB_PATH) -> dict | None:
    with get_conn(db_path) as conn:
        row = conn.execute("SELECT * FROM groups WHERE name = ?", (name,)).fetchone()
        return _attach_destinations(dict(row), conn) if row else None


def create_group(name: str, description: str = "", db_path: str = DB_PATH) -> dict:
    with _lock, get_conn(db_path) as conn:
        cur = conn.execute(
            "INSERT INTO groups (name, description) VALUES (?, ?)",
            (name, description),
        )
        # Read the row back on the SAME connection. Calling get_group() would
        # open a separate connection that can't see this uncommitted INSERT
        # (the transaction commits only when the with-block exits), so it
        # would return None and the endpoint would 500. The group would still
        # be created (committed on exit), which is why a refresh shows it.
        row = conn.execute(
            "SELECT * FROM groups WHERE id = ?", (cur.lastrowid,)
        ).fetchone()
        return _attach_destinations(dict(row), conn)


def update_group(group_id: int, fields: dict, db_path: str = DB_PATH) -> dict | None:
    allowed = {
        "name", "description", "retention_seconds", "poll_interval_seconds",
        "destinations", "mirror_logs",
    }
    # Separate the destinations list (handled via group_destinations) from
    # the scalar group fields.
    dests = fields.get("destinations")
    scalar = {k: fields[k] for k in fields if k in allowed and k != "destinations"}
    sets = [f"{k} = ?" for k in scalar]
    vals = [scalar[k] for k in scalar]
    with _lock, get_conn(db_path) as conn:
        if sets:
            conn.execute(
                f"UPDATE groups SET {', '.join(sets)} WHERE id = ?", (*vals, group_id)
            )
        if dests is not None:
            # Replace the full destination set: delete then re-insert in order.
            conn.execute(
                "DELETE FROM group_destinations WHERE group_id = ?", (group_id,)
            )
            for pos, d in enumerate(dests):
                name = (d.get("name") or "").strip()
                url = (d.get("url") or "").strip()
                if name and url:
                    conn.execute(
                        "INSERT OR IGNORE INTO group_destinations "
                        "(group_id, name, url, position) VALUES (?, ?, ?, ?)",
                        (group_id, name, url, pos),
                    )
    return get_group(group_id, db_path)


def delete_group(group_id: int, db_path: str = DB_PATH) -> bool:
    # Refuse to delete the default group (id=1) so agents always have a home.
    if group_id == 1:
        return False
    with _lock, get_conn(db_path) as conn:
        # Reassign orphaned agents to the default group.
        conn.execute("UPDATE agents SET group_id = 1 WHERE group_id = ?", (group_id,))
        conn.execute("DELETE FROM rules WHERE group_id = ?", (group_id,))
        # group_destinations rows are removed by the ON DELETE CASCADE.
        cur = conn.execute("DELETE FROM groups WHERE id = ?", (group_id,))
        return cur.rowcount > 0


# --- Agents -----------------------------------------------------------------

def register_agent(agent_id: str, hostname: str = "", group_id: int = 1,
                   ip_address: str = "", os_name: str = "",
                   events_created: int = 0, bytes_created: int = 0,
                   events_forwarded: int = 0, bytes_forwarded: int = 0,
                   db_path: str = DB_PATH, update_group: bool = False) -> dict:
    """Insert the agent if new, update last_seen/hostname if known. Returns the
    agent row.

    By default existing agents keep their current group (registration is
    idempotent; only last_seen/hostname/ip/os are touched). Pass
    update_group=True to also move an existing agent into group_id (used by
    POST /agents/register when the caller explicitly supplies a group_id, e.g.
    the install script re-registering a host into a different group).

    If the supplied group_id does not exist (e.g. the group was deleted after
    the install script was generated), the agent is assigned to the default
    group (id=1) instead of failing the foreign-key constraint."""
    now = time.time()
    with _lock, get_conn(db_path) as conn:
        # Validate the group_id; fall back to the default group (id=1) if it
        # doesn't exist so an invalid/deleted group never blocks registration.
        if group_id != 1:
            g = conn.execute("SELECT 1 FROM groups WHERE id = ?", (group_id,)).fetchone()
            if not g:
                group_id = 1
        row = conn.execute("SELECT * FROM agents WHERE agent_id = ?", (agent_id,)).fetchone()
        if row is None:
            conn.execute(
                "INSERT INTO agents (agent_id, hostname, ip_address, os_name, "
                "group_id, last_seen, events_created, bytes_created, "
                "events_forwarded, bytes_forwarded) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (agent_id, hostname, ip_address, os_name, group_id, now,
                 events_created, bytes_created, events_forwarded, bytes_forwarded),
            )
        else:
            if update_group:
                conn.execute(
                    "UPDATE agents SET hostname = ?, ip_address = ?, os_name = ?, "
                    "last_seen = ?, group_id = ?, events_created = ?, "
                    "bytes_created = ?, events_forwarded = ?, bytes_forwarded = ? "
                    "WHERE agent_id = ?",
                    (hostname, ip_address, os_name, now, group_id,
                     events_created, bytes_created, events_forwarded, bytes_forwarded,
                     agent_id),
                )
            else:
                conn.execute(
                    "UPDATE agents SET hostname = ?, ip_address = ?, os_name = ?, "
                    "last_seen = ?, events_created = ?, bytes_created = ?, "
                    "events_forwarded = ?, bytes_forwarded = ? WHERE agent_id = ?",
                    (hostname, ip_address, os_name, now,
                     events_created, bytes_created, events_forwarded, bytes_forwarded,
                     agent_id),
                )
        row = conn.execute("SELECT * FROM agents WHERE agent_id = ?", (agent_id,)).fetchone()
        return dict(row)


def touch_agent(agent_id: str, hostname: str = "", ip_address: str = "",
                os_name: str = "",
                events_created: int | None = None, bytes_created: int | None = None,
                events_forwarded: int | None = None, bytes_forwarded: int | None = None,
                db_path: str = DB_PATH) -> None:
    """Update last_seen (and hostname/ip/os/counters if provided) without
    creating the agent. Called on every poll so the server always has the
    agent's latest detected IP, OS, and cumulative event/byte counters."""
    now = time.time()
    with _lock, get_conn(db_path) as conn:
        # Build the SET clause from whichever fields were supplied so a poll
        # that only sends last_seen doesn't clobber the stored IP/OS/counters.
        sets = ["last_seen = ?"]
        vals: list[Any] = [now]
        if hostname:
            sets.append("hostname = ?"); vals.append(hostname)
        if ip_address:
            sets.append("ip_address = ?"); vals.append(ip_address)
        if os_name:
            sets.append("os_name = ?"); vals.append(os_name)
        if events_created is not None:
            sets.append("events_created = ?"); vals.append(events_created)
        if bytes_created is not None:
            sets.append("bytes_created = ?"); vals.append(bytes_created)
        if events_forwarded is not None:
            sets.append("events_forwarded = ?"); vals.append(events_forwarded)
        if bytes_forwarded is not None:
            sets.append("bytes_forwarded = ?"); vals.append(bytes_forwarded)
        vals.append(agent_id)
        conn.execute(
            f"UPDATE agents SET {', '.join(sets)} WHERE agent_id = ?", vals
        )


def list_agents(db_path: str = DB_PATH) -> list[dict]:
    with get_conn(db_path) as conn:
        rows = conn.execute(
            "SELECT a.*, g.name AS group_name FROM agents a "
            "LEFT JOIN groups g ON a.group_id = g.id ORDER BY a.first_seen"
        ).fetchall()
        return [dict(r) for r in rows]


def get_agent(agent_id: str, db_path: str = DB_PATH) -> dict | None:
    with get_conn(db_path) as conn:
        row = conn.execute(
            "SELECT a.*, g.name AS group_name FROM agents a "
            "LEFT JOIN groups g ON a.group_id = g.id WHERE a.agent_id = ?",
            (agent_id,),
        ).fetchone()
        return dict(row) if row else None


def set_agent_group(agent_id: str, group_id: int, db_path: str = DB_PATH) -> dict | None:
    with _lock, get_conn(db_path) as conn:
        # Validate the group_id; fall back to the default group (id=1) if it
        # doesn't exist so an invalid/deleted group never strands an agent.
        if group_id != 1:
            g = conn.execute("SELECT 1 FROM groups WHERE id = ?", (group_id,)).fetchone()
            if not g:
                group_id = 1
        conn.execute("UPDATE agents SET group_id = ? WHERE agent_id = ?", (group_id, agent_id))
    return get_agent(agent_id, db_path)


def delete_agent(agent_id: str, db_path: str = DB_PATH, cascade: bool = False) -> bool:
    """Delete an agent row. Returns True if a row was removed.

    By default the agent's historical alerts/logs are KEPT (they may be
    needed for investigation after the agent is decommissioned). Pass
    cascade=True to also delete them."""
    with _lock, get_conn(db_path) as conn:
        cur = conn.execute("DELETE FROM agents WHERE agent_id = ?", (agent_id,))
        if cascade:
            # Cascade-clean history tables (created lazily by store_alert/store_logs).
            _ensure_alerts_table(conn)
            _ensure_logs_table(conn)
            conn.execute("DELETE FROM alerts WHERE agent_id = ?", (agent_id,))
            conn.execute("DELETE FROM forwarded_logs WHERE agent_id = ?", (agent_id,))
            conn.execute("DELETE FROM agent_commands WHERE agent_id = ?", (agent_id,))
        return cur.rowcount > 0


# --- Agent commands (on-demand tasks queued for an agent) -------------------

def create_command(agent_id: str, command_type: str, params: dict,
                   db_path: str = DB_PATH) -> dict:
    """Queue a command for an agent. Returns the new command row.

    Refuses to create a new command if the agent already has a non-terminal
    (pending/sent) command, so there is at most one in-flight command per
    agent at a time. The UI also enforces this, but the DB is the source of
    truth."""
    import json
    now = time.time()
    with _lock, get_conn(db_path) as conn:
        # Enforce one in-flight command per agent.
        existing = conn.execute(
            "SELECT id FROM agent_commands "
            "WHERE agent_id = ? AND status IN ('pending','sent') "
            "ORDER BY id DESC LIMIT 1",
            (agent_id,),
        ).fetchone()
        if existing:
            # Return the existing in-flight command rather than creating a
            # duplicate so the caller gets a meaningful row back.
            row = conn.execute(
                "SELECT * FROM agent_commands WHERE id = ?", (existing["id"],)
            ).fetchone()
            return dict(row)
        cur = conn.execute(
            "INSERT INTO agent_commands (agent_id, command_type, params, "
            "status, created_at) VALUES (?, ?, ?, 'pending', ?)",
            (agent_id, command_type, json.dumps(params), now),
        )
        row = conn.execute(
            "SELECT * FROM agent_commands WHERE id = ?", (cur.lastrowid,)
        ).fetchone()
        return dict(row)


def pending_commands(agent_id: str, db_path: str = DB_PATH) -> list[dict]:
    """Return all pending (not yet delivered) commands for an agent."""
    with get_conn(db_path) as conn:
        rows = conn.execute(
            "SELECT * FROM agent_commands "
            "WHERE agent_id = ? AND status = 'pending' "
            "ORDER BY id",
            (agent_id,),
        ).fetchall()
        return [dict(r) for r in rows]


def mark_commands_sent(command_ids: list[int],
                        db_path: str = DB_PATH) -> None:
    """Flip the given commands from pending to sent (delivered to the agent).
    Stamps sent_at so a retry poll does not re-deliver."""
    if not command_ids:
        return
    now = time.time()
    with _lock, get_conn(db_path) as conn:
        conn.executemany(
            "UPDATE agent_commands SET status = 'sent', sent_at = ? "
            "WHERE id = ? AND status = 'pending'",
            [(now, cid) for cid in command_ids],
        )


def get_command(command_id: int, db_path: str = DB_PATH) -> dict | None:
    with get_conn(db_path) as conn:
        row = conn.execute(
            "SELECT * FROM agent_commands WHERE id = ?", (command_id,)
        ).fetchone()
        return dict(row) if row else None


def complete_command(command_id: int, status: str, result: dict | None = None,
                     error: str | None = None, db_path: str = DB_PATH) -> dict | None:
    """Mark a command done or failed. `status` must be 'done' or 'failed'."""
    import json
    now = time.time()
    with _lock, get_conn(db_path) as conn:
        conn.execute(
            "UPDATE agent_commands SET status = ?, completed_at = ?, "
            "result = ?, error = ? WHERE id = ?",
            (status, now,
             json.dumps(result) if result is not None else None,
             error, command_id),
        )
        row = conn.execute(
            "SELECT * FROM agent_commands WHERE id = ?", (command_id,)
        ).fetchone()
        return dict(row) if row else None


def agent_command_summary(agent_id: str, db_path: str = DB_PATH) -> dict | None:
    """Return the latest non-done command for an agent (for the UI badge), or
    the most recent done command if none is in flight. Returns None if the
    agent has no commands at all."""
    with get_conn(db_path) as conn:
        row = conn.execute(
            "SELECT * FROM agent_commands WHERE agent_id = ? "
            "ORDER BY id DESC LIMIT 1",
            (agent_id,),
        ).fetchone()
        return dict(row) if row else None


# --- Rules ------------------------------------------------------------------

def list_rules(group_id: int | None = None, db_path: str = DB_PATH) -> list[dict]:
    with get_conn(db_path) as conn:
        if group_id is None:
            rows = conn.execute("SELECT * FROM rules ORDER BY rule_id").fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM rules WHERE group_id = ? ORDER BY rule_id", (group_id,)
            ).fetchall()
        return [dict(r) for r in rows]


def get_rule(rule_id: str, group_id: int, db_path: str = DB_PATH) -> dict | None:
    with get_conn(db_path) as conn:
        row = conn.execute(
            "SELECT * FROM rules WHERE rule_id = ? AND group_id = ?",
            (rule_id, group_id),
        ).fetchone()
        return dict(row) if row else None


def upsert_rule(rule_id: str, group_id: int, yaml_body: str,
                name: str = "", description: str = "", severity: str = "medium",
                enabled: bool = True, db_path: str = DB_PATH) -> dict:
    now = time.time()
    with _lock, get_conn(db_path) as conn:
        existing = conn.execute(
            "SELECT id FROM rules WHERE rule_id = ? AND group_id = ?", (rule_id, group_id)
        ).fetchone()
        if existing is None:
            conn.execute(
                "INSERT INTO rules (rule_id, group_id, name, description, severity, "
                "enabled, yaml_body, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (rule_id, group_id, name, description, severity, int(enabled),
                 yaml_body, now, now),
            )
        else:
            conn.execute(
                "UPDATE rules SET name = ?, description = ?, severity = ?, enabled = ?, "
                "yaml_body = ?, updated_at = ? WHERE rule_id = ? AND group_id = ?",
                (name, description, severity, int(enabled), yaml_body, now, rule_id, group_id),
            )
        # Read back on the SAME connection (see create_group for why).
        row = conn.execute(
            "SELECT * FROM rules WHERE rule_id = ? AND group_id = ?",
            (rule_id, group_id),
        ).fetchone()
        return dict(row) if row else None


def upsert_rules_bulk(rows: list[dict], group_id: int,
                      db_path: str = DB_PATH) -> int:
    """Upsert many rules into one group in a SINGLE transaction.

    Each row: {rule_id, yaml_body, name, description, severity, enabled}.
    Returns the number of rows written. One transaction rather than one
    upsert_rule() call per rule: 3,000 connections and 3,000 commits take
    tens of seconds under the global lock, and an agent polling mid-way
    would receive a half-written ruleset (load it, resubscribe on it, and
    load again a minute later). With a single transaction an agent sees
    either the old set or the complete new one. Relies on
    UNIQUE(rule_id, group_id).
    """
    if not rows:
        return 0
    now = time.time()
    params = [
        (r["rule_id"], group_id, r.get("name", ""), r.get("description", ""),
         r.get("severity", "medium"), int(r.get("enabled", True)),
         r["yaml_body"], now, now)
        for r in rows
    ]
    with _lock, get_conn(db_path) as conn:
        conn.executemany(
            "INSERT INTO rules (rule_id, group_id, name, description, severity, "
            "enabled, yaml_body, created_at, updated_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) "
            "ON CONFLICT(rule_id, group_id) DO UPDATE SET "
            "name = excluded.name, description = excluded.description, "
            "severity = excluded.severity, enabled = excluded.enabled, "
            "yaml_body = excluded.yaml_body, updated_at = excluded.updated_at",
            params,
        )
    return len(params)


def delete_rule(rule_id: str, group_id: int, db_path: str = DB_PATH) -> bool:
    with _lock, get_conn(db_path) as conn:
        cur = conn.execute(
            "DELETE FROM rules WHERE rule_id = ? AND group_id = ?", (rule_id, group_id)
        )
        return cur.rowcount > 0


def delete_rules(rule_ids: list[str], group_id: int,
                 db_path: str = DB_PATH) -> int:
    """Delete many rules by rule_id within one group in a single transaction.
    Returns the number of rows actually deleted (may be less than len(rule_ids)
    if some ids don't exist in this group). Safe to call with an empty list
    (returns 0 without touching the DB)."""
    if not rule_ids:
        return 0
    # Dedupe so we don't bind the same id twice (defensive; the IN list
    # would still work, but it keeps the parameter count predictable).
    ids = list(dict.fromkeys(rule_ids))
    placeholders = ",".join("?" for _ in ids)
    with _lock, get_conn(db_path) as conn:
        cur = conn.execute(
            f"DELETE FROM rules WHERE group_id = ? AND rule_id IN ({placeholders})",
            [group_id, *ids],
        )
        return cur.rowcount


# --- Lists (reusable value lists, global across all groups) -----------------

def list_lists(db_path: str = DB_PATH) -> list[dict]:
    """Return all reusable lists, ordered by name."""
    with get_conn(db_path) as conn:
        rows = conn.execute("SELECT * FROM lists ORDER BY name").fetchall()
        return [dict(r) for r in rows]


def get_list(name: str, db_path: str = DB_PATH) -> dict | None:
    with get_conn(db_path) as conn:
        row = conn.execute("SELECT * FROM lists WHERE name = ?", (name,)).fetchone()
        return dict(row) if row else None


def upsert_list(name: str, content: str, db_path: str = DB_PATH) -> dict:
    """Insert or update a reusable list by name. Returns the row."""
    now = time.time()
    with _lock, get_conn(db_path) as conn:
        existing = conn.execute("SELECT id FROM lists WHERE name = ?", (name,)).fetchone()
        if existing is None:
            conn.execute(
                "INSERT INTO lists (name, content, created_at, updated_at) "
                "VALUES (?, ?, ?, ?)",
                (name, content, now, now),
            )
        else:
            conn.execute(
                "UPDATE lists SET content = ?, updated_at = ? WHERE name = ?",
                (content, now, name),
            )
        row = conn.execute("SELECT * FROM lists WHERE name = ?", (name,)).fetchone()
        return dict(row) if row else None


def delete_list(name: str, db_path: str = DB_PATH) -> bool:
    with _lock, get_conn(db_path) as conn:
        cur = conn.execute("DELETE FROM lists WHERE name = ?", (name,))
        return cur.rowcount > 0


# --- Alerts / logs (received from agents) -----------------------------------

# How many of the newest forwarded-log batches keep their full payload in
# the DB. Older batches are pruned to slim metadata rows (payload='');
# their events live on in the logs.txt text file (append_logs_text), which
# is the durable archive. The slim rows keep the Metrics timeseries
# (event_count + payload_bytes) working over the FULL history while the
# Logs tab only ever shows the newest batches anyway.
LOGS_PAYLOAD_KEEP = 40


def _ensure_alerts_table(conn: Any) -> None:
    """Create the alerts table if missing and migrate the severity column
    (added after the table first shipped). Idempotent, so safe to call on
    every read/write path. Also creates the received_at index that keeps
    the default newest-first listing fast as the table grows to thousands
    of alerts."""
    conn.executescript(
        "CREATE TABLE IF NOT EXISTS alerts ("
        "  id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "  agent_id TEXT, rule_id TEXT, message TEXT, severity TEXT DEFAULT '',"
        "  received_at REAL, payload TEXT);"
        "CREATE INDEX IF NOT EXISTS idx_alerts_received_at"
        "  ON alerts(received_at);"
    )
    cols = {r[1] for r in conn.execute("PRAGMA table_info(alerts)")}
    if "severity" not in cols:
        try:
            conn.execute("ALTER TABLE alerts ADD COLUMN severity TEXT DEFAULT ''")
        except sqlite3.OperationalError:
            pass  # lost a race with a concurrent migration: column exists
        # One-time backfill: rows written before the column existed get
        # their severity from the stored payload's level. json_extract needs
        # the JSON1 extension; skip silently if the build lacks it.
        try:
            conn.execute(
                "UPDATE alerts SET severity = "
                "COALESCE(json_extract(payload, '$.level'), '') "
                "WHERE severity = ''"
            )
        except Exception:
            pass


def _ensure_logs_table(conn: Any) -> None:
    """Create the forwarded_logs table if missing and add the payload_bytes
    column to databases that predate payload pruning.
    Idempotent, so safe to call on every read/write path. Also creates the
    received_at index used by the newest-first listing and the timeseries
    range scans."""
    conn.executescript(
        "CREATE TABLE IF NOT EXISTS forwarded_logs ("
        "  id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "  agent_id TEXT, rule_id TEXT, event_count INTEGER, received_at REAL,"
        "  payload TEXT, payload_bytes INTEGER DEFAULT 0);"
        "CREATE INDEX IF NOT EXISTS idx_forwarded_logs_received_at"
        "  ON forwarded_logs(received_at);"
    )
    cols = {r[1] for r in conn.execute("PRAGMA table_info(forwarded_logs)")}
    if "alert_id" not in cols:
        try:
            conn.execute(
                "ALTER TABLE forwarded_logs ADD COLUMN alert_id TEXT DEFAULT ''")
        except sqlite3.OperationalError:
            pass
    if "payload_bytes" not in cols:
        try:
            conn.execute(
                "ALTER TABLE forwarded_logs ADD COLUMN payload_bytes INTEGER DEFAULT 0")
        except sqlite3.OperationalError:
            pass  # lost a race with a concurrent migration: column exists
        # One-time backfill: existing rows get their payload size recorded
        # BEFORE any pruning strips the payload (the timeseries reads
        # payload_bytes, never the payload itself).
        try:
            conn.execute(
                "UPDATE forwarded_logs SET payload_bytes = LENGTH(COALESCE(payload, '')) "
                "WHERE payload_bytes = 0 AND COALESCE(payload, '') != ''"
            )
        except Exception:
            pass


def store_alert(agent_id: str, payload: dict, db_path: str = DB_PATH) -> int:
    """Store an alert reported by an agent. Returns the row id.

    The `severity` column holds the Sigma level (critical/high/medium/low/
    informational) the agent threaded through from the rule. The payload
    still stores the full JSON (including level + the trigger event XML)
    for the detail view, which the UI fetches ON DEMAND per alert via
    get_alert; list_alerts deliberately omits payloads so listing stays
    fast with thousands of alerts."""
    import json
    now = time.time()
    with _lock, get_conn(db_path) as conn:
        _ensure_alerts_table(conn)
        cur = conn.execute(
            "INSERT INTO alerts (agent_id, rule_id, message, severity, received_at, payload) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (agent_id, payload.get("rule_id", ""), payload.get("message", ""),
             payload.get("level", ""), now, json.dumps(payload)),
        )
        return int(cur.lastrowid)


def store_logs(agent_id: str, payload: dict, db_path: str = DB_PATH) -> int:
    """Store a batch of forwarded logs from an agent. Returns the row id.

    The full payload (every event's raw XML) is kept ONLY for the newest
    LOGS_PAYLOAD_KEEP batches; older rows are pruned to slim metadata
    (payload='') right here, because their events are already archived in
    the logs.txt text file (append_logs_text) and nothing reads old
    payloads: the Logs tab lists metadata only, and the Metrics timeseries
    reads the pre-computed payload_bytes column. This keeps the table tiny
    even after tens of thousands of batches, so neither the DB nor the UI
    ever hauls around megabytes of stale event XML."""
    import json
    now = time.time()
    with _lock, get_conn(db_path) as conn:
        _ensure_logs_table(conn)
        payload_json = json.dumps(payload)
        cur = conn.execute(
            "INSERT INTO forwarded_logs "
            "(agent_id, rule_id, event_count, received_at, payload, payload_bytes, alert_id) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (agent_id, payload.get("rule_id", ""), payload.get("event_count", 0),
             now, payload_json, len(payload_json), payload.get("alert_id", "") or ""),
        )
        # Prune payloads that fell out of the keep-window. Runs on every
        # insert but only ever writes the row(s) that just aged out (all
        # older rows already have payload='').
        conn.execute(
            "UPDATE forwarded_logs SET payload = '' "
            "WHERE payload != '' AND id NOT IN "
            "(SELECT id FROM forwarded_logs ORDER BY id DESC LIMIT ?)",
            (LOGS_PAYLOAD_KEEP,),
        )
        return int(cur.lastrowid)


def list_alerts(db_path: str = DB_PATH, limit: int = 100, q: str = "",
                sort: str = "recency", offset: int = 0) -> list[dict]:
    """List recent alerts. `sort` selects the ordering:
      - "recency"  (default): received_at DESC, newest first.
      - "severity": severity rank (critical > high > medium > low >
                   informational > unknown) DESC, then received_at DESC, so
                   the analyst sees the most severe recent alerts first.
    `q` is an optional substring filter matched (case-insensitively, via
    LIKE) against the rule_id, message, agent_id, or the rule's display
    name. `offset` pages past the first `limit` rows. Each row also carries
    `rule_name` (the rule's display name from the rules table, when the
    rule still exists) so the UI can show a friendly name instead of the
    raw rule_id.

    The payload column is deliberately NOT selected. Alert payloads embed
    the trigger event XML (plus sequence/window events) and run to
    kilobytes each, so SELECT a.* on a 200-row listing would ship megabytes
    and stall the browser while it parses them. The UI fetches one alert's
    payload on demand via get_alert / GET /alerts/{id} when the analyst
    expands a row."""
    with get_conn(db_path) as conn:
        _ensure_alerts_table(conn)
        # Severity rank: critical=5, high=4, medium=3, low=2, informational=1,
        # unknown/empty=0. Computed inline so the ORDER BY can use it without
        # a separate column.
        order_by = (
            "a.received_at DESC"
            if sort == "recency"
            else "CASE LOWER(a.severity) "
                 "  WHEN 'critical' THEN 5 "
                 "  WHEN 'high' THEN 4 "
                 "  WHEN 'medium' THEN 3 "
                 "  WHEN 'low' THEN 2 "
                 "  WHEN 'informational' THEN 1 "
                 "  ELSE 0 END DESC, a.received_at DESC"
        )
        # LEFT JOIN the rules table for the rule's display name. MAX(name)
        # collapses the (rare) case where the same rule_id exists in multiple
        # groups; pick one deterministically instead of duplicating rows.
        sql = (
            "SELECT a.id, a.agent_id, a.rule_id, a.message, a.severity, "
            "a.received_at, rn.rule_name AS rule_name FROM alerts a "
            "LEFT JOIN (SELECT rule_id, MAX(name) AS rule_name FROM rules "
            "            GROUP BY rule_id) rn ON rn.rule_id = a.rule_id "
        )
        params: list[Any] = []
        if q:
            needle = f"%{q}%"
            sql += ("WHERE a.rule_id LIKE ? OR a.message LIKE ? "
                    "OR a.agent_id LIKE ? OR rn.rule_name LIKE ? ")
            params.extend([needle, needle, needle, needle])
        sql += f"ORDER BY {order_by} LIMIT ? OFFSET ?"
        params.extend([limit, offset])
        rows = conn.execute(sql, params).fetchall()
        return [dict(r) for r in rows]


def get_alert(alert_id: int, db_path: str = DB_PATH) -> dict | None:
    """Fetch a single alert row INCLUDING its payload (the trigger event
    XML, sequence events, window events). This is the on-demand detail
    source for the Alerts tab; list_alerts strips payloads for speed, so
    the UI calls this only when the analyst expands a row. Returns None
    when the id doesn't exist."""
    with get_conn(db_path) as conn:
        _ensure_alerts_table(conn)
        row = conn.execute(
            "SELECT * FROM alerts WHERE id = ?", (alert_id,)
        ).fetchone()
        return dict(row) if row else None


def list_logs(db_path: str = DB_PATH, limit: int = 100) -> list[dict]:
    # NOTE: deliberately exclude the `payload` column here. Collect-log
    # batches embed every event's raw XML in the payload, so a single row
    # can be hundreds of KB. The Logs tab only needs id/agent/rule/count,
    # and SELECT * for 100 rows would push the /logs endpoint past its timeout.
    # Callers that need the full payload (e.g. the raw text view) use
    # logs_text() or fetch a single row by id.
    with get_conn(db_path) as conn:
        _ensure_logs_table(conn)
        rows = conn.execute(
            "SELECT id, agent_id, rule_id, event_count, received_at, alert_id "
            "FROM forwarded_logs ORDER BY received_at DESC LIMIT ?", (limit,)
        ).fetchall()
        return [dict(r) for r in rows]


def clear_alerts(db_path: str = DB_PATH) -> int:
    """Delete all stored alerts. Returns the number of rows removed.
    Also resets the AUTOINCREMENT counter so IDs restart at 1."""
    with _lock, get_conn(db_path) as conn:
        _ensure_alerts_table(conn)
        cur = conn.execute("DELETE FROM alerts")
        # Reset the AUTOINCREMENT sequence so the next alert gets id=1 instead
        # of continuing from the last high-water mark.
        try:
            conn.execute("DELETE FROM sqlite_sequence WHERE name='alerts'")
        except Exception:
            pass  # sqlite_sequence not created until AUTOINCREMENT is used
        return cur.rowcount


def clear_logs(db_path: str = DB_PATH) -> int:
    """Delete all stored forwarded logs. Returns the number of rows removed.
    Also resets the AUTOINCREMENT counter so IDs restart at 1."""
    with _lock, get_conn(db_path) as conn:
        _ensure_logs_table(conn)
        cur = conn.execute("DELETE FROM forwarded_logs")
        # Reset the AUTOINCREMENT sequence so the next log gets id=1 instead
        # of continuing from the last high-water mark.
        try:
            conn.execute("DELETE FROM sqlite_sequence WHERE name='forwarded_logs'")
        except Exception:
            pass  # sqlite_sequence not created until AUTOINCREMENT is used
        return cur.rowcount


def logs_text_path(db_path: str = DB_PATH) -> str:
    """Path to the newline-separated forwarded-logs text file. Kept next to
    the SQLite DB so it lives on the same persistent volume."""
    import os
    return os.path.join(os.path.dirname(os.path.abspath(db_path)), "logs.txt")


def append_logs_text(agent_id: str, payload: dict, db_path: str = DB_PATH) -> None:
    """Append forwarded logs to the newline-separated text file. Each event
    is written as its own line of raw Windows event XML: no JSON envelope,
    no agent_id/rule_id/event_count header. The event XML already carries the
    host (Computer) and timestamp (TimeCreated), so per-line metadata is
    redundant. Alert details (rule_id, message, trigger event) live in the
    alerts view via POST /alerts, not in the logs file."""
    import os
    path = logs_text_path(db_path)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "a", encoding="utf-8") as f:
        for evt in payload.get("events", []):
            # `evt` is a raw XML string; write it verbatim, one per line.
            f.write(evt + "\n")
    # Enforce the configured size cap (oldest lines trimmed) after every
    # append so the file can never grow unbounded on a busy host.
    _enforce_logs_text_cap(path, db_path)


def get_setting(key: str, default: str = "", db_path: str = DB_PATH) -> str:
    """Read a server-wide setting from the settings table. Returns
    `default` when the key is absent (or the table doesn't exist yet)."""
    try:
        with get_conn(db_path) as conn:
            row = conn.execute(
                "SELECT value FROM settings WHERE key = ?", (key,)
            ).fetchone()
            return row["value"] if row else default
    except Exception:
        return default


def set_setting(key: str, value: str, db_path: str = DB_PATH) -> None:
    """Write a server-wide setting (upsert)."""
    with _lock, get_conn(db_path) as conn:
        conn.execute(
            "INSERT INTO settings (key, value) VALUES (?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            (key, str(value)),
        )


def _enforce_logs_text_cap(path: str, db_path: str = DB_PATH) -> None:
    """Trim the forwarded-logs text file to the configured max size
    (settings key `max_logs_text_mb`, MB, 0 = unlimited). When the file
    exceeds the cap, the OLDEST lines are removed until it's back under
    90% of the cap (a small headroom so we don't trim on every append).
    The trim is atomic: the kept bytes go to a temp file, then os.replace
    swaps it in, so a concurrent reader never sees a partial file."""
    import os
    try:
        max_mb = int(get_setting("max_logs_text_mb", "100", db_path))
    except ValueError:
        return  # non-numeric setting: don't guess, don't trim
    if max_mb <= 0:
        return  # 0 = unlimited
    cap_bytes = max_mb * 1024 * 1024
    try:
        size = os.path.getsize(path)
    except OSError:
        return
    if size <= cap_bytes:
        return
    # Read the file and cut the oldest bytes. Align the cut to the next
    # newline so we never keep a partial (headless) XML line at the top.
    with open(path, "rb") as f:
        data = f.read()
    cut = len(data) - int(cap_bytes * 0.9)
    nl = data.find(b"\n", cut)
    if nl >= 0:
        cut = nl + 1
    else:
        cut = len(data)  # no newline found: drop everything (degenerate)
    kept = data[cut:]
    tmp = path + ".trim"
    with open(tmp, "wb") as f:
        f.write(kept)
    os.replace(tmp, path)  # atomic swap


def clear_logs_text(db_path: str = DB_PATH) -> None:
    """Truncate the forwarded-logs text file."""
    path = logs_text_path(db_path)
    with open(path, "w", encoding="utf-8") as f:
        pass  # truncate


def reset_agent_counters(db_path: str = DB_PATH) -> int:
    """Zero every agent's cumulative created/forwarded counters (the Metrics
    page savings view). Returns the number of agent rows updated. Used by
    DELETE /metrics/reset so an operator can start a clean measurement
    window.

    Agents report CUMULATIVE counters on every poll, so simply zeroing the
    agents row would be overwritten on the next poll. Instead we snapshot
    each agent's current counters into counter_baselines; savings_report
    then subtracts the baseline (clamped at 0), so the view reflects only
    activity since the reset. A second reset re-snapshots (the baseline
    becomes the agent's current cumulative value at that moment)."""
    with _lock, get_conn(db_path) as conn:
        # Snapshot current cumulative counters as the new baseline.
        conn.execute(
            "INSERT OR REPLACE INTO counter_baselines "
            "(agent_id, events_created, bytes_created, events_forwarded, bytes_forwarded) "
            "SELECT agent_id, events_created, bytes_created, events_forwarded, bytes_forwarded "
            "FROM agents"
        )
        cur = conn.execute(
            "UPDATE agents SET events_created = 0, bytes_created = 0, "
            "events_forwarded = 0, bytes_forwarded = 0"
        )
        return cur.rowcount


def logs_text_size_bytes(db_path: str = DB_PATH) -> int:
    """Return the size of the forwarded-logs text file in bytes (0 if absent)."""
    import os
    path = logs_text_path(db_path)
    try:
        return os.path.getsize(path)
    except OSError:
        return 0


def logs_timeseries(db_path: str = DB_PATH, start_ts: float = 0,
                   end_ts: float = 0, bucket_seconds: int = 1) -> list[dict]:
    """Aggregate forwarded_logs into time buckets for the graphs. Returns a
    list of {bucket_ts, event_count, bytes} sorted by time. bucket_ts is the
    epoch timestamp of the start of each bucket. bytes is the total payload
    size (the JSON envelope stored in the DB) for that bucket, a proxy for
    the network bytes the agent shipped. event_count is the sum of event_count
    across all log batches in the bucket. Read from the pre-computed
    payload_bytes column (never the payload itself, which is pruned to
    the newest batches)."""
    with get_conn(db_path) as conn:
        _ensure_logs_table(conn)
        if end_ts and end_ts < start_ts:
            start_ts, end_ts = end_ts, start_ts
        if not end_ts:
            end_ts = time.time()
        if not start_ts:
            start_ts = end_ts - 3600  # default: last 1h
        rows = conn.execute(
            "SELECT received_at, event_count, "
            "COALESCE(payload_bytes, 0) AS payload_bytes FROM forwarded_logs "
            "WHERE received_at >= ? AND received_at <= ? "
            "ORDER BY received_at",
            (start_ts, end_ts),
        ).fetchall()
    if not rows:
        return []
    # Align buckets to the start_ts boundary so they're deterministic.
    buckets: dict[int, dict] = {}
    for r in rows:
        bkt = int(r["received_at"] - (r["received_at"] - start_ts) % bucket_seconds)
        if bkt not in buckets:
            buckets[bkt] = {"bucket_ts": bkt, "event_count": 0, "bytes": 0}
        buckets[bkt]["event_count"] += r["event_count"] or 0
        buckets[bkt]["bytes"] += r["payload_bytes"] or 0
    return sorted(buckets.values(), key=lambda b: b["bucket_ts"])


def logs_timeseries_by_agent(
    db_path: str = DB_PATH, start_ts: float = 0, end_ts: float = 0,
    bucket_seconds: int = 1, agent_id: str | None = None,
) -> list[dict]:
    """Same as logs_timeseries but optionally filtered to a single agent.
    When agent_id is None or empty, behaves identically to logs_timeseries
    (totals across all agents). Returns {bucket_ts, event_count, bytes}."""
    with get_conn(db_path) as conn:
        _ensure_logs_table(conn)
        if end_ts and end_ts < start_ts:
            start_ts, end_ts = end_ts, start_ts
        if not end_ts:
            end_ts = time.time()
        if not start_ts:
            start_ts = end_ts - 3600
        if agent_id:
            rows = conn.execute(
                "SELECT received_at, event_count, "
                "COALESCE(payload_bytes, 0) AS payload_bytes FROM forwarded_logs "
                "WHERE received_at >= ? AND received_at <= ? AND agent_id = ? "
                "ORDER BY received_at",
                (start_ts, end_ts, agent_id),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT received_at, event_count, "
                "COALESCE(payload_bytes, 0) AS payload_bytes FROM forwarded_logs "
                "WHERE received_at >= ? AND received_at <= ? ORDER BY received_at",
                (start_ts, end_ts),
            ).fetchall()
    if not rows:
        return []
    buckets: dict[int, dict] = {}
    for r in rows:
        bkt = int(r["received_at"] - (r["received_at"] - start_ts) % bucket_seconds)
        if bkt not in buckets:
            buckets[bkt] = {"bucket_ts": bkt, "event_count": 0, "bytes": 0}
        buckets[bkt]["event_count"] += r["event_count"] or 0
        buckets[bkt]["bytes"] += r["payload_bytes"] or 0
    return sorted(buckets.values(), key=lambda b: b["bucket_ts"])


def alerts_timeseries(
    db_path: str = DB_PATH, start_ts: float = 0, end_ts: float = 0,
    bucket_seconds: int = 1, agent_id: str | None = None,
) -> list[dict]:
    """Aggregate alerts into time buckets for the graphs. Returns a list of
    {bucket_ts, alert_count} sorted by time. Optionally filtered by agent."""
    with get_conn(db_path) as conn:
        _ensure_alerts_table(conn)
        if end_ts and end_ts < start_ts:
            start_ts, end_ts = end_ts, start_ts
        if not end_ts:
            end_ts = time.time()
        if not start_ts:
            start_ts = end_ts - 3600
        if agent_id:
            rows = conn.execute(
                "SELECT received_at FROM alerts WHERE received_at >= ? AND received_at <= ? "
                "AND agent_id = ? ORDER BY received_at",
                (start_ts, end_ts, agent_id),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT received_at FROM alerts WHERE received_at >= ? AND received_at <= ? "
                "ORDER BY received_at",
                (start_ts, end_ts),
            ).fetchall()
    if not rows:
        return []
    buckets: dict[int, dict] = {}
    for r in rows:
        bkt = int(r["received_at"] - (r["received_at"] - start_ts) % bucket_seconds)
        if bkt not in buckets:
            buckets[bkt] = {"bucket_ts": bkt, "alert_count": 0}
        buckets[bkt]["alert_count"] += 1
    return sorted(buckets.values(), key=lambda b: b["bucket_ts"])


def savings_report(db_path: str = DB_PATH) -> list[dict]:
    """Return per-agent savings: how many events the host created vs. how
    many were forwarded to the server. The created/forwarded counters are
    reported by the agent on each poll and stored on the agents row.

    If a Metrics reset has been performed, each agent has a baseline
    snapshot in counter_baselines; the reported figures are the raw
    cumulative counters MINUS the baseline (clamped at 0), so the view
    shows activity since the reset. Agents without a baseline (never
    reset) report their raw cumulative values."""
    with get_conn(db_path) as conn:
        rows = conn.execute(
            "SELECT a.agent_id, a.hostname, a.ip_address, a.os_name, "
            "a.events_created, a.bytes_created, "
            "a.events_forwarded, a.bytes_forwarded, a.last_seen, "
            "b.events_created   AS base_events_created, "
            "b.bytes_created    AS base_bytes_created, "
            "b.events_forwarded AS base_events_forwarded, "
            "b.bytes_forwarded  AS base_bytes_forwarded "
            "FROM agents a "
            "LEFT JOIN counter_baselines b ON b.agent_id = a.agent_id "
            "ORDER BY a.hostname"
        ).fetchall()
        out: list[dict] = []
        for r in rows:
            d = dict(r)
            if d["base_events_created"] is not None:
                for raw, base in (("events_created", "base_events_created"),
                                  ("bytes_created", "base_bytes_created"),
                                  ("events_forwarded", "base_events_forwarded"),
                                  ("bytes_forwarded", "base_bytes_forwarded")):
                    d[raw] = max(0, (d[raw] or 0) - (d[base] or 0))
            for k in ("base_events_created", "base_bytes_created",
                      "base_events_forwarded", "base_bytes_forwarded"):
                d.pop(k, None)
            out.append(d)
        return out


# --- Admin seeding ----------------------------------------------------------

def _seed_admin(conn) -> None:
    """Seed the default admin user from env vars (idempotent upsert on
    username). Called from init_db. Logs a prominent warning if the password
    is the default 'admin' or unset; no forced change, just visibility."""
    username = os.environ.get("ELF_ADMIN_USER", "admin")
    password = os.environ.get("ELF_ADMIN_PASSWORD", "admin")
    weak = password in ("", "admin")
    if weak:
        print(
            "WARNING: ELF_ADMIN_PASSWORD is unset or 'admin'; the seeded "
            "admin account has a weak password. Set ELF_ADMIN_PASSWORD to a "
            "strong value and restart, or change the admin password from "
            "the Users tab.",
            flush=True,
        )
    existing = conn.execute(
        "SELECT id FROM users WHERE username = ?", (username,)
    ).fetchone()
    if existing is None:
        conn.execute(
            "INSERT INTO users (username, password_hash, role) VALUES (?, ?, 'admin')",
            (username, _hash_password(password)),
        )
    # If the admin already exists we do NOT overwrite the password; the
    # user may have changed it from the UI. Only insert on first run.
    if weak:
        # Record the weak-password state in the audit log for visibility.
        conn.execute(
            "INSERT INTO audit_log (actor, action, target, detail) "
            "VALUES ('system', 'auth.weak-password', ?, ?)",
            (username, json.dumps({"message": "Seeded admin has default/empty password"})),
        )


# --- Users (human auth + RBAC) ----------------------------------------------

def create_user(username: str, password: str, role: str = "viewer",
                db_path: str = DB_PATH) -> dict:
    """Create a new user. Raises sqlite3.IntegrityError if the username is
    taken. The caller is expected to validate password complexity before
    calling (the seeded admin is exempt; all other callers must enforce
    validate_password())."""
    with _lock, get_conn(db_path) as conn:
        cur = conn.execute(
            "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
            (username, _hash_password(password), role),
        )
        row = conn.execute(
            "SELECT id, username, role, created_at FROM users WHERE id = ?",
            (cur.lastrowid,),
        ).fetchone()
        return dict(row)


def get_user_by_username(username: str, db_path: str = DB_PATH) -> dict | None:
    """Return the full user row (including password_hash) for auth checks."""
    with get_conn(db_path) as conn:
        row = conn.execute(
            "SELECT * FROM users WHERE username = ?", (username,)
        ).fetchone()
        return dict(row) if row else None


def get_user(user_id: int, db_path: str = DB_PATH) -> dict | None:
    with get_conn(db_path) as conn:
        row = conn.execute(
            "SELECT id, username, role, created_at FROM users WHERE id = ?",
            (user_id,),
        ).fetchone()
        return dict(row) if row else None


def list_users(db_path: str = DB_PATH) -> list[dict]:
    """Return all users (without password hashes)."""
    with get_conn(db_path) as conn:
        rows = conn.execute(
            "SELECT id, username, role, created_at FROM users ORDER BY username"
        ).fetchall()
        return [dict(r) for r in rows]


def delete_user(user_id: int, db_path: str = DB_PATH) -> bool:
    """Delete a user. Returns True if a row was removed."""
    with _lock, get_conn(db_path) as conn:
        cur = conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
        return cur.rowcount > 0


def update_user_role(user_id: int, role: str,
                     db_path: str = DB_PATH) -> bool:
    with _lock, get_conn(db_path) as conn:
        cur = conn.execute(
            "UPDATE users SET role = ? WHERE id = ?", (role, user_id)
        )
        return cur.rowcount > 0


def verify_user_password(username: str, password: str,
                         db_path: str = DB_PATH) -> dict | None:
    """Verify a username/password pair. Returns the user row (without
    password_hash) on success, None on failure."""
    with get_conn(db_path) as conn:
        row = conn.execute(
            "SELECT * FROM users WHERE username = ?", (username,)
        ).fetchone()
        if row is None:
            return None
        if not _verify_password(password, row["password_hash"]):
            return None
        return {"id": row["id"], "username": row["username"], "role": row["role"]}


# --- Agent enrollment tokens (machine auth) ---------------------------------

def issue_agent_token(agent_id: str, db_path: str = DB_PATH) -> str:
    """Mint a new enrollment token for an agent. Returns the RAW token (only
    available once; the caller must deliver it to the agent immediately).
    Stores only the SHA-256 hash. Replaces any existing token for this agent
    (re-enroll). Also marks the agent as enrolled."""
    raw_token = secrets.token_urlsafe(32)
    token_hash = _hash_token(raw_token)
    now = time.time()
    with _lock, get_conn(db_path) as conn:
        # Upsert: replace the token if one exists, insert otherwise.
        conn.execute(
            "INSERT INTO agent_tokens (agent_id, token_hash, created_at, last_used) "
            "VALUES (?, ?, ?, NULL) "
            "ON CONFLICT(agent_id) DO UPDATE SET "
            "  token_hash = excluded.token_hash, "
            "  created_at = excluded.created_at, "
            "  last_used = NULL",
            (agent_id, token_hash, now),
        )
        conn.execute(
            "UPDATE agents SET enrolled = 1 WHERE agent_id = ?", (agent_id,)
        )
    return raw_token


def verify_agent_token(agent_id: str, token: str,
                       db_path: str = DB_PATH) -> bool:
    """Verify a raw token against the stored hash for an agent. Returns True
    on match. Updates last_used on success."""
    if not token:
        return False
    token_hash = _hash_token(token)
    now = time.time()
    with _lock, get_conn(db_path) as conn:
        row = conn.execute(
            "SELECT token_hash FROM agent_tokens WHERE agent_id = ?",
            (agent_id,),
        ).fetchone()
        if row is None:
            return False
        if row["token_hash"] != token_hash:
            return False
        conn.execute(
            "UPDATE agent_tokens SET last_used = ? WHERE agent_id = ?",
            (now, agent_id),
        )
        return True


def agent_has_token(agent_id: str, db_path: str = DB_PATH) -> bool:
    """Return True if the agent has an enrollment token issued."""
    with get_conn(db_path) as conn:
        row = conn.execute(
            "SELECT 1 FROM agent_tokens WHERE agent_id = ?", (agent_id,)
        ).fetchone()
        return row is not None


def revoke_agent_token(agent_id: str, db_path: str = DB_PATH) -> bool:
    """Delete the enrollment token for an agent (re-enroll prep). Returns
    True if a row was removed."""
    with _lock, get_conn(db_path) as conn:
        cur = conn.execute(
            "DELETE FROM agent_tokens WHERE agent_id = ?", (agent_id,)
        )
        conn.execute(
            "UPDATE agents SET enrolled = 0 WHERE agent_id = ?", (agent_id,)
        )
        return cur.rowcount > 0


# --- Audit log --------------------------------------------------------------

def write_audit(actor: str, action: str, target: str = "",
                detail: Any = None, db_path: str = DB_PATH) -> int:
    """Append an entry to the audit log. `actor` is a username or
    'agent:<agent_id>'. `action` is a dotted verb (rule.create, auth.login,
    ...). `target` is the affected entity id. `detail` is a JSON-serializable
    blob (prior value for updates, etc.). Returns the row id."""
    detail_str = json.dumps(detail) if detail is not None else ""
    with _lock, get_conn(db_path) as conn:
        # Ensure the table exists even when the caller hits write_audit
        # before init_db (e.g. a deny path during a fresh TestClient run).
        conn.executescript(
            "CREATE TABLE IF NOT EXISTS audit_log ("
            "  id INTEGER PRIMARY KEY AUTOINCREMENT,"
            "  ts REAL DEFAULT (strftime('%s','now')),"
            "  actor TEXT NOT NULL DEFAULT '',"
            "  action TEXT NOT NULL DEFAULT '',"
            "  target TEXT DEFAULT '',"
            "  detail TEXT DEFAULT ''"
            ")"
        )
        cur = conn.execute(
            "INSERT INTO audit_log (actor, action, target, detail) "
            "VALUES (?, ?, ?, ?)",
            (actor, action, target, detail_str),
        )
        return int(cur.lastrowid)


def get_audit_log(limit: int = 200, offset: int = 0,
                  db_path: str = DB_PATH) -> list[dict]:
    """Return recent audit entries, newest first."""
    with get_conn(db_path) as conn:
        rows = conn.execute(
            "SELECT id, ts, actor, action, target, detail "
            "FROM audit_log ORDER BY ts DESC, id DESC LIMIT ? OFFSET ?",
            (limit, offset),
        ).fetchall()
        return [dict(r) for r in rows]


def clear_audit(db_path: str = DB_PATH) -> int:
    """Delete all audit entries. Returns the number of rows removed.
    Also resets the AUTOINCREMENT counter so IDs restart at 1. The caller
    writes the audit.clear entry AFTER calling this so the trail shows the
    clear happened without the old entries reappearing."""
    with _lock, get_conn(db_path) as conn:
        cur = conn.execute("DELETE FROM audit_log")
        try:
            conn.execute("DELETE FROM sqlite_sequence WHERE name='audit_log'")
        except Exception:
            pass  # sqlite_sequence not created until AUTOINCREMENT is used
        return cur.rowcount
