"""Pydantic request/response models for the ELF management API."""

import re
from pydantic import BaseModel, Field, field_validator


# --- Agents -----------------------------------------------------------------

class AgentRegister(BaseModel):
    agent_id: str = Field(..., max_length=200)
    hostname: str = Field("", max_length=200)
    ip_address: str = Field("", max_length=100)
    os_name: str = Field("", max_length=200)
    group_id: int | None = None  # optional; assigned group on first registration


class AgentGroupAssignment(BaseModel):
    group_id: int


# --- Groups -----------------------------------------------------------------

class GroupCreate(BaseModel):
    name: str = Field(..., max_length=100)
    description: str = Field("", max_length=1000)

    @field_validator("name")
    @classmethod
    def _validate_name(cls, v: str) -> str:
        # Group names are used in file paths and display. Restrict them to
        # a safe charset to prevent path traversal and
        # XSS in the UI. Allow letters, digits, spaces, dash, underscore,
        # dot; no slashes, no angle brackets, no quotes.
        if not re.match(r"^[A-Za-z0-9 _.\-]+$", v):
            raise ValueError(
                "Group name may only contain letters, digits, spaces, "
                "dashes, underscores, and dots."
            )
        return v


DESTINATION_FORMATS = ("raw", "json", "ecs", "hec", "gelf", "sentinel")
_DEST_NAME_RE = re.compile(r"^[A-Za-z0-9_.\-]{1,64}$")
_DEST_QUERY_KEYS = {"format", "event", "token", "index", "sourcetype",
                    "tenant", "client", "secret", "insecure"}


def validate_destination(name: str, url: str) -> None:
    """Reject a destination the agent could not use. Mirrors the agent's
    parseDestinationUrl (src/Config.cpp): scheme file/http/https, optional
    ?format=... query with the SIEM options. Raises ValueError with a
    message naming the destination so the Groups tab can show it."""
    from urllib.parse import parse_qsl, urlsplit

    if not _DEST_NAME_RE.match(name or ""):
        raise ValueError(
            f"destination name '{name}' may only contain letters, digits, "
            "dot, dash and underscore (max 64)")
    if "://" not in (url or ""):
        raise ValueError(f"destination '{name}': URL must look like "
                         "file://..., http://... or https://...")
    scheme = url.split("://", 1)[0].lower()
    if scheme not in ("file", "http", "https"):
        raise ValueError(f"destination '{name}': unsupported scheme "
                         f"'{scheme}' (use file, http or https)")
    query = url.split("?", 1)[1] if "?" in url else ""
    opts = dict(parse_qsl(query, keep_blank_values=True))
    fmt = opts.get("format", "raw").lower()
    if fmt not in DESTINATION_FORMATS:
        raise ValueError(f"destination '{name}': unknown format '{fmt}' "
                         f"(one of {', '.join(DESTINATION_FORMATS)})")
    event = opts.get("event", "json").lower()
    if event not in ("json", "ecs"):
        raise ValueError(f"destination '{name}': event= must be json or ecs")
    insecure = opts.get("insecure", "") == "1"
    has_secret = any(opts.get(k) for k in ("token", "secret"))
    if fmt == "sentinel" and scheme != "file":
        if scheme != "https" and not insecure:
            raise ValueError(f"destination '{name}': format=sentinel "
                             "requires https://")
        for k in ("tenant", "client", "secret"):
            if not opts.get(k):
                raise ValueError(f"destination '{name}': format=sentinel "
                                 f"needs {k}= (secret may be env:VAR)")
    if scheme == "http" and has_secret and not insecure:
        raise ValueError(
            f"destination '{name}': a token/secret over plain http:// is "
            "only allowed with insecure=1 (lab use); use https://")
    if fmt == "hec" and scheme != "file" and not opts.get("token"):
        raise ValueError(f"destination '{name}': format=hec needs token=")
    if scheme == "file":
        path = url[len("file://"):].split("?", 1)[0]
        if not path or path.endswith("/") or path.endswith("\\"):
            raise ValueError(f"destination '{name}': file:// URL needs a "
                             "file name")
        if ".." in path.replace("\\", "/").split("/"):
            raise ValueError(f"destination '{name}': file:// path may not "
                             "contain '..'")
    else:
        parts = urlsplit(url)
        if not parts.hostname:
            raise ValueError(f"destination '{name}': URL has no host")


class GroupUpdate(BaseModel):
    name: str | None = Field(None, max_length=100)
    description: str | None = Field(None, max_length=1000)
    retention_seconds: int | None = None
    poll_interval_seconds: int | None = None
    # Ordered list of {name, url} destinations. Replaces the full set on
    # update (send an empty list to clear all destinations).
    destinations: list[dict] | None = None

    @field_validator("destinations")
    @classmethod
    def _validate_destinations(cls, v):
        if v is None:
            return v
        seen = set()
        out = []
        for d in v:
            if not isinstance(d, dict):
                raise ValueError("each destination must be {name, url}")
            name = str(d.get("name", "")).strip()
            url = str(d.get("url", "")).strip()
            validate_destination(name, url)
            if name in seen:
                raise ValueError(f"destination '{name}' is listed twice")
            seen.add(name)
            out.append({"name": name, "url": url})
        return out
    # Mirror forwarded logs to the ELF server (per-group toggle). False is
    # meaningful (alerts still mirror; only log batches stop), so the UI
    # must always send the bool; exclude_none on the server keeps None
    # ("don't change") from clearing it.
    mirror_logs: bool | None = None


# --- Settings ----------------------------------------------------------------

class SettingsUpdate(BaseModel):
    """PUT /settings body. Currently only the max logs.txt size is
    configurable: max_logs_text_mb caps the forwarded-logs text file by
    trimming the OLDEST lines after each append. 0 = unlimited."""
    max_logs_text_mb: int = Field(..., ge=0, le=10240)


# --- Rules ------------------------------------------------------------------

class RuleUpsert(BaseModel):
    rule_id: str = Field(..., max_length=200)
    name: str = Field("", max_length=300)
    description: str = Field("", max_length=2000)
    severity: str = Field("medium", max_length=50)
    enabled: bool = True
    yaml_body: str = Field(..., max_length=1024 * 1024)  # 1 MB ceiling


class BulkRuleDelete(BaseModel):
    """UI -> server: delete many rules from one group in a single request.
    `rule_ids` is the list of Sigma `id` values (the DB primary key) to
    remove. An empty list is rejected by the endpoint (no-op) so a stray
    request can't silently delete nothing."""
    rule_ids: list[str] = Field(..., max_length=1000)


# --- Lists (reusable value lists, global across all groups) -----------------

class ListUpsert(BaseModel):
    name: str = Field(..., max_length=100)
    content: str = Field("", max_length=10 * 1024 * 1024)  # 10 MB ceiling


# --- Ingest (alerts / logs from agents) -------------------------------------

class AlertReport(BaseModel):
    rule_id: str = Field("", max_length=200)
    message: str = Field("", max_length=2000)
    level: str = Field("", max_length=50)  # Sigma severity: critical|high|medium|low|informational
    received_at: str = Field("", max_length=100)
    event_xml: str = Field("", max_length=1024 * 1024)  # 1 MB per event XML
    # Sequence rules include ALL events that formed the sequence (the full
    # attack chain), not just the trigger. Empty for simple/threshold rules.
    sequence_events: list[str] = Field(default_factory=list)
    # Threshold rules include the events that filled the sliding window
    # (all counted events, or one representative per unique value for
    # `distinct` rules), not just the trigger. Empty for simple/sequence
    # rules. Kept separate from sequence_events so the UI can label the
    # items correctly (Stage N for chains, Event N for windows).
    window_events: list[str] = Field(default_factory=list)
    # The agent caps the evidence lists (it keeps the most recent N events)
    # so a huge window never becomes a huge POST. These carry the number of
    # older events it left out, so the UI can say "(N more not shown)".
    sequence_events_truncated: int = Field(0, ge=0)
    window_events_truncated: int = Field(0, ge=0)
    # Ids of lower-severity Simple rules that matched the same event but
    # were suppressed by the agent's severity selection (only the highest
    # severity rule alerts per event). Recorded so no detection is invisible.
    # Pydantic drops unknown fields, so this must be declared to survive.
    also_matched: list[str] = Field(default_factory=list, max_length=200)
    # Id of the rule fire (16 hex chars from the agent). The same value is
    # on the forward_buffer batch of that fire, so alert and context join.
    alert_id: str = Field("", max_length=64)


class LogReport(BaseModel):
    rule_id: str = Field("", max_length=200)
    event_count: int = 0
    events: list[str] = Field(default_factory=list, max_length=10000)
    # Per-event rule attribution: one rule_id per event in `events`, in the
    # same order. Present when a single batch spans multiple rules (e.g.
    # forward_event batches). Lets the server attribute each forwarded log
    # to the rule that sent it. Empty for forward_buffer batches (single
    # rule_id applies to all events).
    rule_ids: list[str] = Field(default_factory=list, max_length=10000)
    # Id of the rule fire that produced this batch (empty for
    # forward_event streams and on-demand collections).
    alert_id: str = Field("", max_length=64)


# --- On-demand log collection (collect logs command + result) --------------

class CollectRequest(BaseModel):
    """UI -> server: request a historical log pull from a host starting at
    `start_time` (ISO-8601, local or with offset; the server normalizes to UTC
    before storing)."""
    start_time: str = Field(..., max_length=100)


class CollectBatch(BaseModel):
    """Agent -> server: one streamed batch of collected events. The agent
    posts these as it pages through the historical query so a large pull does
    not have to complete before the first events arrive."""
    agent_id: str = Field(..., max_length=200)
    batch_index: int = 0
    event_count: int = 0
    events: list[str] = Field(default_factory=list, max_length=10000)


class CollectDone(BaseModel):
    """Agent -> server: final result of a collect command. `status` is
    'done' on success or 'failed' (with `error`) on failure."""
    agent_id: str = Field(..., max_length=200)
    status: str = Field(..., max_length=50)
    events_collected: int = 0
    batches: int = 0
    error: str | None = Field(None, max_length=2000)


# --- Install script generation (Add New Agent modal) ------------------------

class InstallScriptRequest(BaseModel):
    """UI -> server: options for the generated install .ps1.

    account_mode:
      * 'local':  the script creates a dedicated least-privilege LOCAL user
                   (the original behavior; fully self-contained).
      * 'domain': the service runs as an EXISTING domain account. The
                   operator supplies domain\\username; the script prompts for
                   the password SECURELY at run time (Read-Host -AsSecureString
                   in an interactive window) so the password never lands in
                   the script, the clipboard, or the server DB. The account
                   must already have the required rights on the target host
                   (see the docs: Log on as a service, read the Security
                   event log, local ACL on the data dir).
    """
    group: str = Field(..., max_length=100)
    # Target operating system: 'windows' (PowerShell script) or 'linux'
    # (bash script, systemd unit).
    os: str = Field("windows", max_length=10)
    # Windows: local | domain. Linux: local (dedicated system user) |
    # existing (an account already on the host, named in `username`).
    account_mode: str = Field("local", max_length=20)
    # DOMAIN\\username for account_mode='domain'; the account name for
    # account_mode='existing'. Empty for 'local'.
    domain: str = Field("", max_length=100)
    username: str = Field("", max_length=100)
    # Linux only: also install an auditd rule that records program
    # executions, so process_creation rules have events.
    audit_execve: bool = False

    @field_validator("os")
    @classmethod
    def _validate_os(cls, v: str) -> str:
        v = v.strip().lower()
        if v not in ("windows", "linux"):
            raise ValueError("os must be 'windows' or 'linux'")
        return v

    @field_validator("account_mode")
    @classmethod
    def _validate_mode(cls, v: str) -> str:
        if v not in ("local", "domain", "existing"):
            raise ValueError("account_mode must be 'local', 'domain' or 'existing'")
        return v

    @field_validator("domain", "username")
    @classmethod
    def _validate_account(cls, v: str) -> str:
        # Block the characters that break the generated PowerShell string
        # literals and sc.exe argument parsing: quotes, backticks, dollar,
        # semicolons, parens, and control chars. (The backslash in
        # DOMAIN\user is fine and expected.)
        if re.search(r"""["'`$;(){}\[\]&|<>^!]""", v):
            raise ValueError(
                "Domain/username contains characters that are not allowed "
                "(letters, digits, dash, underscore, dot, and the DOMAIN\\ "
                "separator only)."
            )
        if any(ord(c) < 32 for c in v):
            raise ValueError("Domain/username must not contain control characters.")
        return v


# --- Agent-facing response shapes -------------------------------------------

class AgentConfig(BaseModel):
    """What an agent receives from GET /config/{agent_id}. The agent applies
    these settings locally (overriding config.ini where the server is the
    source of truth)."""
    agent_id: str
    hostname: str
    group_name: str
    retention_seconds: int
    poll_interval_seconds: int
    destinations: dict[str, str]
    rules: list[dict]


# --- Auth (human login + user management) -----------------------------------

def _password_fits_bcrypt(v: str) -> str:
    # bcrypt hashes at most 72 bytes of input; reject longer passwords with a
    # clear message instead of a server error.
    if len(v.encode("utf-8")) > 72:
        raise ValueError("Password must be at most 72 bytes.")
    return v


class LoginRequest(BaseModel):
    """POST /auth/login body."""
    username: str = Field(..., max_length=100)
    password: str = Field(..., max_length=1000)

    @field_validator("password")
    @classmethod
    def _password_len(cls, v: str) -> str:
        return _password_fits_bcrypt(v)


class UserCreate(BaseModel):
    """POST /users body. Password complexity is enforced server-side via
    validate_password() (the seeded admin is exempt)."""
    username: str = Field(..., max_length=100)
    password: str = Field(..., max_length=1000)
    role: str = "viewer"  # admin | rule_contributor | viewer

    @field_validator("password")
    @classmethod
    def _password_len(cls, v: str) -> str:
        return _password_fits_bcrypt(v)

    @field_validator("username")
    @classmethod
    def _validate_username(cls, v: str) -> str:
        if not re.match(r"^[A-Za-z0-9_.\-]+$", v):
            raise ValueError(
                "Username may only contain letters, digits, dashes, "
                "underscores, and dots."
            )
        return v

    @field_validator("role")
    @classmethod
    def _validate_role(cls, v: str) -> str:
        if v not in ("admin", "rule_contributor", "viewer"):
            raise ValueError("Role must be one of: admin, rule_contributor, viewer.")
        return v


class UserRoleUpdate(BaseModel):
    """PUT /users/{id}/role body."""
    role: str

    @field_validator("role")
    @classmethod
    def _validate_role(cls, v: str) -> str:
        if v not in ("admin", "rule_contributor", "viewer"):
            raise ValueError("Role must be one of: admin, rule_contributor, viewer.")
        return v
