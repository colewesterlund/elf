# Efficient Log Forwarder (ELF): User Guide

An agent for Windows and Linux hosts that subscribes to the host's log (the Windows Event Log, or the systemd journal on Linux), evaluates **Sigma-format detection rules** against the live event stream, and forwards matching events / alerts / buffers to file or HTTP destinations. A management server (FastAPI) holds the authoritative copy of the rules and per-agent config.

---

## 1. Requirements

### Agent (Windows)
- **Windows 10/11 or Windows Server 2016+** (uses `wevtapi` push subscriptions)
- **CMake ≥ 3.20**
- **C++17 compiler** (MSVC recommended; the project links `wevtapi` and `winhttp`)
- **Internet access on first build**: `yaml-cpp 0.8.0` and `nlohmann/json v3.11.3` are pulled via CMake `FetchContent`
- **Administrator privileges to install**: the installer creates a local user, grants privileges, and registers a Windows service. Once installed, the service runs as a dedicated low-privilege account (no admin rights needed at runtime).

### Agent (Linux)
- A distribution with **systemd** (the agent reads the journal through `libsystemd`); tested on Ubuntu 24.04 and 26.04, built in CI on `ubuntu-latest`
- To build: `cmake`, `g++`, `pkg-config`, `libsystemd-dev`, `libcurl4-openssl-dev` (Debian/Ubuntu names)
- **root to install**: the install script creates the `elf` system user, the directories and the systemd unit. The service itself runs as that user with membership in `systemd-journal`.
- For `process_creation` rules: **auditd** with an `execve` audit rule, and journald's audit socket enabled. The install script's audit option sets both up (see §4.0.2).

### Management Server (Linux, Docker)
- Docker + Docker Compose
- See `server/` for the FastAPI app, `docker-compose.yml`, and `Dockerfile`

---

## 2. Build the Agent

From the repository root:

```powershell
cmake -B build -S .
cmake --build build --config Release
```

The executable is produced at `build\Release\efficient_log_forwarder.exe`.

Build artifacts also copy `config.ini` and the `rules/` directory next to the binary, but the agent is designed to run from the **repository root** (it uses relative paths for `rules/`, `output/`, and `config.ini`).

### Build the tests
Tests are built by the default target. Run them with:

```powershell
cd build\Release
.\test_rule_engine.exe
```

### Build on Linux

```bash
sudo apt-get install -y cmake g++ pkg-config libsystemd-dev libcurl4-openssl-dev
cmake -S . -B build -DCMAKE_POLICY_VERSION_MINIMUM=3.5 -DCMAKE_BUILD_TYPE=Release
cmake --build build -j"$(nproc)"
(cd build && ./test_rule_engine)
```

The executable is `build/efficient_log_forwarder`; the install script and
the console call it `elf-agent`. The same harness runs on both platforms:
the Event Log subscription tests only on Windows, the journal renderer and
audit joiner tests only on Linux. To install a locally built binary without
a console, use `packaging/linux/install.sh` (it writes the unit file next
to it, `packaging/linux/elf-agent.service`).

---

## 3. Configuration (`config.ini`)

The agent reads `config.ini` from its working directory at startup. This is the **bootstrap** config; the management server can override `retention_seconds`, destinations, and the ruleset at runtime (see §6).

```ini
[buffer]
retention_seconds=30          # events older than this are dropped from the buffer (the server can override it per group)
max_events=50000              # size cap on the buffer regardless of age; 0 = no cap (about 3 KB per event in memory)

[rules]
directory=rules               # local directory holding *.yaml Sigma rules

[lists]
directory=lists               # local directory holding *.txt reusable lists (see §7)

[server]
url=http://localhost:8000     # management server base URL
poll_interval_seconds=30      # how often to pull config + rules from the server
agent_id=                     # unique identity for this agent (the install script fills this in)

[logging]
level=notice                  # error | notice | info | debug (default notice)
max_file_size_mb=1            # rotate elf_agent.log when it exceeds this (0 = no rotation)
max_files=3                   # keep this many rotated .1/.2/.N copies (0 = none)
# directory=                  # optional override; default %ProgramData%\ELFAgent\logs\

[spool]
max_spool_mb=100              # cap the disk-backed pending-POST queue at this size
# directory=                  # optional override; default %ProgramData%\ELFAgent\spool\

[destinations]
siem = file://./output/siem.jsonl
data_lake = file://./output/data_lake.jsonl
alerts = file://./output/alerts.jsonl

# Optional: explicit channel subscription list (see §4 XPath filtering).
# When non-empty, the agent subscribes to EXACTLY these channels (the
# auto-derived channels from rules are ignored). When omitted/empty, the
# agent auto-derives channels from the loaded rules. Catch-all rules always
# force a full subscribe-all regardless of this setting.
# [collect]
# channels = Security, Microsoft-Windows-Sysmon/Operational
```

### `[logging]`: log verbosity and rotation
Controls the agent's own diagnostic log (not the forwarded events). The agent
writes two files under `%ProgramData%\ELFAgent\logs\`:
- `elf_agent.log`: all messages at or above `level`.
- `error.log`: ERROR messages only (always, regardless of `level`).

| Key | Default | Meaning |
|-----|---------|---------|
| `level` | `notice` | Minimum severity to emit. `error` = errors only; `notice` = startup/shutdown/alerts; `info` = per-event detail; `debug` = everything. |
| `max_file_size_mb` | `1` | Rotate `elf_agent.log` when it exceeds this many MB. `0` = no rotation. |
| `max_files` | `3` | Number of rotated `.1`/`.2`/`.N` copies to keep. `0` = keep none. |
| `directory` | *(ProgramData)* | Optional override for the log directory. |

With the defaults (1MB × 3 copies), the agent log is bounded at ~4MB,
which suits unattended service operation on thousands of hosts.

### `[spool]`: disk-backed pending-POST queue
When the management server is unreachable, the agent persists pending POSTs
(alerts + forwarded logs) to a disk-backed spool under
`%ProgramData%\ELFAgent\spool\` so they survive a restart or network outage.
The sender thread retries with exponential backoff (1s→60s, reset on success).

How the spool behaves (all of this is automatic):

- **Ack after success.** An entry stays on disk until the server has accepted
  it (2xx). A crash mid-POST re-sends it on the next start (at-least-once).
- **Permanent rejections are dropped, not retried.** A `4xx` other than 408/429
  (e.g. `401` revoked token, `422` oversized batch) can never succeed; the agent
  logs `Dropping POST ... HTTP <status>` with the server's response text and moves
  on, so one rejected entry never blocks the alerts queued behind it.
- **Big batches are split.** A `forward_buffer` dump is sent as `POST /logs`
  chunks of at most 2,000 events / 4 MB (the server accepts 10,000), and alert
  evidence (`window_events` / `sequence_events`) is capped at the most recent 500
  with a `*_truncated` count.
- **Eviction is logged.** When the cap is hit, one line reports how many of the
  oldest entries were evicted; a single body larger than half the cap is refused.
- **Shutdown never waits on the server.** Pending entries stay on disk.
- **`http://` SIEM destinations use a second, independent spool**
  (`spool\destinations\`), so a dead SIEM never blocks alerts to the management
  server and the rule-engine thread never waits on a SIEM.

| Key | Default | Meaning |
|-----|---------|---------|
| `max_spool_mb` | `100` | Max total spool size. Beyond this, the **oldest** entries are evicted (dropped), since the oldest events are the least valuable to an analyst. `0` = unbounded (not recommended). |
| `directory` | *(ProgramData)* | Optional override for the spool directory. |

### `[paths]`: writable data root (optional)
| Key | Default | Meaning |
|-----|---------|---------|
| `data_directory` | `%ProgramData%\ELFAgent` (Windows), `/var/lib/elf` (Linux) | Directory that **relative** `file://` destination paths resolve against. The install script never needs this; it exists for dev/test layouts. |

On Linux the agent reads `config.ini` from `$ELF_CONFIG`, else next to the
binary, else `/etc/elf/config.ini` (what the install script writes). The
data root can also be set with `ELF_DATA_DIR`; when `/var/lib/elf` is not
writable (a `--debug` run as a normal user) the agent falls back to
`~/.elf/` and says so.

### Destination URL schemes
| Scheme | Behavior |
|--------|----------|
| `file://output/siem.jsonl` (relative) | Append one line per event to the file **under the agent data directory** (`%ProgramData%\ELFAgent\output\siem.jsonl`). A leading `./` is accepted. The install directory (`Program Files`) is read-only for the service account and is never used. |
| `file:///C:/logs/siem.jsonl` (absolute) | Append to that exact path (`file://C:\logs\siem.jsonl` also works). On Linux: `file:///var/lib/elf/output/siem.jsonl`. |
| `http://host:port/path`, `https://…` | POST via WinHTTP (Windows) or libcurl (Linux), through the destination spool (see `[spool]`). |

Destinations are **named** in `config.ini` and referenced by name from rule `actions` (see §5). Server-pushed destinations (Groups tab) follow the same resolution rules. A rule action that names a destination not present in `config.ini` is skipped with an error line.

### Destination output formats (`?format=`)

Append a query string to any destination URL to choose the document shape. ELF consumes the known keys and strips them from the request URL; unknown keys pass through to the endpoint.

| `format` | Document | Delivery | Auth / options |
|---|---|---|---|
| `raw` (default) | Windows event XML, one per line; alerts as a text header + pretty XML | file append / one POST per action | none |
| `json` | ELF flat JSON: `@timestamp`, `host`, `channel`, `event_id`, `event_data.*`, `elf.{kind,action,rule_id,rule_name,level,category,message,evidence}` | NDJSON, chunked ≤1,000 docs / 2 MB per POST | `token=` → `Authorization: Bearer <token>` |
| `ecs` | Elastic Common Schema (winlogbeat shape): `event.*`, `process.*`, `user.*`, `source.*`/`destination.*`, `winlog.event_data.*`; alerts add `rule.*`, `event.severity`, `threat.technique.id[]`, `threat.tactic.name[]` | same | same |
| `hec` | Splunk HTTP Event Collector envelope `{time, host, source:"elf", sourcetype, index?, event}` | envelopes concatenated, ≤1,000 per POST | `token=` → `Authorization: Splunk <token>`; `index=`, `sourcetype=` (default `elf:event` / `elf:alert`), `event=json|ecs` |
| `gelf` | Graylog GELF 1.1 (`version`, `host`, `short_message`, `timestamp`, `level`, flat `_elf_*` and `_event_data_*` fields) | one POST per message | none |
| `sentinel` | Azure Monitor Logs Ingestion rows (`TimeGenerated`, `Host`, `EventId`, `EventData`, `RuleId`, …) | JSON array ≤1,000 rows / 1 MB | `tenant=`, `client=`, `secret=` (OAuth2 client credentials, fetched by the agent at send time) |

Secrets: `token=env:VAR` and `secret=env:VAR` read the value from the service environment. A token over plain `http://` is rejected by the server unless `insecure=1` is set (lab only; on `https://` the same flag also disables certificate validation). The stripped URL is what the agent logs, so a token never appears in `error.log`. Step-by-step recipes for Splunk, Graylog and Microsoft Sentinel are in [SIEM.md](SIEM.md).

---

## 4. Running the Agent

The agent has two modes: **service** (production) and **console** (debugging).

### 4.0 Service mode (production)

In production the agent runs as a least-privilege Windows service. It
auto-starts on boot, restarts on crash, and is invisible to normal users.
Install it via the management server's **+ Add New Agent** button (generates
a PowerShell install script). For GPO/SCCM fleets, deploy the same script
as a computer-startup script.

**Service account: two modes** (chosen in the Add New Agent form):

* **Local account (default).** The script creates a dedicated local user
  (`ELFAgent`) with a random password on the target host. Nothing to
  prepare in advance; the cleanup script deletes the account when you
  remove the agent.
* **Existing domain account.** For domain-joined hosts: the service runs
  as an AD service account you create once (e.g. `CORP\svc-elf-agent`) and
  reuse on every host. The script prompts for the account's password
  **securely at install time** on the target host (`Read-Host
  -AsSecureString`, masked input); the password is never stored in the
  script, the clipboard, or the management server. See §4.0.1 for how to
  create the account and which rights it needs.

**Install via the server UI:**
1. In the web UI, click **+ Add New Agent**, pick a group, choose the
   service-account mode (and enter `DOMAIN` + `username` for domain mode),
   click **Generate**.
2. Use **Copy** or **Download .ps1**.
3. On the target host, open an elevated PowerShell prompt and run the
   script (paste it, or run the downloaded `install-elf-agent.ps1`).

The script downloads the exe to `Program Files\ELFAgent`, creates the
`%ProgramData%\ELFAgent\` state tree, provisions the service account
(creating the local `ELFAgent` user, or granting the domain account the
same local rights), grants `SeServiceLogonRight` + `SeSecurityPrivilege` +
Event Log Readers, ACLs the data dir so only SYSTEM + the service account
can read it, writes `config.ini`, and installs + starts the service.

**Service management:**
```powershell
Get-Service ELFAgent              # status
Start-Service ELFAgent            # start
Stop-Service ELFAgent             # stop
sc.exe query ELFAgent             # detailed status
sc.exe failure ELFAgent           # recovery actions
Get-EventLog -LogName Application -Source ELFAgent  # (if event log used)
```

**Uninstall:**
```powershell
# PowerShell-installed: use the generated cleanup script (Add New Agent
# modal → Troubleshooting). It removes the service, the local ELFAgent
# account, group memberships, LSA rights (including those granted to a
# domain account on that host), and both directories. Or manually:

# If the service is stuck in "stopping" (hung agent process), kill the
# process FIRST; the SCM never force-kills a service on its own:
$svcPid = (Get-CimInstance Win32_Service -Filter "Name='ELFAgent'").ProcessId
if ($svcPid -and (Get-Process -Id $svcPid -ErrorAction SilentlyContinue)) {
    Stop-Service ELFAgent -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 5
    if (Get-Process -Id $svcPid -ErrorAction SilentlyContinue) {
        taskkill /F /PID $svcPid
    }
}
sc.exe delete ELFAgent; Remove-LocalUser ELFAgent
Remove-Item -Recurse "C:\Program Files\ELFAgent"
Remove-Item -Recurse "$env:ProgramData\ELFAgent"   # optional: keeps state
```

### 4.0.2 Linux service (systemd)

Pick **Linux** in the Add New Agent form. Paste the whole generated script
into a shell on the host, or save it as `install-elf-agent.sh` and run it
with `bash`. It asks for your sudo password once; the body runs in one
root shell, so a paste is collected before anything runs and an error ends
the install rather than your session. It:

1. downloads `elf-agent` from the console into `/opt/elf/`;
2. creates the `elf` system user (no shell, no home) or uses the existing
   account you named, and adds it to `systemd-journal` so it can read the
   journal;
3. creates `/var/lib/elf/` (`logs`, `spool`, `state`, `rules`, `lists`,
   `output`), owned by that user and private to it;
4. registers the agent with the console (`agent_id` = the host's short
   name) and writes `/etc/elf/config.ini` with the auth token;
5. installs `elf-agent.service` (starts at boot, restarts on failure,
   `ProtectSystem=strict` with `/var/lib/elf` the only writable path) and
   starts it.

Tick **Also add an auditd rule that records program executions** when the
group's rules include `process_creation` rules. The kernel audit stream is
what carries program starts on Linux; the option enables journald's audit
socket (Debian and Ubuntu ship it disabled), sets `Audit=yes`, and installs
an `execve` rule under `/etc/audit/rules.d/`. Without it the agent still
sees every syslog line (sshd, sudo, cron, useradd, ...) but no process
starts.

```bash
systemctl status elf-agent            # state and the last log lines
journalctl -u elf-agent -n 50         # notices and errors (the journal is the console sink)
tail -f /var/lib/elf/logs/elf_agent.log
sudo /opt/elf/elf-agent --debug       # foreground run with the service's config
```

The **cleanup script** (same dialog, Linux selected) removes the unit, the
directories, the audit rule and the `elf` user.

**Channels on Linux.** A Sigma `service:` maps to the journal's syslog
identifier: `sshd` (also `sshd-session`), `sudo`, `cron` (`CRON`, `crond`),
`kernel`, `systemd`, `auditd` (the kernel audit transport, channel `audit`),
and `syslog`/`auth`/`authpriv`/`messages` for the whole journal. The agent
subscribes with journal matches, so only entries from those identifiers
leave journald. A `[collect] channels=` override lists identifiers.

### 4.0.1 Creating a domain service account (domain mode)

Run once on a Domain Controller (or create it via AD Users and Computers):

```powershell
New-ADOrganizationalUnit -Name "Service Accounts" -Path "DC=corp,DC=local"
$pw = Read-Host "Password" -AsSecureString
New-ADUser -Name "svc-elf-agent" `
  -Path "OU=Service Accounts,DC=corp,DC=local" `
  -AccountPassword $pw `
  -PasswordNeverExpires $true `
  -CannotChangePassword $true `
  -Enabled $true `
  -Description "ELF agent service account (log forwarder)"
```

The account needs these rights **on each target host**. The install
script grants all of them automatically, so you only need to make sure no
GPO *denies* them:

| Right / permission | Why | Granted by |
|---|---|---|
| `SeServiceLogonRight` (Log on as a service) | SCM must start the service as this account | Install script (LSA grant) |
| `SeSecurityPrivilege` (Manage auditing and security log) | Read the **Security** event channel | Install script (LSA grant) |
| Local **Event Log Readers** member | Read System/Application/… channels | Install script (`net localgroup`) |
| Write access to `%ProgramData%\ELFAgent` | Logs, spool, bookmarks, rules | Install script (directory ACL) |

> **GPO caveat:** if a domain GPO defines *Deny log on as a service* or
> restricts *Log on as a service* to an explicit list, add the service
> account to that list (or exclude its OU). A GPO deny overrides the
> local grant and the service fails with **error 1069**.

Do **not** make the account a Domain Admin or local Administrator; the
agent deliberately runs least-privilege. If the account's password is
rotated in AD, re-run the install script (or `sc.exe config ELFAgent
password= ...`).

### 4.1 Console mode (debugging)

For development/debugging, run the exe directly from the **repository root**
(so relative paths resolve):

```powershell
.\build\Release\efficient_log_forwarder.exe
```

In console mode the agent prints status to the terminal and responds to
`Ctrl+C`. It does **not** install or register a service. Run as Administrator
if you need the Security channel (the service account has this right; a
console user must elevate).

### What the agent does on startup
1. Loads `config.ini`.
2. Loads all `*.yaml` rules from the `rules/` directory.
3. **Derives a per-channel XPath subscription filter from the loaded rules** (see §4.2 XPath Filtering) and subscribes to only the channels the rules reference, asking Windows to deliver only the EventIDs the rules select. Falls back to subscribing to all channels with no filter when catch-all rules are present or when `[collect] channels` is empty and no rules declare a `logsource`.
4. **Loads any saved event bookmarks** from `%ProgramData%\ELFAgent\state\bookmarks\` and resumes from the last-processed event per channel (no events lost across restarts).
5. **Loads any pending spooled POSTs** from `%ProgramData%\ELFAgent\spool\` and queues them for retry before new collection begins.
6. **Disables Windows console QuickEdit mode** on the input handle (console mode only) so clicking in the console window can't pause output.
7. Starts worker threads:
   - **Buffer cleanup**: drops events older than `retention_seconds` (checks every 1s).
   - **Rule engine**: evaluates rules against new events every 2s.
   - **Rule reload**: re-reads the `rules/` directory every 60s (hot reload). After a reload (or a server-driven ruleset change), the agent **re-derives the XPath filter and re-subscribes** so the subscription always tracks the active ruleset.
   - **Server poll**: contacts the management server every `poll_interval_seconds` to pull config + rules.
   - **Bookmark save**: persists per-channel event-log positions every 30s + on shutdown.
   - **Spool worker**: drains the disk-backed pending-POST queue with exponential backoff.

### Console output
- `[STATUS] Buffered events: N`: current buffer size.
- `[ALERT] ...`: printed when an alert action fires.
- `[Reload] Ruleset refreshed: N rule(s) active.`: hot reload from disk.
- `[AgentClient] Reloaded N rule(s) from server.`: rules pulled from server.

### 4.2 XPath Subscription Filtering

By default the agent does **not** subscribe to every Windows event channel and read every event. Instead it **auto-derives a per-channel XPath query** from the loaded rules so Windows only delivers events the rules can possibly match. On a busy Domain Controller in a three-host lab this cut the agent's event load by ~90% (most channels and most EventIDs on a channel are irrelevant to the loaded ruleset).

**How it works:**
1. For each enabled rule, the agent determines which Windows channels it can match (from `logsource.service` via the service→channel map, or from `logsource.category` via the category→channel map).
2. For each channel, it unions the `EventID` values the rules select into one set. The ids are derived from the rule's **compiled condition**, not from a blind field walk: `a and b` with an `EventID` only in `a` is still restricted to `a`'s ids, but `a or b` is not (b can match any EventID), and `not filter` never restricts.
3. A **category rule with no explicit `EventID`** (most SigmaHQ rules: `category: process_creation` and similar) still gets a selective filter: the engine knows which EventIDs each category means on each channel (`process_creation` → Security 4688, Sysmon 1; `registry_event` → Sysmon 12/13/14 + Security 4657; `ps_script` → 4104; …).
4. It builds the per-channel query and passes it to `EvtSubscribe`. Up to 20 ids this is the flat form `*[System[EventID=4624 or EventID=4625 or ...]]`. **Windows rejects a predicate with more than 23 `EventID=` terms** (`ERROR_EVT_INVALID_QUERY`, 15001), so beyond 20 the agent emits a structured `<QueryList><Query><Select Path="…">…</Select>…</Query></QueryList>` with one `<Select>` per 20 ids; that form has no practical limit (tested with hundreds of selects).
5. If Windows still rejects a filtered query, the agent logs it and **falls back to `*` for that channel** instead of leaving the channel unsubscribed (a rule-referenced channel is never silently dropped).
6. A channel that ends up with no derivable `EventID` at all gets `*` (all events); the rule engine filters in-process. The rule(s) responsible are listed in the log (`Rules forcing an unfiltered (*) channel subscription`), so an operator can tighten them.

**Catch-all rules disable filtering.** A rule with no `logsource` (a true catch-all) can match any event on any channel, so XPath pre-filtering is impossible. When any catch-all rule is loaded, the agent falls back to subscribing to all channels with no filter (`*`). This is the correctness guard: XPath filtering never drops an event a rule could match.

**Re-subscription only when something changed.** After a ruleset change the agent re-derives the channel/EventID set; if it equals the active set, nothing is torn down (every real resubscribe closes and reopens every channel, a brief delivery gap). The 60 s disk watcher likewise only reloads when a rule or list file actually changed on disk, and the server poll skips the whole rewrite/reload/resubscribe cycle when the server reports the ruleset hash it already runs (see §9).

**Overriding with `[collect] channels`.** The optional `[collect]` section in `config.ini` lets you force a fixed list of channels to subscribe to (with all events on each, no EventID filter), ignoring the auto-derived channels. This is useful when you want to collect from channels no rule references yet, or for testing. When `[collect] channels` is non-empty, the agent subscribes to exactly those channels; when empty/omitted, it auto-derives from the rules. Catch-all rules still force a full subscribe-all regardless.

```ini
[collect]
# Subscribe to exactly these channels (all events), ignoring auto-derivation:
channels = Security, Microsoft-Windows-Sysmon/Operational, Microsoft-Windows-PowerShell/Operational
```

---

## 5. Sigma Rules + ELF Extensions

Rules are **standard Sigma YAML** with an added top-level `elf:` block for ELF-specific correlation and action features. A rule file in `rules/` must contain exactly **one** detection.

### Standard Sigma fields (required)
```yaml
title: <display name>           # shown in the UI
id: <unique-id>                 # the Sigma id (may differ from the DB rule_id)
status: stable                  # stable | test | experimental | deprecated | unsupported
description: <text>
level: high                     # critical | high | medium | low | informational
author: <name>
date: 2026-10-01
tags:
  - attack.credential_access
  - attack.t1110
logsource:
  product: windows
  service: security             # Windows channel name
detection:
  selection:
    EventID: 4688
    Image|contains: calc.exe
  condition: selection
falsepositives:
  - Legitimate use
```

### ELF extension block (`elf:`)
This is where the **ELF addons** live. The features needed for the addons to work:

| Key | Required for | Description |
|-----|--------------|-------------|
| `elf.threshold` | Threshold rules | Integer count of matches required to fire |
| `elf.timeframe` | Threshold + Sequence | Sliding window duration, e.g. `60s`, `120s` |
| `elf.group_by` | **Threshold rules** | Field(s) to scope the count per group (mandatory). Scalar (`group_by: TargetUserName`) or sequence (`group_by: [User, Computer]`). See §6. |
| `elf.threshold_op` | Threshold rules (optional) | Comparison operator for the fire condition: `gte` (default), `gt`, `eq`. See §6. |
| `elf.distinct` | Threshold rules (optional) | Field(s) whose **unique resolved values** are counted instead of raw events. Scalar (`distinct: DestAddress`) or sequence (`distinct: [DestAddress, DestPort]`). See §6. |
| `elf.sequence` | Sequence rules | Ordered list of stages (each a mini detection) |
| `elf.actions` | **All rules** | List of actions to take on match/fire |

> **Reusable lists** (`@@name` references) are a separate feature; see §7. They are expanded at load time into field values, so they work in any rule type without an `elf:` key.

If **none** of `threshold`/`sequence` are present, the rule is a **simple** rule (fires on first match). The `elf.actions` list is what makes the rule *do* something; without it, a match produces no output.

> **`group_by` is mandatory for threshold rules.** A threshold rule without `group_by` is rejected by the server at save time and refused by the agent's rule loader. This prevents the false positive where a global count fires on N matches from N different users/hosts. Always scope a threshold to the field that defines the attack unit (e.g. `TargetUserName` for brute force, `Computer` for host-scoped rules).

### Actions (`elf.actions`)
Each action has `type`, `destination`, and (for alerts) `message`:

| Type | Fires when | Sends |
|------|-----------|-------|
| `forward_event` | Every matching event (continuous) | The single matching event. A broad selection with this action makes ELF a plain forwarder for that event type (every logon, every account or group change), which is how a compliance record stays complete; see `rules/win_forward_all_logons.yaml` and `rules/win_compliance_account_changes.yaml` |
| `alert` | Rule fires (threshold/sequence met, or simple match) | The triggering event, annotated with `message` |
| `forward_buffer` | Rule fires | The buffered events this rule has not sent before, as a batch |

`destination` must match a name in `config.ini [destinations]`.

**`forward_buffer` does not clear the buffer.** It sends a snapshot and leaves the
events in place, so every other rule still evaluates them (alerts, threshold
counts and sequence stages on those events are not lost). Each rule keeps its
own cursor into the buffer: a second fire shortly after the first sends only
the events that arrived since.

**An event reaches a destination at most once.** However many rules ask for
it (two `forward_buffer` rules on the same destination, or a `forward_event`
rule plus a `forward_buffer` rule), each destination, and the server mirror,
receives a given event (same channel and `EventRecordID`) one time; the batch
is attributed to the first rule that asked. Two *different* destinations each
get their own copy. This keeps the Logs tab, the SIEM and the forwarded
counters free of duplicates, so *Events forwarded* can never exceed *Events
created* because of overlapping rules.

**Every fire has an alert id.** The agent stamps a 16-character id on the
alert and on the events of the batch that fire forwarded (structured formats:
`elf.alert_id` next to `elf.rule_id`; raw alert files: an `alert_id:` header
line; the server: the alert detail and the Logs tab). Search the SIEM for the
alert id to get one incident's alert plus its context, or for the rule id to
get everything a rule produced. See [SIEM.md](SIEM.md#investigation-keys).

**Combining `alert` + `forward_buffer`:** a rule may declare both (common for
high-severity rules that want to both notify and ship context). When both
fire on the same event, the agent sends **exactly ONE alert** (from the
`alert` action) plus **ONE log batch** (from the `forward_buffer` action). The
`forward_buffer` action's own "fired" notification alert is suppressed in
this case so the server doesn't record a duplicate alert for the same
`EventRecordID`. A `forward_buffer`-only rule (no `alert` action) still
produces its notification alert so it appears in the Alerts view.

### Severity-based alert selection (Simple rules)

When **multiple Simple rules match the same event**, only the **highest-severity** one fires its `alert`/`forward_buffer` actions. This prevents alert storms when a generic rule and a specific rule both match one event (e.g. a broad "process created" rule and a narrow "suspicious process" rule both fire on one 4688; only the higher-severity alert is sent).

- Severity ranking: `critical` (5) > `high` (4) > `medium` (3) > `low` (2) > `informational` (1) > unknown/empty (0).
- **Ties are broken by rule order**: the first-loaded matching rule wins. Rule order is: catch-all rules → channel-indexed rules → category rules, and within each bucket the file load order.
- **`forward_event` is never suppressed.** Every matching Simple rule still forwards its event stream (the `forward_event` action runs for every match, regardless of which rule wins the alert). Only the `alert` and `forward_buffer` actions are subject to severity selection.
- **Threshold and Sequence rules are NOT subject to severity selection.** They fire independently when their condition is met, even if a higher-severity Simple rule also matched the same event. A correlation alert (e.g. brute-force, failed→success) therefore always fires when its own condition is met.
- The rule's Sigma `level` field is threaded through to the server, so the Alerts UI can sort and color-code alerts by severity (see §9).
- **The losers are recorded.** The winning alert carries the ids of the suppressed rules: an `also_matched: id1, id2` header line in the file destination and an `also_matched` array in the server payload (shown as links in the alert detail). The console line reads `Rule fired: <winner> [also matched: N]`. Every match a rule made is therefore recorded.

Example: a `high` rule and a `low` rule both match a 4688 calc.exe event. Only the `high` rule's alert is sent, with `also_matched: <low rule id>`. Both rules still forward the event if they have a `forward_event` action.

---

## 6. Rule Types (worked examples)

### Simple rule: fire on first match
```yaml
title: Suspicious Process Launch (calc)
id: win_calc_susp
status: experimental
level: low
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
      destination: data_lake
```

### Threshold rule: fire after N matches in a window

Threshold rules count matching events within a sliding `timeframe` window and fire when the count meets `threshold` (using `threshold_op`). **`group_by` is mandatory**: it scopes the count to a per-group window so the rule fires on N matches *for the same group* (e.g. the same user), not N matches globally. Without it, 5 failed logons from 5 different users would fire a threshold-5 brute-force rule, a false positive.

```yaml
title: Brute Force Logon Attempt
id: win_brute_force_logon
status: stable
level: high
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4625
  condition: selection
elf:
  threshold: 5
  timeframe: 60s
  group_by: TargetUserName      # mandatory: count per user, not globally
  actions:
    - type: alert
      destination: alerts
      message: "Possible brute-force logon: 5 failed logons within 60s."
    - type: forward_buffer
      destination: siem
```

#### `group_by`: per-group counting

`group_by` takes one or more field names. The engine resolves each field against the event (using the same field resolver as `detection`; see §8) and keys the sliding window by `rule.id + group values`. Events with different group values maintain **independent** windows.

- Scalar: `group_by: TargetUserName` gives one window per username.
- Sequence: `group_by: [TargetUserName, Computer]` gives one window per (user, host) pair.
- If a group field is absent from an event, that event lands in a `<missing>` sentinel bucket (it is **not** dropped) so a rule still catches events with missing fields rather than going blind.

#### `threshold_op`: the comparison operator

Controls when the count triggers a fire. Default is `gte` (at least N) when omitted.

| Operator | Fires when | Typical use |
|----------|-----------|-------------|
| `gte` (default) | `count >= threshold` | "at least N": brute force, spam |
| `gt` | `count > threshold` | "more than N": needs one extra event |
| `eq` | `count == threshold` | "exactly N": precise count |

Example using `gt` (fires on the 6th failed logon, not the 5th):

```yaml
elf:
  threshold: 5
  timeframe: 60s
  group_by: TargetUserName
  threshold_op: gt
  actions:
    - type: alert
      destination: alerts
      message: "More than 5 failed logons within 60s."
```

After firing, the window resets so the rule re-arms for the next burst. `lt`/`lte`/`neq` are **not** supported (see §13 Limitations).

#### `distinct`: counting unique field values

By default a threshold rule counts **matching events**. `distinct` changes what it counts: the **unique resolved values** of the named field(s) within the window. Use it when N repeats of one value must not fire.

The classic case is a **ping sweep**. `ping -n 10 <onehost>` produces 10 matching WFP 5156 events, but they all target **one** destination IP. A plain threshold-5 rule would fire on the 5th event even though the host only ever contacted a single IP. With `distinct: DestAddress`, the rule counts unique destination IPs and stays silent:

```yaml
title: Ping Sweep - 5 Unique Destinations in 30s
id: win_ping_sweep_unique_dst
status: test
level: medium
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 5156
    Protocol: 1
  filter_multicast:
    DestAddress|cidr:
      - 224.0.0.0/4
      - 255.255.255.255/32
  condition: selection and not filter_multicast
elf:
  threshold: 5
  timeframe: 30s
  group_by: Computer
  distinct: DestAddress
  actions:
    - type: alert
      destination: alerts
      message: "Ping sweep: 5 unique destination IPs within 30s from one host."
    - type: forward_buffer
      destination: siem
```

Semantics:
- **Insert-or-refresh.** Each new matching event updates its value's last-seen timestamp. A value stays in the window while it keeps being seen within the `timeframe`; values not refreshed within the `timeframe` expire. This is the sliding-window behavior distinct counting needs: a slow trickle to the same small set of IPs does not accumulate forever.
- **Fire condition.** The rule fires when the number of unique values in the window meets `threshold` (honoring `threshold_op`). Raw event count is ignored for the fire decision.
- **Fire-then-reset.** Like all threshold rules, the window clears after a fire. A 10-unique-IP sweep against a threshold-5 rule fires **twice** (at the 5th and again at the 10th unique IP), the same re-arm behavior as the brute-force rule.
- **`<missing>` sentinel.** If the distinct field is absent from an event, the event counts into a single `<missing>` value bucket (mirroring `group_by`); it is not dropped.
- **Composite keys.** A sequence (`distinct: [DestAddress, DestPort]`) counts unique (field, field) tuples.
- **`group_by` still applies.** `distinct` counts unique values **per group**: `group_by: Computer` + `distinct: DestAddress` counts unique destinations per host independently.
- **Alert evidence.** When a threshold rule fires, the alert carries the window's contributing events (`window_events` in the server payload, "Window events (N)" in the UI dropdown and in the alerts destination file), not just the trigger. For non-`distinct` rules that is every counted event; for `distinct` rules it is **one representative event per unique value**, so a value repeated hundreds of times contributes exactly one evidence event. A "10 unique destinations" alert therefore shows the 10 connections that filled the window.

### Sequence rule: fire when stages occur in order within a window
```yaml
title: Failed Then Success Logon
id: win_failed_then_success_logon
status: stable
level: medium
logsource:
  product: windows
  service: security
detection:
  selection_failed:
    EventID: 4625
  selection_success:
    EventID: 4624
  condition: selection_failed or selection_success
elf:
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
      message: "Failed logon followed by success: possible credential compromise."
    - type: forward_buffer
      destination: data_lake
```

### Continuous forward rule: forward every match
```yaml
title: Forward All Logons
id: win_forward_all_logons
status: stable
level: low
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4624
  condition: selection
elf:
  actions:
    - type: forward_event
      destination: siem
```

---

## 7. Reusable Lists

Reusable lists let you define a set of values once and reference them from any
rule, so you can say "alert when `Image` contains any of these sensitive
processes" without repeating the list in every rule. Lists are **managed
centrally** (on the server) and **shared globally** across all groups.

### Referencing a list from a rule

Use the `@@` prefix in a field value. The list name is the file stem (without
extension). Because `@` is a reserved YAML indicator, **always quote** the
reference:

```yaml
detection:
  selection:
    EventID: 4688
    Image|contains: "@@sensitive_processes"
  condition: selection
```

You can also combine a list reference with literal values in a sequence:

```yaml
detection:
  selection:
    EventID: 4688
    Image|contains:
      - "@@sensitive_processes"
      - mspaint.exe
  condition: selection
```

The loader expands `@@sensitive_processes` at **load time** into the field's
value set, so the matching engine sees the same thing as if you had written
out every value inline.

### List file format

Each list is a plain text file (`.txt` or `.list`) in the `lists/` directory.
The file name (without extension) is the list name:

```
lists/sensitive_processes.txt
```

Format:
- **One value per line.**
- Lines starting with `#` are **comments** and are ignored.
- **Blank lines are ignored.**
- Leading/trailing whitespace on each value is trimmed.

Example:
```
# Sensitive processes to alert on
calc.exe
notepad.exe

# Drawing tools
mspaint.exe
```

### Missing / empty list behavior

If a rule references `@@name` and the list **does not exist or is empty**, the
field **matches nothing** (not "exists"). This is a deliberate safe default:
a typo in the list name must not silently turn the field into a wildcard that
matches everything. The agent logs a warning when this happens.

### Managing lists

- **Via the server UI**: the **Lists** tab lets you create, edit, and delete
  lists. Changes take effect on each agent's next poll (the agent writes the
  list files to its local `lists/` directory, then reloads rules).
- **Via the API**: `GET/POST /lists`, `GET/PUT/DELETE /lists/{name}`.
- **Locally (no server)**: place `.txt` files in the `lists/` directory next
  to the agent binary. The `[lists] directory=lists` setting in `config.ini`
  controls the path (default `lists`).

The server seeds a default `sensitive_processes` list on first start.

---

## 8. Field Resolution

Rules reference **logical field names** that the agent resolves against the rendered Windows event XML:

| Field name | Resolves to |
|-----------|-------------|
| `EventID` | `<System><EventID>` text |
| `Channel` | `<System><Channel>` text |
| `Computer` | `<System><Computer>` text |
| `Provider` | `<System><Provider Name="...">` attribute |
| `TimeCreated` | `<System><TimeCreated SystemTime="...">` attribute |
| *any other* | `<EventData><Data Name="NAME">` text (e.g. `Image`, `CommandLine`, `ScriptBlockText`) |

A dotted name like `EventData.CommandLine` is also supported (last segment is the Data Name).

### Field modifiers (Sigma subset)
Chained with `|` after the field name. All are **case-insensitive**.

| Modifier | Meaning |
|----------|---------|
| *(none)* | equals |
| `contains` | substring match |
| `startswith` | prefix match |
| `endswith` | suffix match |
| `re` | regex (ECMAScript, case-insensitive) |
| `exists` | field is present (value ignored) |
| `cidr` | field is an IP address inside the CIDR range (IPv4 + IPv6) |
| `all` | flag: every value in the list must match (AND); default is OR |

Example: `Image|endswith|all: [\calc.exe, \notepad.exe]` requires both to match (AND).

> **`|cidr`** does a real IP-in-network check, not a substring match. Use it
> in filter selections to exclude local/private IP ranges:
> ```yaml
> filter_main_local:
>   IpAddress|cidr:
>     - 10.0.0.0/8
>     - 172.16.0.0/12
>     - 192.168.0.0/16
>     - fc00::/7      # IPv6 ULA
>     - fe80::/10     # IPv6 link-local
> ```
> IPv4 and IPv6 are never cross-matched (an IPv4 address won't match an IPv6
> CIDR and vice-versa). An absent/empty IP or `"-"` never matches a CIDR
> filter, so it won't be silently excluded.

### Condition expressions
The `detection.condition` string supports:
- Selection names: `selection`
- Boolean: `and`, `or`, `not`
- Parentheses: `(a or b) and not c`
- Quantifiers: `1 of selection*`, `all of them`

---

## 9. Management Server

The server (FastAPI, Docker) holds the **authoritative copy** of the rules and per-agent config. The agent polls it on the configured interval.

### What the server provides
- `GET /config/{agent_id}`: returns effective config + ruleset. The agent:
  - Applies `retention_seconds` and destinations at runtime.
  - Writes the ruleset to the local `rules/` directory (only files whose bytes changed, via temp-file + rename; removing files not in the server set). Rules toggled off in the UI are not sent.
  - Triggers a rule-engine hot reload + resubscribe only when something changed.
  - **Ruleset fingerprint.** Every response carries `ruleset_hash` (SHA-256 over the group's enabled rules + lists). The agent sends it back as `?known_hash=` on the next poll; when it still matches, the server omits `rules`/`lists` entirely and answers `ruleset_unchanged: true` (a few hundred bytes instead of a multi-MB payload per agent per poll), and the agent skips the disk compare, reload and resubscribe. The per-group ruleset is cached server-side and invalidated by any rule/list change. An agent that sends no hash gets the full payload.
- `POST /alerts`: the agent pushes alerts here when an `alert` action fires.
- `POST /logs`: the agent pushes forwarded buffer batches here when a `forward_buffer` action fires.

### Web UI
The server hosts a web UI at its root URL (e.g. `http://localhost:8000/`) with these tabs:
- **Agents**: view all registered agents, change an agent's group via the inline dropdown, refresh the list manually or with auto-refresh, delete an agent
- **Groups**: create/edit/delete groups, and expand the **Members** column to see which agents are currently assigned to each group. Each group has a **Mirror logs** checkbox (default on): uncheck it and the group's agents stop copying forwarded log batches to the server (they still forward to their own destinations and still report alerts; alerts always mirror)
- **Rules**: create / edit / enable / disable rules (saved as Sigma YAML), with a search box filtering the rule list by name/id/severity
- **Lists**: manage reusable value lists (see §7)
- **Alerts**: view alerts with a color-coded severity badge per row (red=critical, orange=high, yellow=medium, blue=low, gray=informational/unknown). A search box filters by rule name/id/message/agent, a dropdown sorts by newest or severity, and clicking the rule name jumps to that rule in the Rules tab. Clear all (testing).
- **Metrics**: savings statistics + event-count and bytes graphs over a selectable time range (see below). Admins get a **Reset Metrics** button that zeroes the counters and deletes stored log batches (alerts are kept)
- **Logs**: simple list of forwarded log batches with the logs text file size and View/Download links; clear all (testing). A **Max file size (MB)** setting caps the logs text file (oldest lines trimmed; `0` = unlimited)
- **Audit** (admin-only): a record of every privileged action (logins, rule/group edits, clears, …) with a **Clear** button; the clear itself is always recorded after truncating

#### Metrics tab
The **Metrics** tab shows how much bandwidth the agent is saving by forwarding selectively instead of sending everything:

1. **Savings**: summary cards (bytes sent / created, savings %, events sent / created) plus a per-agent table:
   | Agent | Hostname | Events Created | Events Forwarded | % Forwarded | Bytes Created | Bytes Forwarded | Savings |
   - **% Forwarded**: bar graphic of `bytes_forwarded / bytes_created * 100` (green <25%, amber 25–75%, red >75%)
   - **Savings**: bar graphic of `(1 - bytes_forwarded / bytes_created) * 100` (green >50%, amber 0–50%, red 0%)
2. **Event Count graph**: time-bucketed bar chart of events over the selected date range
3. **Bytes graph**: time-bucketed bar chart of bytes over the selected date range

The date range controls (From/To) apply to both graphs. While a preset (1h/24h/7d/30d/All) is active the window slides forward with the current time; picking a custom From/To freezes the window. Auto-refresh updates the charts in place (no flicker) and pauses while you interact (text selection, open modal, date picker). The savings statistics are cumulative since agent registration and are not filtered by date.

**Reset Metrics** (admin-only button at the top of the tab) zeroes every agent's cumulative created/forwarded counters and deletes all stored forwarded-log batches (Logs tab rows + the logs text file). Alerts are kept. Use it to start a clean measurement window after tuning rules. Agents keep counting from zero onward.

**Savings formula:** `savings = (1 - bytes_forwarded / bytes_created) * 100`. The agent reports cumulative `events_created`, `bytes_created`, `events_forwarded`, and `bytes_forwarded` counters to the server on every poll (via `GET /config/{agent_id}` query params).

- **Created** counters measure everything the host **generated** on the watched channels: the agent reads each channel's log metadata (oldest record number + record count) every poll and accumulates the delta of the newest record number; this keeps advancing even when a circular log wraps, and it counts all events, not just the rule-referenced subset that gets delivered. Events are exact; bytes are estimated from the average rendered size of delivered events.
- **Forwarded** counters are incremented before each POST, regardless of whether destination resolution succeeds, so savings always reflects everything the host generated vs. what was actually sent.

#### Logs tab
The **Logs** tab is a simple testing view: a table of forwarded log batches (ID, Agent, Rule, Events) with the logs text file size and View/Download links. There are no date/time controls on the Logs tab; time filtering is on the Metrics tab.

The **Max file size (MB)** field caps how large the logs text file may grow (default 100 MB, `0` = unlimited). When the file exceeds the cap the server trims the oldest lines after each append, keeping the newest data. The cap applies only to the text file; the database rows are unaffected. Whether batches reach the server at all is controlled per group by the **Mirror logs** checkbox on the Groups tab.

### Rule identity
- The Sigma `id` field is the **YAML id** (shown in the UI rules list middle field).
- The server also assigns a **DB `rule_id`** (the primary key), which may differ from the YAML id. When editing a rule via the UI, the PUT updates in place by the original `rule_id` (no duplicate is created).

### Offline agent install (no internet on the target host)
The server can serve the prebuilt agent executable and generate a PowerShell install script (a full multi-line `.ps1`) so a new Windows host can be enrolled without reaching out to the internet.

> **The agent is statically linked** (`/MT`). The VC++ runtime is baked into the exe, so it has **no external DLL dependencies**; it runs on a clean Windows install with no `vcruntime140.dll` / `MSVCP140.dll` / `VCRUNTIME140_1.dll` needed. Only the single `efficient_log_forwarder.exe` must be shipped to the target.

**Providing the binary.** Bake it into the Docker image:
1. Build the agent on a build machine: `cmake --build build --config Release` → produces `build/Release/efficient_log_forwarder.exe`.
2. Copy the binary into `server/agent/`:
   ```
   server/agent/efficient_log_forwarder.exe
   ```
3. Rebuild the image: `docker compose up --build -d`. On every start the entrypoint seeds this file into the `elf-data` volume at `/data/agent/` (always overwriting any stale copy). A fresh install ships with a working agent.

The binary lives in the `elf-data` volume at `/data/agent/` and is **re-seeded onto the volume on every container start**, so rebuilding the image with a new exe replaces any stale one left on the volume by a previous install. To ship a new agent build, stage the exe into `server/agent/` and redeploy.

**Enroll a new host:**
1. In the web UI, click **+ Add New Agent**.
2. Pick the **group** the new agent should join.
3. Choose the **service account** mode:
   - *Create a local service account* (default): self-contained; the script creates the `ELFAgent` local user on the target host.
   - *Use an existing domain account*: enter the NetBIOS domain and username of an AD service account (see §4.0.1 for creating one). The script prompts for the password securely at install time on the target host.
4. Click **Generate**; the install script appears. Use **Copy** or **Download .ps1**.
5. On the target Windows host, open an **elevated PowerShell** prompt and run the script (paste it, or run the downloaded `install-elf-agent.ps1`).

The script:
- Downloads `efficient_log_forwarder.exe` from the server to `Program Files\ELFAgent\` (no internet needed beyond reaching the server).
- Creates the writable state tree under `%ProgramData%\ELFAgent\` with `logs\`, `state\bookmarks\`, `spool\`, `rules\`, `lists\`, and `output\` subdirectories.
- Provisions the service account: creates a dedicated local user `ELFAgent` with a random password (local mode), or grants the same local rights to the existing domain account (domain mode; the password is prompted securely, never stored).
- Grants `SeServiceLogonRight` + `SeSecurityPrivilege` + membership in **Event Log Readers** (least privilege, not Administrator).
- ACLs the `%ProgramData%\ELFAgent` tree so only SYSTEM and the service account can read it.
- Writes `config.ini` with `agent_id` set to the host's `$env:COMPUTERNAME` (so every host gets a unique id derived from its hostname).
- Registers the agent with the server in the chosen group.
- Installs and starts the `ELFAgent` Windows service (auto-start on boot, restart on crash).

**API:** `POST /install-script` with JSON body `{"group": "<name>", "account_mode": "local"|"domain", "domain": "<netbios>", "username": "<user>"}` returns the script as `text/plain`. (`GET /install-script?group=<name>` still works and is equivalent to local mode.)

**Server address in the script:** the script embeds the server's address. Set `ELF_PUBLIC_HOST` (and optionally `ELF_PUBLIC_PORT`) in `docker-compose.yml` to the address the target hosts can reach (e.g. the Docker host's IP). If left blank, the server uses the hostname of the request that generated the script.

**Endpoints (for automation):**
- `GET /agent/binary`: download the prebuilt exe (baked into the image from `server/agent/`).
- `GET /agent/binary/status`: `{available, name, bytes}`.
- `GET /agent/files`: list companion files `[{name, bytes}, ...]` (optional extras; the agent needs none).
- `POST /agent/files`: upload a companion file (`multipart/form-data`, field `file`).
- `GET /agent/files/{name}`: download a companion file.
- `DELETE /agent/files/{name}`: delete a companion file.
- `POST /install-script`: returns the install `.ps1` as `text/plain` (JSON body: `group`, `account_mode`, `domain`, `username`).
- `GET /install-script?group=<name>`: legacy form; local-account mode only.
- `GET /cleanup-script`: returns the cleanup `.ps1` as `text/plain` (removes the service, the local service account, LSA rights, and both directories).

### Database reset on container start
By default the server wipes its SQLite database on every container start so a new install comes up with no leftover agents, rules, or alerts from previous runs. This is controlled by the `ELF_RESET_DB` environment variable (default `1`):

| `ELF_RESET_DB` | Behavior |
|---|---|
| `1` (default) | Delete `elf.db` on startup. Fresh DB; default group + seed rules recreated by `init_db`. |
| `0` | Preserve the DB across restarts. Use for dev or when you only want to restart the server without losing registrations. |

Only the database is wiped; the seeded agent binary and companion files in `/data/agent/` are always preserved. To force a completely clean slate (DB + agent files), delete the `elf-data` volume before starting:

```bash
docker compose down -v   # removes the named volume
docker compose up -d --build
```

### Seeding demo data (`ELF_SEED_TEST_DATA`)
A default deployment seeds two groups: `default` with the Windows sample rules and `linux-servers` with the Linux ones. Set `ELF_SEED_TEST_DATA=1` to add three demo groups with more rules, lists, and destinations on startup, for a lab where you want the kill-chain suite without hand-configuring anything. The flag is off in `docker-compose.yml`; the demo groups are not part of an installation.

| Group | Purpose | Rules | Highlights |
|---|---|---|---|
| `workstations` | MITRE kill-chain suite | 12 | the **12-rule MITRE kill-chain suite** (see §9.1); every rule's title and description names its kill-chain step (tactic) |
| `servers` | Server hardening | 3 | sequence (failed→success logon), `@@living_off_the_land` list ref, `forward_event` |
| `tier-0` | High-value assets | 3 | aggressive threshold (3/30s), dual-list rule (`@@suspicious_parents` + `@@living_off_the_land`), `forward_event` |

Four reusable lists are seeded: `sensitive_processes`, `living_off_the_land`, `suspicious_parents`, `uac_bypass_binaries` (auto-elevate binaries abused for UAC bypass). Each group gets distinct `file://` destinations under `output/` and its own retention/poll settings. Re-runs are idempotent (groups/rules/lists are upserted, not duplicated).

The flag lives in `server/docker-compose.yml`:

```yaml
environment:
  - ELF_SEED_TEST_DATA=0   # 1 adds the demo groups (lab only)
```

To test an agent against a specific group, register it with that group's id (see the install script at `GET /install-script?group=<name>`, or assign it via the web UI).

### 9.1 Seeded MITRE kill-chain suite (`workstations` group)

The `workstations` group ships a 12-rule suite covering the MITRE ATT&CK tactics from **Execution to Impact** (11 tactics; Credential Access is doubled: LSASS dump + password spray). Every rule's **title names its kill-chain step** (e.g. `Kill-Chain 04 (Defense Evasion) - Security Event Log Cleared`) and its description opens with the step (`Defense Evasion step of the MITRE kill chain - ...`), so the tactic is visible in the Rules tab. Each rule pairs with an [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team) test that triggers it from a single Windows host, and each exercises a different ELF capability. All rules are prefixed `win_kc_` and land in the workstations group, so one lab host in that group can run the full chain.

| # | Tactic | Technique | Rule id | Atomic test (trigger) | Event | ELF capability |
|---|--------|-----------|---------|----------------------|-------|----------------|
| 01 | Execution | T1059.001 PowerShell | `win_kc_01_ps_encoded` | T1059.001 *PowerShell Command Execution* #17 (`powershell.exe -enc <base64>`) | 4688 | multi-value `contains` |
| 02 | Persistence | T1543.003 Windows Service | `win_kc_02_service_install` | T1543.003 *Service Installation CMD* #2 (`sc.exe create ...`; `-GetPrereqs` first) | **7045 (System ch.)** | multi-channel + `forward_event` |
| 03 | Priv. Escalation | T1548.002 Bypass UAC | `win_kc_03_uac_bypass` | T1548.002 *Bypass UAC using Fodhelper* #3 (`fodhelper.exe`; #1/#2/#4/#5/#7 also fire) | 4688 | `@@uac_bypass_binaries` list + `endswith` |
| 04 | Defense Evasion | T1685.005 Clear Event Logs (ex-T1070.001) | `win_kc_04_log_clear` | T1685.005 *Clear Logs* #1 (`wevtutil cl Security` via `-InputArgs`) | 4688 + **1102** | multi-selection `or` (dual signal) |
| 05 | Credential Access | T1003.001 LSASS Memory | `win_kc_05_lsass_dump` | T1003.001 *Dump LSASS.exe Memory using comsvcs.dll* #2 (rundll32; not #9 ProcDump) | 4688 | `|all` AND-list + critical level |
| 06 | Credential Access | T1110.003 Password Spraying | `win_kc_06_password_spray` | no matching atomic on a member host; local `net use` failed-logon loop instead | 4625 | threshold + `group_by: IpAddress` |
| 07 | Discovery | T1046 Network Service Scanning | `win_kc_07_port_scan` | T1046 *Port-Scanning /24 Subnet with PowerShell* #10 (not #1, which is bash) | **5156** | threshold + `distinct` + `|cidr` filter |
| 08 | Lateral Movement | T1021.001 RDP | `win_kc_08_rdp_logon` | T1021.001 *RDP to Remote Host* #1 (needs real credentials via `-InputArgs`) | 4624 | field-value match (`LogonType: 10`) + `and not` filter |
| 09 | Collection | T1074.001 Local Data Staging | `win_kc_09_archive_stage` | T1074.001 *Zip a Folder with PowerShell for Staging in Temp* #3 | 4688 | `|re` regex with alternation |
| 10 | Command & Control | T1105 Ingress Tool Transfer | `win_kc_10_ingress_transfer` | T1105 *certutil download (urlcache)* #7 (not #8, which uses verifyctl) | 4688 | `1 of sel_*` quantifier |
| 11 | Exfiltration | T1048.002 Exfil Over Alternative Protocol | `win_kc_11_stage_exfil` | T1074.001 #3 then T1048.002 *Exfiltrate data HTTPS using curl windows* #1 within 300s (`-GetPrereqs` first) | 4688 ×2 | **sequence** (stage → upload, 300s) |
| 12 | Impact | T1490 Inhibit System Recovery | `win_kc_12_inhibit_recovery` | T1490 *Windows - Delete Volume Shadow Copies* #1 (`vssadmin delete shadows /all /quiet`; #3 wbadmin also fires) | 4688 | critical + `alert`+`forward_buffer` combo |

**Prerequisites for the chain to fire:**

- **Audit policy**: most rules need *Audit Process Creation* (with command-line inclusion), *Logon/Logoff*, and *Filtering Platform Connection* enabled on the host (e.g. via GPO). Rules 02 (7045) and 04's EventID 1102 are logged by default and fire without any audit policy, which makes them useful pre-GPO smoke tests.
- **Windows Defender**: disable real-time protection on the lab host (the comsvcs LSASS dump is killed otherwise).
- **Agent group**: the host's agent must be in the `workstations` group; rules are per-group.

**Running the chain:** install Atomic Red Team on the lab host (`IEX (IWR 'https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1' -UseBasicParsing); Install-AtomicRedTeam -Force`), then run the exact test for each rule, **always with `-TestNumbers`**, since a bare `Invoke-AtomicTest Txxxx` detonates *every* test in the technique and most produce event shapes the rule does not match. Each rule's description in the Rules tab embeds the same command. In order:

```powershell
Invoke-AtomicTest T1059.001 -TestNumbers 17      # 01 encoded PowerShell
Invoke-AtomicTest T1543.003 -GetPrereqs         # 02 fetch the service binary first...
Invoke-AtomicTest T1543.003 -TestNumbers 2      #    ...then the service install (7045)
Invoke-AtomicTest T1548.002 -TestNumbers 3      # 03 UAC bypass via fodhelper
Invoke-AtomicTest T1685.005 -TestNumbers 1 -InputArgs @{log_name='Security'}   # 04 wevtutil cl Security
Invoke-AtomicTest T1003.001 -TestNumbers 2      # 05 LSASS dump via comsvcs (Defender off)
Invoke-AtomicTest T1046 -TestNumbers 10         # 07 /24 port scan (5156 volume)
Invoke-AtomicTest T1021.001 -TestNumbers 1 -InputArgs @{username='<valid_user>'; password='<valid_password>'}   # 08 RDP logon
Invoke-AtomicTest T1074.001 -TestNumbers 3      # 09 Compress-Archive staging
Invoke-AtomicTest T1105 -TestNumbers 7          # 10 certutil urlcache download
Invoke-AtomicTest T1074.001 -TestNumbers 3      # 11 stage, then within 300s upload:
Invoke-AtomicTest T1048.002 -GetPrereqs         #    fetch the curl artifact first...
Invoke-AtomicTest T1048.002 -TestNumbers 1      #    ...then the curl exfil (completes rule 11)
Invoke-AtomicTest T1490 -TestNumbers 1          # 12 vssadmin delete shadows
```

Rule 06 has no matching atomic on a member host (the T1110.003 spray tests authenticate against the DC, so their 4625s land on the domain controller, where this host's agent cannot see them); trigger it locally with 5+ failed logons within 60s instead: `net use \\127.0.0.1\IPC$ /user:LAB\nosuchuser1 BadPassword1` in a loop (vary the username). After each test, check the server's **Alerts** tab (search `win_kc_`) and the group's `output/*.jsonl` destinations. Rule 08 is `forward_event`-only; it never alerts, so verify it in the SIEM stream. Rule 07's 5156 events are voluminous; expect the Metrics tab's *Events Created* to jump noticeably (and the savings % to rise).

---

## 10. Output Files

When using `file://` destinations, the agent appends to the configured paths. Relative paths resolve under the agent data directory, so with the default destinations an installed agent writes:

| File | Written by |
|------|-----------|
| `%ProgramData%\ELFAgent\output\siem.jsonl` | `forward_event` and `forward_buffer` actions targeting `siem` |
| `%ProgramData%\ELFAgent\output\data_lake.jsonl` | `forward_event` and `forward_buffer` actions targeting `data_lake` |
| `%ProgramData%\ELFAgent\output\alerts.jsonl` | `alert` actions targeting `alerts` |

With the default `raw` format, forwarded events are written as raw Windows event XML, one event per line, and alerts are a plain-text header (`rule_id`, `message`, `timestamp`, optional `also_matched`) followed by the pretty-printed triggering event and, for threshold/sequence rules, the evidence events. Add `?format=json` or `?format=ecs` to a `file://` destination to get one JSON document per line instead (see §3 and [SIEM.md](SIEM.md)).

---

## 11. Testing

### Unit tests
```powershell
cd build\Release
.\test_rule_engine.exe
```
719 checks (723 with the scale block) covering rule parsing, field resolution, condition evaluation, threshold/sequence logic, action dispatch, reusable-list expansion, `group_by`/`threshold_op` behavior, XPath query derivation, severity-based alert selection, bookmark flag-selection, live `EvtSubscribe` integration, CIDR IP-in-network matching, server-config `mirror_logs` handling, the seeded kill-chain suite (YAML parity with the server seed, tactic-in-title/description, and per-rule firing on synthetic atomic-test events), threshold-window alert evidence, spool ack/4xx/corrupt-entry handling, `/logs` chunking, evidence caps, the evaluation cursor under concurrent buffer cleanup, `forward_buffer` without clearing, `also_matched`, concurrent reload safety, sequence restart, cross-channel dedup, threshold-state hygiene, type-safe config parsing, data-dir path resolution, binary rule writes + the `ruleset_hash` protocol, structured XPath + the `*` fallback, partial rule loading, per-rule exception containment, and the SIEM output formats (destination URL options and redaction, the json/ECS/HEC/GELF/Sentinel document builders per event type, alert decoration with ATT&CK tags and capped evidence, NDJSON/array chunking, spool record v2 + v1 compatibility, header blocks, and a byte-for-byte guard on `raw` output).

```powershell
# Scale check (3,000 synthetic rules + a planted needle; prints µs/event, asserts ≤ 1.5 ms):
$env:ELF_SCALE_TEST = '1'; .\test_rule_engine.exe; Remove-Item Env:ELF_SCALE_TEST
```

Server-side smoke scripts (repo root, FastAPI TestClient against a throwaway SQLite DB):
```powershell
.venv\Scripts\python.exe -I tests/server/smoke_new_endpoints.py
.venv\Scripts\python.exe -I tests/server/smoke_perf_round.py
.venv\Scripts\python.exe -I tests/server/smoke_seed_killchain.py
.venv\Scripts\python.exe -I tests/server/smoke_wire_format.py   # ruleset_hash/known_hash, /logs limits, also_matched, 3,000-rule import, WAL, validator
.venv\Scripts\python.exe -I tests/server/check_ui_js.py     # inline web UI: JS parses, handlers declared, element ids exist (pip install esprima)
.venv\Scripts\python.exe -I tests/server/e2e_ui.py --channel msedge   # browser E2E: own server + seeded DB, every tab, console errors fail (pip install playwright)
```

### Manual end-to-end test
1. Run the agent in console mode from the repository root (elevated prompt needed for the Security channel; see §4.1). The installed service already has `SeSecurityPrivilege` and needs no elevation.
2. Trigger a monitored event (e.g. open `calc.exe` twice within the rule's `timeframe` for a threshold-2 calc rule).
3. Watch the console for `[ALERT] ...`.
4. Check `output/alerts.jsonl` for the alert JSON.
5. Check the server web UI for the alert.

### Clearing data for re-tests
Use the web UI **Clear All** buttons on the Alerts and Logs tabs, or the `DELETE /alerts` and `DELETE /logs` endpoints. The logs text file (`/logs/text`) is also truncated when logs are cleared.

---

## 12. Troubleshooting

| Symptom | Check |
|---------|-------|
| No events buffered | In console mode, run from an elevated prompt (the Security channel needs `SeSecurityPrivilege`). The installed service already has this right. Confirm Security channel audit policy is enabled |
| Rule never fires | Verify `logsource.service` matches the channel; check field names against event XML; confirm `condition` references the selection names |
| Threshold never fires | Confirm `timeframe` is long enough for manual triggering; confirm `threshold` count |
| Alert fires but no output file | Confirm the `destination` name exists in `config.ini [destinations]` and the path is writable |
| Duplicate alerts | Expected for `forward_event` (continuous); for `alert`/`forward_buffer` the engine dedupes by EventRecordID per rule. A rule with BOTH `alert` AND `forward_buffer` sends exactly ONE alert (the `alert` action) plus ONE log batch (the `forward_buffer` action); the `forward_buffer` notification alert is suppressed to avoid a duplicate |
| Rules don't update after server edit | Confirm `agent_id` matches; check the agent's server poll is reaching the server; the server rewrites changed `rules/*.yaml` on the next poll (unchanged rulesets are skipped via `ruleset_hash`) |
| `[YamlRuleLoader] N rule file(s) failed to load and were skipped: ...` | Those files have a YAML/structure error (named in the line); every other rule is loaded and active. Fix the file (or the rule on the server) and it reloads on the next change. The agent keeps its previous ruleset only if *nothing* parsed |
| `Dropping POST to ... HTTP 4xx` in `error.log` | The server rejected that request permanently (e.g. `401` revoked enrollment token → re-run the install script; `422` payload shape the server does not accept → agent/server version mismatch, redeploy both). The entry is discarded so the queue keeps moving; the response text is in the line |
| `[STATUS] WARNING: events evicted before evaluation +N` | The engine is not keeping up (or `retention_seconds` is shorter than one evaluation pass): N events aged out of the buffer before any rule saw them. Raise retention, reduce the ruleset, or check for a stalled engine thread |
| `Filtered subscription rejected for channel X ... falling back to all events` | Windows refused the XPath filter for that channel (unexpected: the agent chunks filters to stay under the 23-term limit). The channel is still collected unfiltered; the rule engine filters in-process. Report the logged query length |
| Alerts in the UI but none in the `file://` destination on the host | Check `error.log` for `Cannot open file`; the path must be under a directory the service account can write. Relative paths resolve under `%ProgramData%\ELFAgent`; absolute paths must grant the service account (`<domain>\ELFAgent` or the local `ELFAgent` user) write access |
| 100% CPU in `MsMpEng.exe` (Windows Defender) when many rules are enabled | Defender real-time scanning hooks the agent's rule-file I/O. Exclude the agent's state tree + process; see **§12.1 Antivirus exclusions** below |
| Agent appears frozen (no console output, buffer keeps growing), Ctrl+C resumes it | The Windows console **QuickEdit mode** pauses output on a mouse click. The agent disables QuickEdit at startup, so this does not happen in a real console. If it does (e.g. the agent is run under a redirected/piped console where the disable is a no-op), press `Enter` to release the selection. The agent's threads keep running while output is paused; only the console is blocked |

### Debug mode
Set the `ELF_DEBUG` environment variable for verbose output:
```powershell
$env:ELF_DEBUG="1"
.\build\Release\efficient_log_forwarder.exe
```

### 12.1 Antivirus exclusions (Windows Defender / high CPU with large rulesets)

**Where the rules live on the host.** The server-pushed ruleset is stored in
the agent's writable state tree, not next to the exe:

```
C:\Program Files\ELFAgent\              (read-only: exe, config.ini, shipped defaults)
%ProgramData%\ELFAgent\rules\           (server-pushed rules, one .yaml per rule)
%ProgramData%\ELFAgent\lists\           (server-pushed lists)
%ProgramData%\ELFAgent\{logs,state,spool,output}\   (other hot I/O)
```

An unchanged ruleset causes no file writes and no reload (`ruleset_hash`
handshake with the server + a directory fingerprint for the 60 s disk
watcher), so steady-state polls are quiet. The exclusions below matter for a
2,000+ rule import, because the *first* write of a new ruleset is 2,000 files.

**Why Defender spikes.** With 2000+ rules enabled, two I/O patterns make
`MsMpEng.exe` run at 100% CPU:
1. **Bulk writes**: when the ruleset changes, the agent rewrites every changed
   rule file in one poll; each write fires a real-time scan. (Unchanged files
   are skipped, but a 2000-rule import writes 2000 files at once.)
2. **Reload reads**: every ruleset change (server poll or edit on disk)
   re-parses every rule file. Defender intercepts every open.

**Fix: add path + process exclusions** (elevated PowerShell on the host):
```powershell
# Exclude the whole agent state tree (rules, lists, spool, logs, bookmarks)
Add-MpPreference -ExclusionPath "$env:ProgramData\ELFAgent"

# Process exclusion: stops Defender hooking every file the agent opens/creates
# (covers the exe itself + every reload that re-reads the rule files)
Add-MpPreference -ExclusionProcess "efficient_log_forwarder.exe"

# Verify
Get-MpPreference | Select-Object -ExpandProperty ExclusionPath
```

For a fleet, deploy via GPO: *Computer Configuration → Administrative
Templates → Windows Components → Microsoft Defender Antivirus → Exclusions →
Path/Process Exclusions*.

**Security trade-off.** Excluding `%ProgramData%\ELFAgent` means files dropped
there are never scanned. The risk is bounded: the tree is ACL'd to `SYSTEM` +
the `ELFAgent` service account only (the install script sets this), so a
normal user cannot plant files there. If your security posture prefers
minimal exclusions, exclude just the hot paths instead:
```powershell
Add-MpPreference -ExclusionPath "$env:ProgramData\ELFAgent\rules"
Add-MpPreference -ExclusionPath "$env:ProgramData\ELFAgent\lists"
Add-MpPreference -ExclusionPath "$env:ProgramData\ELFAgent\spool"
```

The **process exclusion** is the most effective single change for the read
side; the **path exclusion** removes the write-side scan storm. Together they
typically eliminate the 100% CPU spikes.

---

## 13. ELF Addon Feature Summary

For the ELF addons (`elf:` block) to work, you need:

1. **A valid Sigma rule** with `title`, `id`, `status`, `level`, `logsource`, and `detection`.
2. **An `elf:` block** with at least `elf.actions`.
3. **Rule type** determined by which ELF keys are present:
   - No `threshold`/`sequence` → **simple** (fires on first match)
   - `elf.threshold` + `elf.timeframe` + `elf.group_by` → **threshold** (fires after N matches per group in window). `elf.group_by` is **mandatory** for threshold rules. `elf.threshold_op` is optional (default `gte`). `elf.distinct` is optional: count unique field values instead of raw events (see §6).
   - `elf.sequence` + `elf.timeframe` → **sequence** (fires when stages occur in order within window)
4. **At least one action** in `elf.actions`; otherwise the rule matches silently with no output.
5. **Named destinations** in `config.ini [destinations]` matching the `destination` field in each action.
6. **For server-managed rules**: the management server must be reachable and the `agent_id` in `config.ini` must match a registered agent.
7. **Reusable lists** (optional): define value lists in `lists/*.txt` and reference them from rules with `@@name` (see §7). Lists are expanded at load time and shared globally across all groups.

### Limitations

- **`group_by` is threshold-only.** It is mandatory for threshold rules and rejected on simple/sequence rules. Sequence-rule grouping (per-user failed→success) is not yet implemented; sequence rules still use a single global window keyed by `rule.id`.
- **`threshold_op` supports `gte`/`gt`/`eq` only.** `lt`/`lte`/`neq` are not supported. The meaningful version of "fewer than N events in the window" fires when the timeframe *expires* without reaching N, which requires timer-driven evaluation the arrival-driven engine doesn't have today. Under the current fire-then-reset model, `lt`/`lte`/`neq` would fire on every matching event after a reset (count resets to 1, which is `< N`), which is useless.
- **`distinct` counts unique values, not events.** With `distinct`, repeats of an already-seen value refresh its last-seen time but never increase the count. This is the desired behavior (a ping storm to one host must not fire a sweep rule), but it means a rule tuned for "N events" semantics will fire *later* than expected when the same values repeat. `distinct` is threshold-only (rejected on simple/sequence rules).
- **`<missing>` sentinel for unresolved group fields.** If a `group_by` field is absent from an event, the event lands in a `<missing>` bucket rather than being dropped. This keeps the rule from going blind on events with missing fields, but it means events with missing group fields are counted together: a rule grouped by `TargetUserName` will fire on N events that all lack `TargetUserName`.
- **No field-name validation.** The server validates that `group_by` is a string/list of strings, but does not check that the field names are resolvable (it can't, without knowing the agent's field resolver). An unresolvable field name behaves as `<missing>` for every event, which is effectively global counting. Use field names from §8.
- **Memory grows with group cardinality.** Each distinct group value creates a `RuleState` entry. The engine evicts stale per-group states (those with an empty window and no recent alerts) during its periodic prune pass, but a noisy host with many distinct users can accumulate many entries between prune cycles.
- **Category rules only see classified events.** A rule with a `logsource.category` the engine knows (`process_creation`, `network_connection`, `registry_*`, `image_load`, `ps_script`, …) is evaluated only against events the engine classifies into that category (e.g. Security 4688 / Sysmon 1 for `process_creation`). An event the engine cannot classify (a 4624 logon, a custom provider) is never evaluated against those rules; that is what stops a `CommandLine: ''` filter from matching an unrelated event type. A rule whose category the engine does not know is evaluated only against unclassified events; such rules are listed in the agent log at reload. Use `logsource.service` (channel-based) for event types outside the table.
