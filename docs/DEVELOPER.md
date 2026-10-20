# ELF: Developer Documentation

This document explains the **architecture and codebase** of the Efficient
Log Forwarder (ELF). It is written for a developer who needs to understand,
extend, or debug the system. For end-user instructions, see `docs/USAGE.md`
and the in-server web UI guide.

---

## 1. System Overview

ELF is a two-tier Windows event-log forwarding system:

```
┌─────────────────────────────────────┐         ┌──────────────────────────┐
│  Windows Agent (C++17, wevtapi)     │  HTTP    │  Management Server        │
│                                    │  (WinHTTP│  (Python, FastAPI, SQLite,│
│  EventCollector ──► EventBuffer    │ ───────► │  Docker on Linux)         │
│       │                            │         │                          │
│       ▼                            │  ◄────── │  Web UI (rules/agents/    │
│  RuleEngine ──► Forwarder ──► files│  poll   │  groups/lists/alerts/    │
│                     │     └► SIEM  │         │                          │
│                     │  (hec/gelf/  │         │                          │
│                     │   sentinel/  │         │                          │
│                     │   ecs/json)  │         │                          │
│       │                            │         │  metrics/logs)            │
│       └──► AgentClient ───────────►│         │                          │
└─────────────────────────────────────┘         └──────────────────────────┘
```

- **Agent**: runs on each monitored Windows host as a service under a dedicated, limited account (`ELFAgent`). Subscribes
  to the Windows Event Log, evaluates Sigma rules against the live event
  stream, and forwards matching events/alerts/buffers to file or HTTP
  destinations. Pulls its ruleset and config from the server.
- **Server**: runs once (Docker on a Linux host). Holds the authoritative copy of
  the rules, agent registrations, groups, and lists. Hosts the web UI. Receives
  alerts and forwarded logs from agents.

The two communicate over plain HTTP (WinHTTP on the agent side, FastAPI on the
server side). The agent polls the server on a configurable interval; the
server never pushes to the agent (the agent is the initiator, which keeps the
agent firewall-friendly).

---

## 2. Repository Layout

```
efficient_log_forwarder/
├── CMakeLists.txt              # Build: agent + test_rule_engine (yaml-cpp, nlohmann/json via FetchContent)
├── config.ini                  # Agent bootstrap config (server can override)
├── src/                        # Portable agent core (see §3)
│   ├── Platform.h, EventSource.h   # The two interfaces the platform layers implement
│   ├── AgentRuntime.h/.cpp     # runAgent(): wiring + worker threads, shared by both entry points
│   └── platform/
│       ├── win/                # Event Log collection, WinHTTP, service entry point (main_win.cpp)
│       └── linux/              # journald collection + audit join, libcurl, daemon entry point (main_linux.cpp)
├── packaging/linux/            # elf-agent.service + install.sh for a locally built binary
├── rules/                      # Sample YAML rules (win_*, lin_*) copied next to the built exe
├── lists/                      # Reusable value lists (*.txt) referenced by rules as @@name
├── tests/
│   ├── test_rule_engine.cpp    # Agent regression harness (~790 CHECKs on Windows, ~780 on Linux; writes test_rules*/ next to itself)
│   └── server/                 # Server checks: smoke_*.py (TestClient), check_ui_js.py, e2e_ui.py (Playwright)
├── server/                     # Management server (Python, FastAPI, SQLite, Docker)
│   ├── main.py                 # FastAPI app + embedded web UI (single file)
│   ├── models.py               # Pydantic models (request/response schemas, destination validation)
│   ├── db.py                   # SQLite data layer (agents, groups, rules, lists, alerts, logs, metrics, users, audit)
│   ├── static/                 # Vendored Chart.js
│   ├── requirements.txt, Dockerfile, docker-compose.yml, entrypoint.sh, .dockerignore
│   ├── linux_install.py        # The bash install + cleanup scripts the Add New Agent dialog generates for Linux
│   └── agent/                  # Prebuilt agents (efficient_log_forwarder.exe, elf-agent) baked into the image and served to new hosts
├── demo/                       # enable-audit.ps1, enroll-agent.ps1: lab setup helpers (docs/DEMO.md)
├── tools/siem-sink.py          # Offline Splunk/Graylog/Sentinel stand-in for testing destinations
├── docs/                       # USAGE.md, SIEM.md, DEMO.md, DEPLOYMENT.md, DEVELOPER.md (this), img/
├── .github/                    # CI workflow, issue + PR templates
└── README.md, CHANGELOG.md, SECURITY.md, CONTRIBUTING.md, LICENSE, SBOM.md, THIRD_PARTY_NOTICES.md
```

---

## 3. Agent Architecture (C++17)

The agent is a single executable (`efficient_log_forwarder.exe` on Windows,
`elf-agent` on Linux) built from the sources in `src/`. The Windows build is
**statically linked** (`/MT`) so it has no external DLL dependencies and
runs on a clean Windows install; the Linux build links `libsystemd` and
`libcurl` from the distribution.

Everything above `src/platform/` is plain C++17 and builds on both
platforms. The platform layers implement two interfaces: `Platform.h`
(paths, environment, host identity, UTF conversions, time, crash handlers,
historical collection) and `EventSource.h` (subscribe to the channels the
rules can match, keep the read position, report what the host generated).
Both collectors hand the core the same event shape, the Windows event XML
envelope: the Linux collector renders a journal entry into it (the syslog
identifier or `audit` as the Channel, the audit record type as the EventID,
every journal field as a `<Data>` element), so the field resolver, the
engine, the formats and the tests are shared.

### 3.1 Source files and responsibilities

| File | Responsibility |
|------|---------------|
| `AgentRuntime.h/.cpp` | `runAgent()`: parses `config.ini`, wires components, starts worker threads, sets up the server-poll + rule-reload callbacks (including re-subscription). `StopSignal` is what a service handler or a POSIX signal handler sets to stop it. |
| `platform/win/main_win.cpp` | Windows entry point: service control manager integration, `--install`/`--uninstall`, `--debug`. |
| `platform/win/PlatformWin.cpp`, `EventSourceWin.cpp` | `Platform.h` on Windows; `EventSource` over `EventCollector` + `BookmarkStore` + `LogGrowthMonitor`. |
| `platform/linux/main_linux.cpp` | Linux entry point: a plain daemon under systemd, SIGINT/SIGTERM to stop. |
| `platform/linux/PlatformLinux.cpp` | `Platform.h` on Linux: `/var/lib/elf`, `/etc/elf/config.ini`, UTF-32 conversions, signal crash handlers, historical collection by journal time. |
| `platform/linux/JournalEvent.h/.cpp` | Renders a journal entry into the event envelope. `AuditJoiner` groups the records of one audit event (`_AUDIT_ID`: SYSCALL, EXECVE, CWD, PATH, PROCTITLE, EOE) and renders each with its siblings' fields, so an EXECVE record carries `exe`, `pid`, `key` and a joined `CommandLine`. |
| `platform/linux/EventSourceLinux.cpp` | `EventSource` over `sd-journal`: one reader thread, journal matches per channel (`SYSLOG_IDENTIFIER=`, `_TRANSPORT=audit`), cursor persisted to `state/bookmarks/journal.cursor`, audit record types filtered after the join. `GrowthMonitor` counts journal growth on the watched identifiers from a second handle. |
| `platform/linux/HttpClientCurl.cpp` | `HttpClient` over libcurl (redirects, inactivity timeouts and no `Expect:` to match the WinHTTP transport). |
| `Config.h/.cpp` | INI parser. Loads `[buffer]`, `[rules]`, `[lists]`, `[server]`, `[destinations]`, and the optional `[collect]` section into a `Config` struct. |
| `EventCollector.h/.cpp` | Windows Event Log subscription. Enumerates channels (`EvtOpenChannelEnum`), subscribes via `EvtSubscribe` (push), renders events to XML (`EvtRender`). **Builds per-channel XPath queries** (`buildEventIdXPath`) so Windows only delivers events the rules can match. Supports re-subscription under a mutex. |
| `EventBuffer.h/.cpp` | Thread-safe rolling buffer (`std::deque<BufferedEvent>`) with retention pruning. `snapshotFromAbsolute(absFrom, absEnd)` hands the engine its next cursor computed under the same lock as the snapshot, so events the cleanup thread pops mid-pass are never skipped. Counts events evicted before any pass saw them. |
| `BufferedEvent.h` | The event struct: rendered XML, receive timestamp, parsed field cache (`CachedField` = value + lowercased narrow copy), lazily lowercased XML for `keywords`. |
| `FieldResolver.h/.cpp` | Parses event XML into a flat field map (`EventID`, `Channel`, `Computer`, `Provider`, `EventData.*`). The field cache is warmed once per event so all rules share O(1) lookups. `canonicalFieldKey()` / `lookupField()` are the compiled-rule fast path; `eventDedupKey()` hashes (channel, EventRecordID). |
| `Rule.h` | The `Detection` struct (one Sigma rule), `SigmaField`, `Action`, `CondNode` (compiled condition AST). Rule types: Simple, Threshold, Sequence. `compileDetection()` precomputes cache keys, lowercased values, regexes and the AST once per rule. |
| `RuleEngine.h/.cpp` | The correlation engine. Evaluates rules against new events each pass from an immutable `RuleSet` (built per `reload()`, swapped via `shared_ptr` so a reload can never free rules a pass is reading). Index buckets: catch-all, by channel, by Sigma category (from one (channel, EventID)→category table, own + parent category), unmapped-category, unknown-service. **Derives per-channel XPath queries** (`deriveChannelQueries`) from the compiled condition (`a or b` with an EventID only in `a` is unrestricted) and from the category table for category rules. **Severity-based selection** for Simple rules with `also_matched`. `RuleState` lives here; `pruneStates()` drops idle groups and states of unloaded rules. |
| `YamlRuleLoader.h/.cpp` | Parses Sigma YAML into `Detection` structs. Expands `@@list` references. Validates `group_by` for threshold rules. `loadRules()` returns a `LoadSummary` (what parsed is applied; failures are counted and named once). |
| `Forwarder.h/.cpp` | Dispatches actions (`forward_event`, `alert`, `forward_buffer`) to file/HTTP destinations. Resolves destination names from `Config`, builds a `FormatContext` (`RuleMeta` + action + evidence + `also_matched`) and writes every `FormattedPayload` the formatter returns. `http(s)://` destinations go through its own `PostWorker` spool (never blocks the engine thread; independent of the server mirror) with the format's headers in the spool record; `format=sentinel` registers an OAuth2 source with the worker. Mirrors alerts/logs to the server via `AgentClient`. `SentOnce` remembers the (channel, record id) keys already sent per destination and for the mirror (TTL ≥ 4× retention), so overlapping rules never deliver an event twice to the same place. |
| `OutputFormat.h/.cpp` | Destination document shapes selected by `?format=`: `raw` (Windows event XML lines / text alert; the default), `json` (ELF flat doc), `ecs` (Elastic Common Schema; three layers: common fields, Sigma-category → `event.category/type`, per-event specializations for Security 4688/4624/4625/5156/1102, Sysmon 1/3, System 7045, PowerShell 4104; alerts add `rule.*`, `event.severity`, `threat.*` from `attack.*` tags), `hec` (Splunk envelope), `gelf` (GELF 1.1, flat `_` fields), `sentinel` (Logs Ingestion rows). Chunks NDJSON at 1,000 docs / 2 MB, Sentinel arrays at 1,000 rows / 1 MB, GELF one message per payload. Evidence capped at `AgentClient::MAX_ALERT_EVIDENCE_EVENTS` with `evidence_truncated`. |
| `AgentClient.h/.cpp` | WinHTTP client. Polls `/config/{agent_id}` (with `known_hash` so an unchanged ruleset costs nothing), pushes `/alerts` + `/logs` through a `PostWorker`. Applies server config (type-checked JSON reads), writes rules binary + atomically (only when bytes changed; honors `enabled`), chunks `/logs` batches, caps alert evidence. |
| `SpoolQueue.h/.cpp` | Disk-backed FIFO (`SpoolQueue`: record v2 `"ELF2"[url][headers][body]`, v1 records still read; ack-after-success, corrupt entries dropped, bounded) + the sender thread (`PostWorker`: 2xx ack, permanent 4xx dropped with the response logged, transient failures requeued with backoff, bearer token scoped to the server URL, per-entry header block, OAuth2 client-credentials token cache per URL prefix with one refresh on 401, stop never waits on the server). |
| `HttpClient.h/.cpp` | Low-level WinHTTP wrapper (POST/GET; `HttpRequestOptions` = content type + headers + lab-only `insecure` certificate flag). Reports the HTTP status (`isPermanentFailure`), fails on a truncated body. User agent `ELF-Agent/<ELF_AGENT_VERSION>`. |
| `EventRender.h/.cpp` | Pretty-prints event XML (one tag per line) for alert payloads. |
| `EventQueryCollector.h/.cpp` | On-demand historical pull: enumerates a channel with `EvtQuery`/`EvtNext` and streams batches back to the server (used by the "Collect logs" UI command). |
| `XmlPretty.h/.cpp` | XML pretty-printer helper. |
| `Console.h/.cpp` | Logging sinks + console utilities (disables QuickEdit mode so a mouse click can't pause output). Crash handlers: `installCrashHandlers()` on the main thread, `runGuarded(name, fn)` for every worker thread (MSVC keeps `std::set_terminate` per thread; without it a worker-thread exception surfaces as a bare `SIGABRT` with no thread name or exception text). |

### 3.2 Threading model

The agent starts these threads in `main.cpp`:

| Thread | Loop | Purpose |
|--------|------|---------|
| EventCollector | Windows callback | `EvtSubscribe` push callback; receives events and pushes them into `EventBuffer`. |
| Buffer cleanup | 1s | Drops events older than `retention_seconds` from the front of the deque. |
| Status | 5s | Prints `[STATUS] Buffered events: N`. |
| Rule engine | 2s | `RuleEngine::evaluateOnce()` processes newly-arrived events. |
| Rule reload | 60s | Re-reads `rules/*.yaml` from disk; hot-swaps the ruleset. **Re-derives the XPath filter and re-subscribes** the EventCollector. |
| Server poll | `poll_interval_seconds` | `AgentClient` polls `/config/{agent_id}`; on a ruleset/config change, applies it and **re-subscribes**. |

All threads share the `EventBuffer`, `RuleEngine`, `Forwarder`, and
`AgentClient` via references; each guards its mutable state with a mutex
(`m_bufferMutex`, `m_rulesMutex`, `m_mutex`, etc.).

### 3.3 The event pipeline

```
Windows Event Log
      │ (EvtSubscribe push, XPath-filtered)
      ▼
EventCollector ──► EventBuffer (deque, retention-pruned)
                        │
                        ▼ (every 2s)
                  RuleEngine::evaluateOnce()
                        │
                        │  for each new event:
                        │    1. populateFieldCache (parse XML once)
                        │    2. extract channel → look up candidate rules
                        │    3. evaluate catch-all + channel + category rules
                        │    4. Simple rules: collect candidates, fire highest-severity
                        │       Threshold/Sequence: fire independently
                        │    5. on fire: runFireActions → Forwarder
                        ▼
                  Forwarder
                   ├── file:// → append JSONL
                   ├── http:// → POST JSON
                   └── AgentClient ──► server /alerts, /logs
```

### 3.4 Rule index (fast event→rule filtering)

With 1000+ rules, iterating every rule against every event is the dominant
cost. Most Sigma rules declare a `logsource.service` (e.g. "powershell",
"security") that maps to a specific Windows channel. `RuleEngine` indexes
rules into three buckets at `reload()` time:

- `m_catchAllRules`: rules with no service AND no category (apply to every
  event; backward-compatible).
- `m_categoryRules`: rules with a category but no service (apply to events
  whose Sigma category matches; checked via `eventSigmaCategory`).
- `m_channelRules`: map from lowercase channel name → rules whose
  `logsource.service` maps to that channel.

For each event, the engine extracts the channel once, then evaluates only
the catch-all rules + the channel-indexed rules for that channel + the
category rules that pass a per-event check. With 1000 rules and ~20 rules
per channel, this is a ~50x reduction in `matchEvent` calls.

### 3.5 XPath subscription filtering

`RuleEngine::deriveChannelQueries()` walks the enabled rules and produces a
`vector<(channel, EventID-set)>`:

1. For each rule, determine the channels it can match (service→channel via
   `sigmaServiceChannelMap`, category→channel via `categoryChannelMap`).
2. For each channel, union the rule's `EventID` values (`extractEventIds`
   walks selections + sequence stages).
3. A channel with no explicit EventID gets an empty set → "subscribe to all
   events on this channel".
4. If any catch-all rule exists, return empty → caller falls back to
   `subscribeAll()`.

`main.cpp::buildChannelQueries()` converts this to a `vector<ChannelQuery>`
(channel path + XPath string) and calls `EventCollector::subscribeWithQueries()`.
`buildEventIdXPath()` builds the `*[System[EventID=N or ...]]` string.

Re-subscription happens on:
- Startup (initial subscription).
- Local hot reload (60s thread detects changed rules).
- Server-driven ruleset change (AgentClient applies new rules, calls the
  `ResubscribeFn` callback).

All subscription operations are guarded by `m_subMutex` so a re-subscribe
during an active subscription callback is safe.

### 3.6 Severity-based alert selection

When multiple **Simple** rules match the same event, only the highest-severity
one fires its `alert`/`forward_buffer` actions. This is implemented in
`RuleEngine::evaluateOnce()`:

1. `evaluateRule()` for a Simple rule does **not** call `runFireActions`
   immediately. It runs `forward_event` (continuous, never suppressed),
   records per-rule dedup, and reports the rule as a **candidate** via an
   out-parameter (`simpleCandidate`).
2. The `evaluateOnce` loop collects all Simple candidates across the three
   rule buckets for the event.
3. After all buckets are evaluated, it picks the candidate with the highest
   `severityRank()` (critical=5 … unknown=0). Ties are broken by rule order
   (first candidate wins, matching catch-all → channel → category order and
   file load order within a bucket).
4. Only the winner's `runFireActions` is called, with the ids of the other
   candidates as `alsoMatched` (file header `also_matched:`, server payload
   `also_matched[]`) so suppressed detections stay visible.

The pass itself never stops early: a `forward_buffer` fire does not clear
the buffer or break out of the bucket loops (every rule sees every event);
`runFireActions` keeps a per-rule absolute cursor so a rule does not re-send
events it already sent.

**Threshold and Sequence rules are NOT subject to selection**; they fire
independently inside `evaluateRule` (a correlation alert fires whenever its
own condition is met). `forward_event` is never suppressed (every matching
Simple rule forwards its event stream regardless of which rule wins the
alert).

The rule's Sigma `level` is threaded through the fire chain:
`RuleEngine::runFireActions` → `Forwarder::forwardAlert/forwardBuffer` →
`AgentClient::reportAlert/reportLogs` → server `POST /alerts` payload `level`
field → stored in the `alerts.severity` column.

### 3.6.1 Duplicate-alert prevention (`alert` + `forward_buffer`)

A rule may declare BOTH `alert` AND `forward_buffer` actions (common for
high-severity rules that want to both notify and ship context). Without a
guard, this produces TWO alerts on the server for the same event:

- `alert` action → `reportAlert` → POST `/alerts` (the real alert).
- `forward_buffer` action → `reportLogs` → POST `/alerts` (a "forward_buffer
  fired" notification, so forward_buffer-only rules still appear in the
  Alerts view) + POST `/logs` (the buffer batch).

`runFireActions` tracks an `alertAlreadyFired` flag as it iterates the
rule's actions in order. When `forward_buffer` runs after an `alert`
already fired, it passes `skipAlertNotification=true` through
`Forwarder::forwardBuffer` → `AgentClient::reportLogs`, which **skips the
POST `/alerts` notification** and only sends the POST `/logs` batch. The
result: exactly ONE alert reaches the server, plus the buffer batch lands
in the Logs view.

forward_buffer-ONLY rules (no `alert` action) keep their notification alert
because `alertAlreadyFired` stays `false` (the default). The per-rule
`EventRecordID` dedup in `RuleState.alertedRecordIds` does NOT catch this
case on its own; it guards against a second `evaluateOnce` pass re-firing
the same event, not two actions firing within one pass.

### 3.7 Dedup and state management

`RuleState` (per rule, keyed by `rule.id` + group values) holds:
- `alertedRecordIds`: EventRecordIDs that already fired an alert (per-rule
  dedup, 30-min TTL, pruned every 60s).
- `matchTimes` / `thresholdRecordIds` / `matchRecordIds`: threshold sliding
  window.
- `nextStage` / `windowStart` / `sequenceEvents`: sequence progress.

Dedup is **content-based** (keyed by the stable per-event `EventRecordID`),
not index-based, so it survives the deque shifting when cleanup pops front
events. The engine tracks `m_evaluatedCount` so each pass only processes
newly-arrived events (prevents threshold inflation and simple-rule re-fires).

---

## 4. Server Architecture (Python)

The server is a single FastAPI app in `server/main.py` (the web UI is an
embedded HTML/JS string served at `/`). Data lives in SQLite (`db.py`).

### 4.1 Data model (`db.py`)

| Table | Purpose |
|-------|---------|
| `agents` | Registered agents (id, group, hostname, last seen, cumulative metrics counters). |
| `groups` | Agent groups (each agent belongs to one group; rules are per-group). |
| `rules` | Sigma rules (YAML body, group, enabled flag). |
| `lists` | Reusable value lists (name, values). |
| `alerts` | Alerts reported by agents (id, agent_id, rule_id, message, **severity**, received_at, payload). |
| `logs` | Forwarded log batches. |
| `metrics` | Time-bucketed metrics for the graphs. |

The `alerts.severity` column is added via `ALTER TABLE` migration in both
`store_alert()` and `list_alerts()` so existing databases upgrade in place.

`list_alerts()` sorts by a severity rank (critical=5 … unknown=0) descending,
then by `received_at` descending, so the analyst sees the most severe recent
alerts first.

### 4.2 API surface (`main.py`)

The agent-facing endpoints:
- `GET /config/{agent_id}`: returns effective config + ruleset; accepts
  cumulative metrics counters as query params.
- `POST /alerts?agent_id=`: agent reports an alert (payload includes `level`).
- `POST /logs?agent_id=`: agent forwards a log batch (payload includes `level`).

The UI-facing endpoints cover CRUD for agents, groups, rules, lists, plus
read/clear for alerts and logs, metrics, and the agent binary serving +
companion-file install endpoints. See `server/README.md` for the full table.

### 4.3 Web UI

The UI is a single-page app embedded as a JS string in `main.py`. Tabs:
Agents, Groups, Rules, Lists, Alerts, Metrics, Logs. The **Alerts** tab
shows a severity badge per row (color-coded: red=critical, orange=high,
yellow=medium, blue=low, gray=informational/unknown) and sorts by severity.

---

## 5. Build & Test

### 5.1 Build the agent

```powershell
cmake -B build -S .
cmake --build build --config Release --target efficient_log_forwarder
```

Dependencies (`yaml-cpp 0.8.0`, `nlohmann/json v3.11.3`) are pulled via CMake
`FetchContent` on first build. The agent links `wevtapi` and `winhttp`.

On Linux (Debian/Ubuntu package names):

```bash
sudo apt-get install -y cmake g++ pkg-config libsystemd-dev libcurl4-openssl-dev
cmake -S . -B build -DCMAKE_POLICY_VERSION_MINIMUM=3.5 -DCMAKE_BUILD_TYPE=Release
cmake --build build -j"$(nproc)"
```

CMake picks `src/platform/win` or `src/platform/linux` by platform; the
core sources are the same list on both. CI builds and tests both
(`agent-build-test` on `windows-2022`, `agent-build-linux` on
`ubuntu-latest`), and the release carries both binaries.

### 5.2 Build and run the tests

```powershell
cmake --build build --config Release --target test_rule_engine
cd build\Release
.\test_rule_engine.exe
```

```bash
(cd build && ./test_rule_engine)      # Linux
```

The test harness (`tests/test_rule_engine.cpp`) is a standalone console app
(no WIN32 subsystem) with a custom `CHECK` macro. It writes YAML rule files to
temp directories, loads them via `loadRulesFromDirectory`, pushes events to an
`EventBuffer`, runs `evaluateOnce`, and asserts on `alerts.jsonl` content.
Its checks cover rule parsing, field resolution, condition evaluation,
threshold/sequence logic, action dispatch, reusable-list expansion,
`group_by`/`threshold_op`, XPath query derivation, severity selection,
spool and wire-format behavior, the seeded kill-chain suite and the SIEM
output formats (the full list is in `docs/USAGE.md` §11). The Windows-only
sections (live `EvtSubscribe`, bookmarks, XPath limits) are under
`#ifdef _WIN32`; the Linux section (journal rendering, the audit joiner,
UTF-8 validation) under `#ifndef _WIN32`; the Linux ECS mapping is tested
on both from hand-built events. The suite pins the host product it
evaluates as (`setHostSigmaProductForTests`) so Windows rules behave the
same wherever the harness runs.

### 5.3 Run the server

```bash
cd server
docker compose up -d --build
```

The server listens on port 8000. See `server/README.md`.

---

## 6. Extending the System

### Add a new Sigma field modifier
1. `Rule.h`: add the modifier to the `SigmaField::op` comment + the `op` string.
2. `YamlRuleLoader.cpp`: parse the modifier from the YAML field key (after `|`); set `op` to the new string.
3. `Rule.cpp::evalSigmaField`: implement the match logic in the `matchOne` lambda (add a new `if (f.op == "...")` branch). For stateful matchers (e.g. CIDR), add a helper function above `evalSigmaField`.
4. Add a test in `tests/test_rule_engine.cpp`.

> **Example (`|cidr`, IP-in-network):** the modifier is parsed in `YamlRuleLoader.cpp` (sets `op = "cidr"`), and the match is implemented in `Rule.cpp` via `fieldInCidr()` → `parseIp()`/`parseCidr()`/`ipInCidr()`. IPv4 addresses are stored as IPv4-mapped IPv6 (`::ffff:a.b.c.d`) for uniform 128-bit math, but the family flag (`ParsedAddr::v6`) prevents cross-family matches. The prefix is offset by 96 bits for IPv4 so `/8` means the first 8 bits of the 32-bit IPv4 portion, not the 128-bit mapped address.

### Add a new action type
1. `Rule.h`: add the action type string.
2. `Forwarder.cpp`: implement the dispatch (in `forwardAlert`/`forwardBuffer`/`forwardEvent` or a new method).
3. `RuleEngine.cpp::runFireActions` / `runForwardEventActions`: call the new action.
4. Add a test.

### Add a new output format
1. `Config.cpp::parseDestinationUrl`: accept the name in the format whitelist (and any new query keys in `DestinationOptions`).
2. `OutputFormat.cpp`: add a builder (`build<Format>Doc`) and wire it in `docFor()`; set the content type / chunking rule in `packDocs()` and the auth header in `addAuthHeader()`.
3. `server/models.py::validate_destination`: mirror the whitelist and any required options so the Groups tab rejects what the agent would.
4. `tools/siem-sink.py`: add a `--mode` so the format can be verified offline; document the recipe in `docs/SIEM.md`.
5. Add tests (one builder test per event shape, plus the chunking rule).

### Add a new rule type (beyond simple/threshold/sequence)
1. `Rule.h`: add the `Detection::Type` enum + fields.
2. `RuleEngine.cpp::evaluateRule`: add the branch.
3. `YamlRuleLoader.cpp`: parse the new `elf:` keys.
4. Decide whether it participates in severity selection (currently only Simple
   rules do; threshold/sequence fire independently).
5. Add tests.

### Change the XPath derivation
- `RuleEngine::deriveChannelQueries()` (in `RuleEngine.cpp`) is the one
  place that defines the channel→EventID mapping. `categoryChannelMap()` and
  `sigmaServiceChannelMap()` define the service/category→channel maps.
- `EventCollector::buildEventIdXPath()` builds the XPath string from an
  EventID set.
- `main.cpp::buildChannelQueries()` wires them together and handles the
  `[collect] channels` override + catch-all fallback.

### Change severity selection
- `severityRank()` (in `RuleEngine.cpp`) defines the ranking.
- The selection loop is step 4 in `evaluateOnce()` (the `simpleCandidates`
  collection + winner pick). Threshold/Sequence are excluded by design.
- `runFireActions` threads `rule.level` through the fire chain to the server.

---

## 7. Key Design Decisions

1. **Agent is the HTTP initiator.** The server never pushes to the agent; the
   agent polls. This keeps the agent firewall-friendly (one outbound
   connection) and avoids needing a listening port on the agent.

2. **XPath filtering is auto-derived, not operator-configured.** The operator
   writes Sigma rules; the agent figures out which channels/EventIDs to
   subscribe to. The optional `[collect] channels` is an escape hatch, not the
   primary path. Catch-all rules disable filtering (correctness guard).

3. **Severity selection applies only to Simple rules.** Threshold/Sequence
   rules fire independently, so a correlation alert fires whenever its
   own condition is met. `forward_event` is never suppressed (every matching rule
   forwards its event stream).

4. **Static CRT (`/MT`).** The agent has no external DLL dependencies and runs
   on a clean Windows install. This simplifies deployment to locked-down hosts.

5. **Content-based dedup.** Dedup is keyed by the stable per-event
   `EventRecordID`, not buffer index, so it survives the deque shifting when
   cleanup pops front events.

6. **Field cache warmed once per event.** The XML is parsed into a flat field
   map once per event; all rules share O(1) hash lookups. This is what lets the engine
   scale to 1000+ rules.

7. **The server holds the authoritative copy.** The agent's local `rules/` and
   `config.ini` are a bootstrap; the server overwrites them on each
   successful poll. Local edits are for offline/testing use.
