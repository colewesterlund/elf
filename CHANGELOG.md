# Changelog

All notable changes to ELF are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow
[SemVer](https://semver.org/).

## [Unreleased]

## [1.0.0] - 2026-10-20

First public release: a Windows agent, a Linux agent and the console. The
agent and server had been developed privately since 2026-09; this entry
summarizes what ships.

### Added
- **C++17 Windows agent** that subscribes to the Event Log (`wevtapi`) and
  evaluates **Sigma rules** on the host: simple, threshold (`group_by`,
  `threshold_op`, `distinct`, `timeframe`) and sequence rules; modifiers
  `contains`/`startswith`/`endswith`/`re`/`exists`/`all`/`cidr`; full
  `condition` grammar with `1 of` / `all of`; reusable `@@lists`.
- **C++17 Linux agent** (`elf-agent`, x86_64, glibc) with the same rule
  engine, buffer, destinations and server protocol. It reads the systemd
  journal through `libsystemd` with per-identifier matches derived from the
  rules (Sigma `service: sshd|sudo|cron|kernel|systemd|auditd`,
  `syslog`/`auth` for the whole journal), keeps its journal cursor across
  restarts, and joins the records of one kernel audit event so an `EXECVE`
  record carries the executable, pid, audit key and the full command line.
  `product: linux, category: process_creation` rules run on those records;
  `Image`/`CommandLine` resolve as on Windows. An agent skips rules written
  for the other operating system. `config.ini` is read from `$ELF_CONFIG`,
  next to the binary, or `/etc/elf/config.ini`; the data root is
  `/var/lib/elf` (`ELF_DATA_DIR`).
- A portable core (`src/`) behind `Platform.h` and `EventSource.h`, with
  `src/platform/win` and `src/platform/linux`; the test harness builds and
  runs on both platforms.
- Linux ECS documents follow the Filebeat `system`/`auditd` modules
  (`event.module`, `event.dataset`, `journald.fields.*`, `event.sequence`),
  with specializations for `execve`, sshd logins, sudo, account and group
  changes, systemd unit starts/stops and cron.
- Console: **Add New Agent** offers Windows or Linux. For Linux it generates
  a bash installer (dedicated `elf` system user or an existing account,
  systemd unit with `ProtectSystem=strict`, optional execve audit rule plus
  journald audit socket) and a matching cleanup script;
  `GET /agent/binary?os=linux` serves the Linux binary; the rule importer's
  product filter offers `linux`.
- Sample rules seeded into `default` (Windows) and `linux-servers` (Linux:
  SSH brute force, sudo command forwarding, download piped to a shell,
  `/etc/shadow` on a command line, account or group created, crontab
  edited; also in `rules/lin_*.yaml`). The demo groups with the kill-chain
  rules are opt-in (`ELF_SEED_TEST_DATA=1`). Each sample rule's description
  names what produces its event; nothing that triggers detections ships
  with the agent, the console or the install scripts.
- **Rule-derived XPath pre-filter**: the agent asks Windows only for the
  EventIDs some rule can match (structured `<QueryList>` chunked at 20 ids, since
  Windows rejects more than 23 terms, with a `*` fallback), cutting event
  load by ~90 % on a busy domain controller in a three-host lab.
- Actions `forward_event`, `alert`, `forward_buffer`, each to a named
  destination; severity-based selection when several simple rules match one
  event, with the losers recorded as `also_matched`. Rules load in file-name
  order, so a tie between equally severe rules resolves the same way on
  every host.
- **SIEM-native output** via destination `?format=`: `json`, `ecs`
  (winlogbeat-shaped Elastic Common Schema with per-event mappings for
  Security 4688/4624/4625/5156/1102, Sysmon 1/3, System 7045, PowerShell
  4104, ATT&CK `threat.*` on alerts), `hec` (Splunk HTTP Event Collector),
  `gelf` (Graylog 1.1), `sentinel` (Azure Monitor Logs Ingestion API with
  OAuth2 client credentials). Chunked POSTs, disk-backed spool with backoff,
  secrets via `env:VAR`, URL redaction in logs. Recipes in `docs/SIEM.md`
  and an offline stand-in in `tools/siem-sink.py`.
- **Least-privilege Windows service**: dedicated local account, *Log on as a
  service* + *Manage auditing and security log* + Event Log Readers only,
  recovery actions, writable state confined to `%ProgramData%\ELFAgent`,
  size-rotated logs, per-channel bookmarks (no events lost across restarts),
  disk-backed spools for the server mirror and for SIEM destinations
  (ack-after-success, permanent 4xx dropped and logged, oldest-first
  eviction at the size cap).
- **Management server** (FastAPI + SQLite, Docker): groups, per-group
  destinations/retention/poll/mirror toggle, Sigma rule editor with
  validation aligned to the agent loader, **bulk import** of Sigma zips and
  SigmaHQ release packages with a severity → action map and preview/commit,
  reusable lists, alerts with evidence (threshold window / sequence chain),
  forwarded-log viewer, on-demand historical collection, metrics with
  savings (events/bytes created vs forwarded) and Chart.js charts, audit
  log, users with `admin` / `rule_contributor` / `viewer` roles, per-agent
  enrollment tokens, generated PowerShell install script (GPO/SCCM ready).
- **Seeded 12-rule MITRE ATT&CK kill chain** (`win_kc_01..12`), each
  paired with a verified Atomic Red Team test, plus a YAML-parity test.
- `ruleset_hash` / `known_hash` poll protocol so an unchanged ruleset costs
  one small request; binary + atomic rule writes on the host.
- Hardened container (non-root via `gosu`, minimal capabilities), SBOM,
  `pip-audit` in CI, a GitHub Actions pipeline that builds and tests both
  agents and publishes the release artifacts (`SHA256SUMS.txt`,
  `SHA256SUMS-linux.txt`) and the console image on ghcr.io.
- `--version` flag; `User-Agent: ELF-Agent/<version>`.
- **Investigation keys**: every rule fire gets a 16-hex alert id, written on
  the alert and on every event of the batch that fire forwarded
  (`elf.rule_id` / `elf.alert_id`, `_elf_*` for GELF, `RuleId` / `AlertId`
  for Sentinel, `alert_id:` header on raw alerts), shown in the alert detail
  and the Logs tab, so one SIEM search returns an incident's alert plus its
  context and a rule-id search returns everything a rule produced.
- **One copy per destination**: however many rules ask for an event, each
  destination and the server mirror receive it once (keyed on channel +
  record id, remembered for ≥ 4× the buffer retention), so overlapping
  `forward_buffer` / `forward_event` rules never duplicate events in the
  SIEM or inflate the forwarded counters.
- SigmaHQ bulk import counts a rule id once across the nested release
  packages (core ⊂ core+ ⊂ core++ ⊂ all); the picker allows one tier plus
  the emerging-threats addon, and the preview reports duplicates.
- Browser end-to-end test (Playwright) and an inline-UI static check in CI.
- Sample rule `win_compliance_account_changes.yaml`: forwards account,
  group-membership, permission and audit-policy changes unchanged, the
  record-keeping counterpart to `win_forward_all_logons.yaml`.

### Security
- Server dependencies pinned to current releases (FastAPI 0.150.0, Starlette
  1.7, uvicorn 0.54.0, pydantic 2.14.1, python-multipart 0.0.32, bcrypt
  5.0.0, PyYAML 6.0.3); `pip-audit --strict` reports no known
  vulnerabilities. Passwords longer than 72 bytes (bcrypt's input limit) are
  rejected with a clear message instead of a server error.

### Performance
- 3,001 rules (SigmaHQ-shaped) against 2,000 mixed events: ~0.7–1.0 ms per
  event on a Windows Server 2022 lab box (Release), down from 29 ms before
  compile-once rules and the category index. 719 agent checks (723 with the
  scale block).

### Fixed (during private development, kept for the record)
- A single oversized `forward_buffer` batch rejected with HTTP 422 blocked
  every alert behind it in the spool; permanent 4xx are now dropped and
  batches are chunked.
- Server-pushed relative `file://` paths resolved against `Program Files`
  (unwritable for the service); now under `%ProgramData%\ELFAgent`.
- Worker-thread exceptions terminated the service with an empty detail;
  every thread now runs under a crash handler and `/config` JSON is
  type-checked.
- Evaluation cursor skipped events popped by retention during a pass;
  `forward_buffer` cleared the buffer for every other rule; reload could
  free rules mid-pass; `timeframe: 5m` parsed as 5 seconds; dedup collided
  across channels; sequences could not restart; disabled rules kept running
  on agents; every poll rewrote every rule file (CRLF churn).
- Duplicate server alert when a rule had both `alert` and `forward_buffer`.
- UTF-16 → UTF-8 narrowing corrupted non-ASCII event text.

[Unreleased]: https://github.com/colewesterlund/elf/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/colewesterlund/elf/releases/tag/v1.0.0
