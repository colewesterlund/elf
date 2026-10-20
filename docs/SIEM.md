# Sending ELF output to your SIEM

ELF evaluates Sigma rules **on the host** and forwards only what a rule asked
for: the alert, the triggering event, and the events that formed the
correlation. A destination URL's `?format=` option chooses the document shape,
so the same rule action can feed Splunk, Graylog, Microsoft Sentinel, an
Elastic-style NDJSON endpoint, or a file, without a shipper, a parser or an extra
agent.

```
splunk   = https://splunk.example.com:8088/services/collector/event?format=hec&token=<HEC token>&index=elf
graylog  = http://graylog.example.com:12201/gelf?format=gelf
sentinel = https://<dce>.ingest.monitor.azure.com/dataCollectionRules/<dcr-id>/streams/Custom-ELF_CL?api-version=2023-01-01&format=sentinel&tenant=<tenant-id>&client=<app-id>&secret=env:ELF_SENTINEL_SECRET
```

Put these on the **Groups** tab (every agent in the group inherits them) or in
the agent's `config.ini [destinations]`, then reference the name from a rule
action:

```yaml
elf:
  actions:
    - type: alert
      destination: splunk
      message: "Encoded PowerShell command line"
```

## How delivery works

| | |
|---|---|
| **Transport** | HTTP POST (WinHTTP on Windows, libcurl on Linux) through a disk-backed spool (`%ProgramData%\ELFAgent\spool\destinations\` or `/var/lib/elf/spool/destinations/`). A SIEM outage never blocks the rule engine; entries are retried with exponential backoff (1 s → 60 s) and survive agent restarts. 4xx responses are logged once and dropped (retrying a rejected document can never succeed); 5xx and transport errors are retried. |
| **Batching** | `json` / `ecs` / `hec`: up to 1,000 documents or 2 MB per POST. `sentinel`: up to 1,000 rows or 1 MB per POST (the Logs Ingestion API limit). `gelf`: one message per POST (what a GELF HTTP input accepts). A `forward_buffer` of 2,500 events becomes three POSTs. |
| **Alerts** | One document per alert, carrying the rule (`id`, `name`, `level`, `description`, ATT&CK tags), the message, the triggering event, correlation evidence (the events that filled a threshold window or formed a sequence, capped at the most recent 500 with a `*_truncated` count), and `also_matched` (lower-severity rules that matched the same event but were outranked). |
| **Events** | `forward_event` / `forward_buffer` produce one document per event with every field preserved (original case): the `<Data Name=…>` fields of a Windows event, or the journal fields of a Linux entry (`Message`, `SYSLOG_IDENTIFIER`, `pid`, `exe`, the audit record's `type`, `exe`, `a0..aN`, `key`, ...). |
| **Secrets** | `token=env:VAR` / `secret=env:VAR` read the service's environment instead of the URL. The agent logs the URL with options stripped, so a token never reaches `error.log`. The server rejects a secret over plain `http://` unless `insecure=1` is present (lab only; on `https://` the same flag also disables certificate validation). Sentinel requires `https://`. |
| **Mirror** | Independent of SIEM destinations, alerts also mirror to the ELF server (Alerts tab). Uncheck **Mirror logs** on the group to stop mirroring log batches while keeping alerts. |

### Investigation keys

Every rule fire gets a 16-character **alert id**. The agent writes it on the
alert *and* on every event of the batch that fire forwarded, next to the rule
id, so one search pulls an incident together and a rule-id search returns
everything that rule ever produced:

| format | rule id | alert id |
|---|---|---|
| `json`, `hec` (default `event=json`) | `elf.rule_id` | `elf.alert_id` |
| `ecs`, `hec` with `event=ecs` | `rule.id` (alerts) and `elf.rule_id` | `elf.alert_id` |
| `gelf` | `elf_rule_id` (`_elf_rule_id` on the wire) | `elf_alert_id` |
| `sentinel` | `RuleId` | `AlertId` |
| `raw` alert file | `rule_id:` header line | `alert_id:` header line |

```spl
index=elf elf.alert_id="5f1c0b7e9a2d4c88"                      -- Splunk: the alert and its context events
index=elf elf.rule_id="win_kc_11_stage_exfil" | stats count by elf.alert_id
```
```
elf_alert_id:5f1c0b7e9a2d4c88                                   -- Graylog
```
```kusto
ELF_CL | where AlertId == "5f1c0b7e9a2d4c88"                    // Sentinel
ELF_CL | where RuleId == "win_kc_11_stage_exfil" | summarize count() by AlertId, bin(TimeGenerated, 1h)
```

`forward_event` streams carry the rule id only (there is no alert), and an
event reaches a given destination at most once, so a batch is attributed to
the first rule fire that asked for it. The same keys appear on the ELF server:
*Investigation keys* in an alert's detail and the *Alert ID* column on the
Logs tab.

Verify any destination offline with the stand-in sink in `tools/siem-sink.py`
(see [Testing without a SIEM](#testing-without-a-siem)).

---

## Splunk (HTTP Event Collector)

**1. Create a HEC token.** Settings → Data Inputs → HTTP Event Collector →
*Global Settings*: enable *All Tokens*, note the port (default **8088**) and
whether SSL is enabled. *New Token*: name `elf`, source type **Automatic**,
pick the index (`elf` below), save, copy the token value.

**2. Add the destination** (Groups tab or `config.ini`):

```
splunk = https://splunk.example.com:8088/services/collector/event?format=hec&token=<HEC token>&index=elf
```

Options:

| option | meaning |
|---|---|
| `token=` | sent as `Authorization: Splunk <token>` (required) |
| `index=` | envelope `index`; omit to use the token's default |
| `sourcetype=` | override the default `elf:alert` / `elf:event` |
| `event=ecs` | put an ECS document inside the envelope instead of ELF's flat JSON |
| `insecure=1` | accept Splunk's self-signed certificate (lab only) |

**3. Search.** The envelope sets `host` (the Windows computer name),
`source=elf`, `sourcetype=elf:alert` or `elf:event`, and `time` from the
event's own `TimeCreated`.

```spl
index=elf sourcetype=elf:alert
| table _time host elf.rule_id elf.level elf.message event_data.NewProcessName event_data.CommandLine

index=elf sourcetype=elf:alert elf.level IN (high, critical)
| stats count by host, elf.rule_name

index=elf sourcetype=elf:event event_id=4688
| stats count by event_data.NewProcessName
```

A `props.conf` stanza is not needed; HEC's `/event` endpoint stores the JSON
as-is and Splunk auto-extracts the fields. If you prefer the Splunk CIM, use
`event=ecs` and map `process.command_line` → `Processes.process` etc. in a
calculated-field alias.

**Document (`format=hec`, default `event=json`):**

```json
{"time":1760923021.0,"host":"WS07","source":"elf","sourcetype":"elf:alert","index":"elf",
 "event":{"@timestamp":"2026-10-20T01:17:01.000Z","host":"WS07","channel":"Security","provider":"Microsoft-Windows-Security-Auditing",
          "event_id":4688,"record_id":881234,
          "event_data":{"NewProcessName":"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe","CommandLine":"powershell -enc SQBFAFgA…","SubjectUserName":"alice"},
          "elf":{"kind":"alert","action":"alert","agent_id":"ws07","rule_id":"win_kc_01_encoded_ps","rule_name":"Encoded PowerShell","level":"high",
                 "category":"process_creation","message":"Execution: encoded PowerShell command line","also_matched":["win_ps_generic"]}}}
```

---

## Graylog (GELF HTTP input)

**1. Create the input.** System → Inputs → *Select input* → **GELF HTTP** →
*Launch new input*. Port **12201**, bind address `0.0.0.0` (or the node IP),
leave *Enable Bulk Receiving* off; ELF sends one message per request. TLS is
optional; if you enable it with a self-signed certificate, add `insecure=1`.

**2. Add the destination:**

```
graylog = http://graylog.example.com:12201/gelf?format=gelf
```

**3. Search.** Graylog strips the leading underscore from custom fields, so
ELF's `_elf_rule_id` is searchable as `elf_rule_id`, `_event_data_CommandLine`
as `event_data_CommandLine`, and so on. `level` follows syslog severity
(critical 2, high 3, medium 4, low 5, events 6), so the built-in *Level*
widgets work.

```
elf_kind:alert AND elf_level:(high OR critical)
elf_rule_id:win_kc_06_brute_force
event_id:4688 AND event_data_NewProcessName:*\\certutil.exe
```

**Stream for alerts:** Streams → *Create stream* → rule
*Field* `elf_kind` *must match exactly* `alert`. Attach an *Event Definition*
(Alerts → Event Definitions) with the filter `elf_kind:alert AND elf_level:critical`
to notify on critical detections.

**Document (`format=gelf`):**

```json
{"version":"1.1","host":"WS07","short_message":"Encoded PowerShell","timestamp":1760923021.0,"level":3,
 "_elf_kind":"alert","_elf_action":"alert","_elf_agent_id":"ws07","_elf_rule_id":"win_kc_01_encoded_ps","_elf_rule_name":"Encoded PowerShell",
 "_elf_level":"high","_elf_category":"process_creation","_elf_message":"Execution: encoded PowerShell command line",
 "_event_id":4688,"_record_id":881234,"_channel":"Security","_provider":"Microsoft-Windows-Security-Auditing","_event_time":"2026-10-20T01:17:01.000Z",
 "_event_data_NewProcessName":"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe","_event_data_CommandLine":"powershell -enc SQBFAFgA…",
 "_elf_evidence_count":0,"full_message":"<Event xmlns=…>…</Event>"}
```

GELF forbids nested objects, so evidence is summarized (`_elf_evidence_count`,
`_elf_evidence_record_ids`) and the trigger's full XML rides in `full_message`.
Use `format=json` to a Graylog **Raw/Plaintext HTTP** input if you need the
nested evidence array.

---

## Microsoft Sentinel (Azure Monitor Logs Ingestion API)

Sentinel ingests via a **custom table** behind a **data collection rule
(DCR)**; the agent authenticates with an **Entra app registration** using OAuth2
client credentials. One-time setup (≈15 minutes in the portal):

**1. Create the custom table.** Log Analytics workspace → *Tables* → *Create*
→ **New custom log (DCR-based)**. Table name `ELF` (the portal appends `_CL`).
Create a data collection endpoint (DCE) when prompted, or reuse one in the same
region. When asked for sample data, upload one row produced by the agent (write
a `file://output/sentinel-sample.json?format=sentinel` destination, trigger a
rule, and paste a row), or this minimal sample:

```json
[{"TimeGenerated":"2026-10-20T01:17:01.000Z","Host":"WS07","Channel":"Security","Provider":"Microsoft-Windows-Security-Auditing",
  "EventId":4688,"RecordId":881234,"Kind":"alert","Action":"alert","AgentId":"ws07",
  "RuleId":"win_kc_01_encoded_ps","RuleName":"Encoded PowerShell","Level":"high","Category":"process_creation",
  "EventData":{"NewProcessName":"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe","CommandLine":"powershell -enc SQBFAFgA"},
  "Message":"Execution: encoded PowerShell command line","AlsoMatched":[],"Evidence":[],"EventXml":"<Event>…</Event>"}]
```

Set the transformation to `source` (or `source | extend TimeGenerated = todatetime(TimeGenerated)`
if the wizard typed it as string). `EventData`, `AlsoMatched` and `Evidence`
become `dynamic` columns.

**2. Note the DCR details.** The wizard creates a DCR; open it and copy
the **Immutable Id** (`dcr-…`) from *Overview* → *JSON view*, and the DCE's
**Logs ingestion** URI (`https://<dce-name>-<id>.<region>-1.ingest.monitor.azure.com`).
The stream name is `Custom-ELF_CL`.

**3. Register an application.** Entra ID → *App registrations* → *New
registration* (`elf-agent`). Copy the **Application (client) ID** and
**Directory (tenant) ID**. *Certificates & secrets* → *New client secret*;
copy the value. Then on the **DCR** → *Access control (IAM)* → *Add role
assignment* → **Monitoring Metrics Publisher** → the `elf-agent` app. (Role
propagation can take a few minutes.)

**4. Add the destination.** Keep the secret out of the URL by putting it in the
agent service's environment. Windows services read a `REG_MULTI_SZ` value
named `Environment` under their service key (one `NAME=value` per line); set
it once as an administrator and restart the service:

```powershell
Set-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\ELFAgent `
    -Name Environment -Type MultiString -Value @('ELF_SENTINEL_SECRET=<secret>')
Restart-Service ELFAgent
```

(The value is readable only by administrators and the service account,
the same trust boundary as `config.ini`'s enrollment token.)

```
sentinel = https://<dce-name>-<id>.<region>-1.ingest.monitor.azure.com/dataCollectionRules/<dcr-immutable-id>/streams/Custom-ELF_CL?api-version=2023-01-01&format=sentinel&tenant=<tenant-id>&client=<client-id>&secret=env:ELF_SENTINEL_SECRET
```

The agent requests a token from
`https://login.microsoftonline.com/<tenant>/oauth2/v2.0/token` with scope
`https://monitor.azure.com/.default`, caches it until five minutes before
expiry, and refreshes once on a `401` before treating the response as
permanent. Rows are posted as a JSON array, chunked under the API's 1 MB limit.

**5. Query.** Data appears in `ELF_CL` within a few minutes.

```kusto
ELF_CL
| where Kind == "alert"
| project TimeGenerated, Host, RuleId, Level, Message, Process = tostring(EventData.NewProcessName), CommandLine = tostring(EventData.CommandLine)
| order by TimeGenerated desc

ELF_CL
| where Kind == "alert" and Level in ("high", "critical")
| summarize count() by Host, RuleName, bin(TimeGenerated, 1h)

// Evidence events of a threshold alert
ELF_CL
| where RuleId == "win_kc_06_brute_force"
| mv-expand Evidence
| project TimeGenerated, Host, User = tostring(Evidence.EventData.TargetUserName), Source = tostring(Evidence.EventData.IpAddress)
```

To raise Sentinel incidents, create an **Analytics rule** (Scheduled) with
`ELF_CL | where Kind == "alert" and Level in ("high","critical")`, map
`Host` → Host entity and `EventData.SubjectUserName` → Account entity, and let
ELF's `Level` drive the incident severity.

---

## Elastic / OpenSearch / anything that takes NDJSON

`format=ecs` emits Elastic Common Schema documents in the shape winlogbeat
produces (`event.*`, `process.*`, `user.*`, `source.*`/`destination.*`,
`winlog.event_data.*`, plus `rule.*`, `event.severity` and
`threat.technique.id[]` on alerts), so existing winlogbeat dashboards and
detection rules keep working. Post to an ingest endpoint or write to a file for
Filebeat/Fluent Bit to tail:

```
elastic  = https://ingest.example.com/elf/_bulk-ish?format=ecs&token=<bearer>
ecsfile  = file://output/ecs.ndjson?format=ecs
```

(`token=` is sent as `Authorization: Bearer <token>`. For Elasticsearch's own
`_bulk` API, which needs action lines, front it with Logstash's `http` input or
an ingest proxy.)

Per-event ECS specializations: Security 4688 (process start), 4624/4625
(authentication with `winlog.logon.type` names), 5156 (network connection),
1102 (audit log cleared); Sysmon 1 (process + hashes + PE metadata) and 3
(network); System 7045 (service installed); PowerShell 4104 (script block).
Every other event gets the common fields, a Sigma-category-derived
`event.category`/`event.type` when known, and `winlog.event_data.*` verbatim.

**Linux events** follow the Filebeat `system` and `auditd` modules instead
of winlogbeat: `event.module` is `auditd` (channel `audit`) or `system`,
`event.dataset` is `auditd.log`, `system.auth` or `system.syslog`,
`host.os.type` is `linux`, every journal field is under `journald.fields.*`,
and `event.sequence` carries the record id. Specializations: audit `execve`
(`process.pid/parent.pid/executable/name/command_line/args/working_directory`,
`user.id`, `auditd.log.record_type/sequence/key`, `event.outcome`), sshd
logins (`event.category: authentication`, `event.outcome`, `user.name`,
`source.ip/port`, `auth.method`), sudo (`process.command_line`,
`user.effective.name`, `event.action: sudo_command`), useradd/usermod/
groupadd (`event.category: iam`, `user.name`, `group.name`), systemd unit
starts and stops (`service.name`), cron commands.

---

## Testing without a SIEM

`tools/siem-sink.py` (standard library only) stands in for each endpoint,
checks the auth header, and pretty-prints what arrives:

```powershell
# Terminal 1: Splunk stand-in on port 8088
python tools\siem-sink.py --mode hec --token lab

# config.ini [destinations] on the agent (or the group):
splunk = http://127.0.0.1:8088/services/collector/event?format=hec&token=lab&insecure=1

# Terminal 2: run the agent in the console; the next rule fire goes to the sink
.\efficient_log_forwarder.exe --debug
```

`--mode gelf` and `--mode ndjson` work the same way. `--mode sentinel` also
serves a fake `/oauth2/v2.0/token` so the full OAuth round-trip runs: use a
destination like
`http://127.0.0.1:8088/dataCollectionRules/dcr-lab/streams/Custom-ELF_CL?api-version=2023-01-01&format=sentinel&tenant=lab&client=lab&secret=lab&insecure=1`
and set `ELF_OAUTH_TOKEN_URL=http://127.0.0.1:8088/lab/oauth2/v2.0/token` in
the environment of the `--debug` console (the agent normally builds the token
URL from the tenant; this override exists only for the sink).
`--fail-first 3` answers 503 to the first three POSTs so you can watch the
spool retry and the entries drain once the sink recovers.

---

## Bring your SIEM's Sigma rules to the host

The detections you already run in the SIEM are, in most shops, Sigma rules or
convertible to them. ELF runs them on the host where the event is logged:

1. **Rules → Import** on the ELF server accepts a `.zip` of Sigma YAML (your
   own repo, or a SigmaHQ release package fetched directly with
   *Import from SigmaHQ*). Pick a severity → action map once (e.g.
   critical/high → `alert` to your SIEM destination, medium → `forward_event`,
   low → skip) and the importer writes the `elf:` block into every rule.
2. The agent derives a pre-filter from the imported rules: an XPath query
   so the Windows Event Log only hands it the EventIDs some rule can
   match, or journal matches on Linux so only the syslog identifiers (and
   the audit transport) some rule names leave journald. Import with the
   product filter set to `linux` for a Linux group; an agent skips rules
   written for the other operating system.
3. Alerts arrive in the SIEM already enriched (rule, ATT&CK tags, evidence),
   and only the events a rule asked for are shipped; the rest never leave the
   host, which keeps ingest volume low on SIEMs that charge per GB.

Rules that use a construct the agent does not support are reported by the
importer's validator (with the reason, in the dry-run preview), not silently
dropped.
