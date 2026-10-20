# ELF Management Server

Python + FastAPI + SQLite, packaged in Docker. This is the management plane
that the Windows agents talk to.

## Run

Needs Docker Desktop (Windows/macOS) or Docker Engine + Compose (Linux).

Each release publishes a console image to the GitHub Container Registry with
the matching agents inside it (`efficient_log_forwarder.exe` for Windows,
`elf-agent` for Linux):

```bash
docker pull ghcr.io/colewesterlund/elf-server:v1.0.0     # or :latest
```

To use it with the compose file, replace `build: .` with
`image: ghcr.io/colewesterlund/elf-server:v1.0.0` and start without
`--build`. To build locally instead, copy `efficient_log_forwarder.exe` and
`elf-agent` into `server/agent/` first (otherwise the image has no agent to
hand out; `GET /agent/binary?os=windows|linux` serves them) and run:

```bash
cd server
ELF_ADMIN_PASSWORD='choose-a-strong-one' docker compose up -d --build
```

The server listens on port **8000**; open `http://localhost:8000/` and log in
as `admin`. The SQLite database is persisted in a named volume (`elf-data`)
so rules, agents, and groups survive restarts. Set `ELF_PUBLIC_HOST` in
`docker-compose.yml` to the address agents should use when the host has more
than one (generated install scripts embed it). A fresh instance has the
`default` group with the Windows sample rules and `linux-servers` with the
Linux ones; `ELF_SEED_TEST_DATA=1` adds the demo groups and the kill-chain
rules for a lab.

## Endpoints

Auth: *session* = logged-in browser cookie (`viewer` can read, `rule_contributor`
can edit rules/lists, `admin` everything); *agent* = the per-agent bearer token
issued at registration; *open* = no auth (install-time endpoints).

| Method | Path | Auth | Purpose |
|---|---|---|---|
| GET | `/` | open | Web UI (single inline page) |
| GET | `/health` | open | Health check |
| POST | `/auth/login`, `/auth/logout` · GET `/auth/me` | open | Session login/logout/whoami |
| GET/POST | `/users` · DELETE `/users/{id}` · PUT `/users/{id}/role` | admin | User management |
| GET/DELETE | `/audit` | admin | Privileged-action audit trail |
| POST | `/agents/register` | open | Enroll a host (returns its `auth_token` once); `group_id` optional |
| POST | `/agents/{agent_id}/reissue-token` | admin | Mint a fresh token (rotates a compromised one) |
| GET | `/agents` · `/agents/{agent_id}` | session | List / detail |
| PUT | `/agents/{agent_id}/group` | admin | Move an agent between groups |
| DELETE | `/agents/{agent_id}?cascade=` | admin | Remove an agent (optionally its alerts + logs) |
| POST | `/agents/{agent_id}/collect` | admin | Queue an on-demand historical collection |
| POST | `/collect/{command_id}` · `/collect/{command_id}/done` | agent | Agent streams collected batches / marks completion |
| GET | `/config/{agent_id}` | agent | **The agent's poll**: effective config + ruleset; accepts `known_hash` and the cumulative metrics counters as query params |
| POST | `/alerts?agent_id=` · `/logs?agent_id=` | agent | Alert / forwarded-batch ingest (≤10,000 events per batch) |
| GET/POST/PUT/DELETE | `/groups`, `/groups/{group_id}` | session / admin to write | Groups: retention, poll interval, destinations (validated: see `docs/SIEM.md`), mirror toggle |
| GET/POST | `/rules?group_id=` · GET/PUT/DELETE `/rules/{rule_id}?group_id=` | session / contributor to write | Rule CRUD (summary list; full YAML per rule) |
| POST | `/rules/validate` | session | Validate a YAML body (the editor calls this as you type) |
| POST | `/rules/bulk-delete?group_id=` | contributor | Delete many rules |
| POST | `/rules/import` · `/rules/import/sigmahq` · `/rules/import/commit` · GET `/rules/import/sigmahq/assets` | contributor | Bulk import: zip upload or SigmaHQ release packages, preview then commit |
| GET/POST | `/lists` · GET/PUT/DELETE `/lists/{name}` | session / contributor to write | Reusable `@@lists` |
| GET | `/alerts?limit=&offset=&sort=&q=` · `/alerts/{id}` · DELETE `/alerts` | session / admin to clear | Alerts (list without payloads; detail with evidence) |
| GET | `/logs` · `/logs/text` · `/logs/size` · DELETE `/logs` | session / admin to clear | Forwarded batches, the newline-separated text file, its size |
| GET/PUT | `/settings` | session / admin to write | `max_logs_text_mb` |
| GET | `/metrics/savings` · `/metrics/stats` · `/metrics/alerts` · DELETE `/metrics/reset` | session / admin to reset | Savings report, time-bucketed events/bytes/alerts (`/logs/savings`, `/logs/stats` are legacy aliases) |
| POST | `/install-script` (GET `?group=` legacy) | admin | Generate the install `.ps1` (`group`, `account_mode`=`local`\|`domain`, `domain`, `username`) |
| GET | `/cleanup-script` | admin | Cleanup `.ps1` (service, account, rights, directories) |
| GET | `/agent/binary` · `/agent/binary/status` · `/agent/lsa-helper` | open | The prebuilt exe (and the LSA rights helper) the install script downloads |
| GET/POST | `/agent/files` · GET/DELETE `/agent/files/{name}` | admin to write | Companion files served alongside the binary |

The interactive OpenAPI page is at `/docs`.

## Model

- An **agent** belongs to exactly one **group**.
- A **group** has its own settings (retention, poll interval, destinations)
  and its own set of **rules**.
- The agent's `agent_id` is its identity. On first contact (`GET /config/{id}`)
  the agent is auto-registered into the `default` group.
- The server holds the authoritative copy: agents pull their effective config +
  ruleset on every poll and apply them locally.
- Destinations are resolved per-group (e.g.
  `splunk = https://splunk.example.com:8088/services/collector/event?format=hec&token=…`).
  The agent receives them and uses them for `forward_event`/`alert`/`forward_buffer`
  actions. See `docs/SIEM.md` for the per-SIEM recipes.

## Quick test

Human endpoints need a login session (cookie); agent endpoints need the
agent's bearer token. `/health` is open.

```bash
# Health
curl http://localhost:8000/health

# Log in (cookie jar), then list groups and create one
curl -c jar -X POST http://localhost:8000/auth/login \
  -H 'Content-Type: application/json' -d '{"username":"admin","password":"admin"}'
curl -b jar http://localhost:8000/groups
curl -b jar -X POST http://localhost:8000/groups \
  -H 'Content-Type: application/json' \
  -d '{"name":"domain-controllers","description":"DC fleet"}'

# Enroll an agent (returns its auth_token once), then fetch what it would receive
curl -X POST http://localhost:8000/agents/register \
  -H 'Content-Type: application/json' -d '{"agent_id":"demo-host","hostname":"demo-host"}'
curl -H 'Authorization: Bearer <auth_token>' http://localhost:8000/config/demo-host
```
