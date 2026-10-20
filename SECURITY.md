# Security Policy

## Reporting a vulnerability

Please **do not open a public issue** for security problems. Use GitHub's
private vulnerability reporting on this repository (*Security* → *Report a
vulnerability*). You will get an acknowledgement within a few days and a fix
or mitigation plan before any public disclosure. Credit is given in the
release notes unless you ask otherwise.

In scope: the agent (`src/`), the management server (`server/`), the generated
install script, and the CI/release pipeline. Out of scope: vulnerabilities in
third-party dependencies that are already public (please still tell us so the
pin can be bumped).

## Supported versions

Only the latest tagged release receives fixes.

## Security model in one page

ELF is a lab/SOC tool, not a hardened appliance. Read this before exposing it
to anything you don't own.

| Area | What ELF does | What you must do |
|---|---|---|
| **Agent privileges** | Runs as a dedicated local user (`ELFAgent`) with *Log on as a service*, *Manage auditing and security log* and **Event Log Readers** only; not Administrator, not LocalSystem. Writes only under `%ProgramData%\ELFAgent`. | Keep it that way; the install script sets it up. See [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md). |
| **Admin account** | The server seeds `admin` / `admin` on first start. It warns at startup while the password is weak. | Set `ELF_ADMIN_PASSWORD` in `docker-compose.yml` before the first start, or change it from the Users tab immediately. |
| **Agent ↔ server transport** | Plain HTTP by default. Every agent-facing endpoint requires a per-agent bearer token (`ELF_REQUIRE_AGENT_TOKEN=1`); human sessions use HMAC-signed cookies and bcrypt-hashed passwords. | Put TLS termination (nginx, Caddy, a cloud load balancer) in front of port 8000 and use an `https://` server URL in the install script. The agent's WinHTTP client validates certificates by default. |
| **Install-time endpoints** | `GET /agent/binary` (the exe) and `POST /agents/register` (issues a token for a new host) are unauthenticated by design so a fresh host can enroll with nothing but the install script. | Treat the server URL as internal; use the group assignment and the Agents tab to spot unexpected enrollments; rotate a host's token with *Re-enroll*. |
| **SIEM destinations** | Tokens live in the group config (server DB) and `config.ini`, the same trust boundary as the enrollment token. The agent strips them from every logged URL. | Prefer `token=env:VAR` / `secret=env:VAR` (service environment). `insecure=1` disables certificate validation and allows a secret over `http://` (lab use only); the server rejects a secret over plain HTTP without it. |
| **Rule content** | Rules are evaluated on the host. A rule can only *read* events and *send* them to configured destinations; it cannot execute anything. The server validates YAML before storing it and the agent skips rules it cannot parse. | Restrict the `rule_contributor` role to people you trust with your detection logic; review bulk imports with the preview step. |
| **Container** | Runs as a non-root user via `gosu`, minimal capabilities, no privileged flags. SQLite data on a named volume. | Keep the volume on encrypted storage if alerts are sensitive; back it up. |
| **Binary provenance** | Release exes are built by GitHub Actions from the tagged commit and published with `SHA256SUMS.txt`. They are **not Authenticode-signed**. | Verify the hash before deploying (`Get-FileHash`), or build from source. Expect SmartScreen prompts on first run. |
| **Dependencies** | Pinned in `server/requirements.txt` and `CMakeLists.txt`; `pip-audit --strict` runs in CI; see [SBOM.md](SBOM.md). | Watch the security advisories for the pinned libraries if you run an old release. |

## Known limitations

- ELF itself does no TLS (see above).
- SQLite on a single volume; no multi-server HA.
- The web UI is an inline single page without a CSP header; keep it on an
  internal network.
- Agent self-update is not implemented; re-run the install script after a
  server upgrade.
