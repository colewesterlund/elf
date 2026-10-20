# Ten-minute demo

Goal: a management server in Docker, one Windows host running the agent in a
console, the twelve kill-chain rules loaded, and the first alerts landing
in the UI, in a file, and (optionally) in a SIEM stand-in.

## What you need

- A Windows 10/11 or Server 2016+ host where you can run an **elevated**
  PowerShell (the audit-policy step and the agent's Security-log read need it).
- Docker Desktop (Windows/macOS) or Docker Engine + Compose (Linux), on the
  same host or any host the Windows machine can reach on port 8000.
- The agent exe: download `efficient_log_forwarder.exe` from the
  [latest release](https://github.com/colewesterlund/elf/releases) and check
  it against `SHA256SUMS.txt`, or build it (`cmake --build build --config Release`).
- Python 3 only if you want the SIEM stand-in in step 6.

## 1. Start the server

```bash
cd server
ELF_ADMIN_PASSWORD='choose-a-strong-one' docker compose up -d --build
```

Open `http://<server>:8000/`, log in as `admin`. For the demo set
`ELF_SEED_TEST_DATA=1` in `docker-compose.yml` before starting: it adds the
three demo groups, and **workstations** holds the twelve `win_kc_*` rules.
A default deployment leaves that off and seeds only `default` and
`linux-servers` with their sample rules. If the server runs on another
machine, set `ELF_PUBLIC_HOST` in `docker-compose.yml` to its reachable
address first.

## 2. Enable auditing on the Windows host (elevated)

```powershell
cd <folder with efficient_log_forwarder.exe and the demo\ scripts>
.\demo\enable-audit.ps1          # 4688 with command line + 4625
```

Workstations don't audit process creation by default; without this step the
events the rules look for are never written. `-Revert` undoes it.

## 3. Enroll the host

```powershell
.\demo\enroll-agent.ps1 -Server http://<server>:8000 -Group workstations -AgentDir .
```

Logs in as `admin` (prompts for the password), registers this computer in
the group, receives its enrollment token, and writes `config.ini` next to the
exe. For a real deployment use the server's generated install script instead
(Agents → **+ Add New Agent**), which installs the least-privilege service.

## 4. Run the agent in the console (elevated)

```powershell
.\efficient_log_forwarder.exe --debug
```

Within one poll (30 s) the rules arrive from the server and the agent
reloads; the status line reports the count:

```
[Startup] Active rules: 12
```

(Set `level=debug` in `config.ini` `[logging]` to also see the per-channel
subscriptions and the XPath filter the rules produced.)

## 5. See the rules fire

ELF ships nothing that triggers detections. Each of the twelve rules in
**workstations** says in its `description:` which ATT&CK technique it
covers and which public
[Atomic Red Team](https://github.com/redcanaryco/atomic-red-team) test
produces its event; open a rule in the Rules tab to read it. Run the ones
you choose on the host the agent watches, in a lab. The Windows events
behind them are Security 4688 (process creation with the command line),
4625 (failed logon), 4624 type 10 (RDP logon), 5156 (filtered connection),
1102 (audit log cleared) and System 7045 (service installed), so any
activity that writes those events, yours or an adversary's, is what the
rules see.

The agent console prints one line per detection:

```
[ALERT] Rule fired: win_kc_01_ps_encoded (Kill-Chain 01 (Execution) - Encoded PowerShell Command)
[ALERT] Rule fired: win_kc_06_password_spray (Kill-Chain 06 (Credential Access) - Password Spray (Many Users, One Source))
[ALERT] Rule fired: win_kc_11_stage_exfil (Kill-Chain 11 (Exfiltration) - Data Staged then Uploaded (Sequence))
```

Where to look:

- **Alerts tab**: each alert expands to the triggering event; threshold and
  sequence alerts also list their evidence events (the five 4625s, the
  Compress-Archive + curl pair).
- **`%ProgramData%\ELFAgent\output\alerts.jsonl`**: the raw alert payloads
  the `alerts` destination received; `data_lake.jsonl` holds the
  `forward_buffer` batches, `siem.jsonl` the `forward_event` stream.
- **Logs tab**: the mirrored `forward_buffer` batches.
- **Metrics tab** (give it ten minutes): events created on the host vs.
  forwarded, and the savings percentage.

KC-08 watches both sides of an RDP session: the client launch on the host
that starts it, and the type-10 logon, which Windows writes on the host
that accepts the session.

The Linux samples live in the `linux-servers` group. Each rule's
description says what it looks for; the syslog-based ones (sshd, sudo,
useradd) match on the message text, and the process-based ones need the
execve audit rule the install script's audit option sets up.

## 6. Optional: send the alerts to a SIEM stand-in

```powershell
python tools\siem-sink.py --mode hec --token lab        # Splunk HEC on :8088
```

On the Groups tab, add a destination to **workstations**:

```
splunk = http://<windows-host>:8088/services/collector/event?format=hec&token=lab&insecure=1
```

and change one rule's `alert` action to `destination: splunk` (or add a second
action). The next time that rule fires, the sink prints the HEC envelope it
receives. `--mode gelf` and `--mode sentinel` do the same for Graylog and
Microsoft Sentinel; the real recipes are in [SIEM.md](SIEM.md).

## 7. Clean up

```powershell
Ctrl+C in the agent console
.\demo\enable-audit.ps1 -Revert
docker compose down            # add -v to drop the database volume
```

Delete the host on the Agents tab if you want the server clean.
