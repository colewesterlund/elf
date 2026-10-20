#!/usr/bin/env python3
"""Offline SIEM stand-in for testing ELF destinations.

Speaks just enough of each ingestion API to show what the agent sends, so
you can verify a `?format=` destination end-to-end without a Splunk,
Graylog or Sentinel instance:

  python tools/siem-sink.py --mode hec --token lab
      Splunk HTTP Event Collector: expects `Authorization: Splunk lab`,
      splits concatenated envelopes, answers {"text":"Success","code":0}.
  python tools/siem-sink.py --mode gelf
      Graylog GELF HTTP input: one message per POST, answers 202.
  python tools/siem-sink.py --mode sentinel
      Azure Monitor Logs Ingestion: also serves a fake
      /<tenant>/oauth2/v2.0/token so the agent's OAuth2 client-credentials
      flow runs for real; expects `Authorization: Bearer <that token>` and
      a JSON array body; answers 204.
  python tools/siem-sink.py --mode ndjson
      Plain NDJSON receiver (format=json / format=ecs), optional
      `Authorization: Bearer <token>`.

Every accepted document is pretty-printed. `--fail-first N` answers 503 to
the first N POSTs so you can watch the agent's spool retry with backoff.
`--quiet` prints one summary line per request instead of full documents.

Point the agent at it, e.g. in config.ini [destinations]:
  splunk = http://127.0.0.1:8088/services/collector/event?format=hec&token=lab&insecure=1
  graylog = http://127.0.0.1:8088/gelf?format=gelf
  sentinel = http://127.0.0.1:8088/dataCollectionRules/dcr-x/streams/Custom-ELF_CL?api-version=2023-01-01&format=sentinel&tenant=lab&client=lab&secret=lab&insecure=1

(For sentinel the agent builds the token URL from the tenant; set
ELF_OAUTH_TOKEN_URL=http://127.0.0.1:8088/lab/oauth2/v2.0/token in the
agent's environment to redirect it here; see docs/SIEM.md.)

Standard library only.
"""
import argparse
import json
import sys
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ARGS = None
STATE = {"posts": 0, "docs": 0, "failed": 0, "token": "sink-access-token"}


def _split_hec(body: str):
    """Splunk HEC accepts concatenated JSON objects with no separator."""
    dec = json.JSONDecoder()
    i, n = 0, len(body)
    while i < n:
        while i < n and body[i] in " \r\n\t":
            i += 1
        if i >= n:
            break
        obj, end = dec.raw_decode(body, i)
        yield obj
        i = end


class Handler(BaseHTTPRequestHandler):
    server_version = "elf-siem-sink/1.0"

    def log_message(self, fmt, *args):  # quiet the default access log
        pass

    def _reply(self, status, body=b"", ctype="application/json"):
        self.send_response(status)
        if body:
            self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if body:
            self.wfile.write(body)

    def _print_docs(self, docs, label):
        STATE["docs"] += len(docs)
        stamp = time.strftime("%H:%M:%S")
        if ARGS.quiet:
            kinds = {}
            for d in docs:
                k = _kind_of(d)
                kinds[k] = kinds.get(k, 0) + 1
            summary = ", ".join(f"{v} {k}" for k, v in kinds.items())
            print(f"[{stamp}] {label}: {len(docs)} doc(s) ({summary})")
            return
        print(f"\n===== [{stamp}] {label}: {len(docs)} document(s) =====")
        for d in docs:
            print(json.dumps(d, indent=2, ensure_ascii=False))

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length)
        STATE["posts"] += 1
        auth = self.headers.get("Authorization", "")
        ctype = self.headers.get("Content-Type", "")

        # Fake Entra token endpoint for --mode sentinel.
        if ARGS.mode == "sentinel" and self.path.endswith("/oauth2/v2.0/token"):
            form = dict(p.split("=", 1) for p in raw.decode().split("&") if "=" in p)
            if form.get("grant_type") != "client_credentials" or "scope" not in form:
                print("[token] bad client-credentials request:", form)
                return self._reply(400, b'{"error":"invalid_request"}')
            print(f"[token] issued access token for client_id={form.get('client_id')} "
                  f"scope={form.get('scope', '').replace('%2F', '/').replace('%3A', ':')}")
            body = json.dumps({"access_token": STATE["token"], "token_type": "Bearer",
                               "expires_in": 3600}).encode()
            return self._reply(200, body)

        if STATE["failed"] < ARGS.fail_first:
            STATE["failed"] += 1
            print(f"[sink] answering 503 ({STATE['failed']}/{ARGS.fail_first}) "
                  f"to exercise spool retry")
            return self._reply(503, b'{"text":"Service unavailable"}')

        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            print("[sink] body is not UTF-8")
            return self._reply(400, b'{"text":"bad encoding"}')

        if ARGS.mode == "hec":
            if auth != f"Splunk {ARGS.token}":
                print(f"[sink] 403: expected 'Authorization: Splunk {ARGS.token}', got {auth!r}")
                return self._reply(403, b'{"text":"Invalid token","code":4}')
            try:
                docs = list(_split_hec(text))
            except ValueError as e:
                print("[sink] 400: HEC body is not concatenated JSON:", e)
                return self._reply(400, b'{"text":"Invalid data format","code":6}')
            for d in docs:
                for k in ("time", "host", "sourcetype", "event"):
                    if k not in d:
                        print(f"[sink] warning: envelope missing '{k}'")
            self._print_docs(docs, f"HEC {self.path}")
            return self._reply(200, b'{"text":"Success","code":0}')

        if ARGS.mode == "gelf":
            try:
                d = json.loads(text)
            except ValueError as e:
                print("[sink] 400: GELF body is not one JSON object:", e)
                return self._reply(400, b"")
            if d.get("version") != "1.1" or "short_message" not in d or "host" not in d:
                print("[sink] warning: not a valid GELF 1.1 message")
            nested = [k for k, v in d.items() if isinstance(v, (dict, list))]
            if nested:
                print(f"[sink] warning: GELF forbids nested fields: {nested}")
            self._print_docs([d], f"GELF {self.path}")
            return self._reply(202, b"")

        if ARGS.mode == "sentinel":
            if auth != f"Bearer {STATE['token']}":
                print(f"[sink] 401: expected the issued bearer token, got {auth!r}")
                return self._reply(401, b'{"error":{"code":"InvalidAuthenticationToken"}}')
            if "api-version=" not in self.path:
                print("[sink] warning: api-version missing from the URL")
            if len(raw) > 1024 * 1024:
                print(f"[sink] 413: body is {len(raw)} bytes (> 1 MB limit)")
                return self._reply(413, b'{"error":{"code":"ContentLengthLimitExceeded"}}')
            try:
                rows = json.loads(text)
            except ValueError as e:
                print("[sink] 400: body is not JSON:", e)
                return self._reply(400, b"")
            if not isinstance(rows, list):
                print("[sink] 400: Logs Ingestion expects a JSON array of rows")
                return self._reply(400, b"")
            for r in rows:
                if "TimeGenerated" not in r:
                    print("[sink] warning: row without TimeGenerated")
            self._print_docs(rows, f"Sentinel {self.path}")
            return self._reply(204, b"")

        # ndjson
        if ARGS.token and auth != f"Bearer {ARGS.token}":
            print(f"[sink] 401: expected 'Authorization: Bearer {ARGS.token}', got {auth!r}")
            return self._reply(401, b'{"error":"unauthorized"}')
        docs = []
        for line in text.splitlines():
            if not line.strip():
                continue
            try:
                docs.append(json.loads(line))
            except ValueError:
                docs.append({"_raw": line})
        self._print_docs(docs, f"{ctype or 'body'} {self.path}")
        return self._reply(200, b'{"ok":true}')


def _kind_of(d):
    if isinstance(d, dict):
        if "event" in d and isinstance(d["event"], dict):   # HEC envelope
            d = d["event"]
        if "elf" in d and isinstance(d["elf"], dict) and "kind" in d["elf"]:
            return d["elf"]["kind"]
        if "event" in d and isinstance(d["event"], dict) and "kind" in d["event"]:
            return d["event"]["kind"]
        if "_elf_kind" in d:
            return d["_elf_kind"]
        if "Kind" in d:
            return str(d["Kind"]).lower()
    return "doc"


def main():
    global ARGS
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--mode", choices=("hec", "gelf", "sentinel", "ndjson"), default="hec")
    p.add_argument("--port", type=int, default=8088)
    p.add_argument("--bind", default="127.0.0.1")
    p.add_argument("--token", default="lab",
                   help="HEC token to require (hec) or Bearer token to require (ndjson; "
                        "empty = no auth)")
    p.add_argument("--fail-first", type=int, default=0, metavar="N",
                   help="answer 503 to the first N POSTs to show spool retry/backoff")
    p.add_argument("--quiet", action="store_true", help="one summary line per request")
    ARGS = p.parse_args()
    if ARGS.mode == "ndjson" and ARGS.token == "lab":
        ARGS.token = ""   # no auth by default for the plain receiver
    srv = ThreadingHTTPServer((ARGS.bind, ARGS.port), Handler)
    print(f"elf siem-sink: mode={ARGS.mode} listening on http://{ARGS.bind}:{ARGS.port}/ "
          f"(Ctrl+C to stop)")
    if ARGS.mode == "hec":
        print(f"  expecting: Authorization: Splunk {ARGS.token}")
    elif ARGS.mode == "sentinel":
        print("  serving a fake /oauth2/v2.0/token; POSTs need the bearer it issues")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    print(f"\n{STATE['posts']} request(s), {STATE['docs']} document(s) received")
    return 0


if __name__ == "__main__":
    sys.exit(main())
