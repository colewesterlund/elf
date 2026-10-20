"""Static check for the inline web UI in server/main.py.

The UI is a single HTML page embedded in main.py, so a JavaScript syntax
error only surfaces when someone opens the console. This script parses the
<script> block with esprima and runs a few cheap consistency checks:

  - the script parses (ES2017+ as served to browsers)
  - no function is declared twice (the later one silently wins)
  - every function named in an inline on* handler is declared
  - every static el('id') lookup has a matching id="..." in the HTML

Run from the repo root:
  .venv\\Scripts\\python.exe -I tests/server/check_ui_js.py      (pip install esprima)
Exit code 1 on any finding.
"""
import os
import re
import sys

try:
    import esprima
except ImportError:  # pragma: no cover
    print("esprima is not installed: pip install esprima")
    sys.exit(2)

MAIN = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "server", "main.py")
src = open(MAIN, encoding="utf-8").read()
start = src.index('_UI_HTML = r"""')
end = src.index('"""', start + 20)
html = src[start:end]
scripts = re.findall(r"<script>(.*?)</script>", html, re.S)
assert len(scripts) == 1, "expected exactly one inline <script> block"
js = scripts[0]

failed = False

try:
    tree = esprima.parseScript(js, {"tolerant": False, "loc": True})
    print("JS parses OK (%d top-level statements)" % len(tree.body))
except esprima.Error as e:
    print("JS SYNTAX ERROR:", e)
    sys.exit(1)

FUNC_RE = r"^\s*(?:async\s+)?function\s+([A-Za-z_$][\w$]*)\s*\("
declared = set(re.findall(FUNC_RE, js, re.M))
declared |= set(re.findall(r"^\s*(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=", js, re.M))
names = re.findall(FUNC_RE, js, re.M)
dups = sorted({n for n in names if names.count(n) > 1})
if dups:
    failed = True
    print("duplicate function declarations:", dups)

# Handlers referenced from inline on* attributes in the HTML and in JS
# template strings. Comments are stripped first so an example in a comment
# is not mistaken for a reference.
js_no_comments = re.sub(r"//[^\n]*", "", js)
handler_re = r"on(?:click|change|input|submit|keydown|load)=\\?[\"']\s*(?:return\s+)?([A-Za-z_$][\w$]*)\s*\("
called = set(re.findall(handler_re, html.replace(js, ""))) | set(re.findall(handler_re, js_no_comments))
missing = sorted(c for c in called if c not in declared)
if missing:
    failed = True
    print("handlers referenced but never declared:", missing)

ids_in_html = set(re.findall(r"\bid=\"([^\"${}]+)\"", html))
static_refs = set(re.findall(r"\bel\('([^'${}]+)'\)", js))
dynamic_prefixes = ("collect-", "g-", "arow-", "alert-", "rule-count", "dt-")
unknown = sorted(r for r in static_refs if r not in ids_in_html and not r.startswith(dynamic_prefixes))
if unknown:
    failed = True
    print("el('id') with no static element:", unknown)

if failed:
    sys.exit(1)
print("UI static checks passed")
