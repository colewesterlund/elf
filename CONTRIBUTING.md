# Contributing to ELF

Thanks for taking a look. Bug reports, detection rules, SIEM recipes and
code are all welcome. Please open an issue before a large change so the
design can be discussed first.

## Build and test

**Agent (Windows, MSVC 2022 or Build Tools, CMake ≥ 3.20):**

```powershell
cmake -S . -B build "-DCMAKE_POLICY_VERSION_MINIMUM=3.5" -DCMAKE_BUILD_TYPE=Release
cmake --build build --config Release
cd build\Release
.\test_rule_engine.exe                       # ~700 checks, must print "0 failed"
$env:ELF_SCALE_TEST = '1'; .\test_rule_engine.exe; Remove-Item Env:ELF_SCALE_TEST   # optional 3,000-rule timing block
```

**Server (Python 3.12):**

```powershell
python -m venv .venv
.venv\Scripts\pip install -r server\requirements.txt httpx
foreach ($s in Get-ChildItem tests\server\smoke_*.py) { .venv\Scripts\python.exe -I $s.FullName }
```

Each smoke script uses a throwaway SQLite database and prints `... PASSED`.
Two more checks cover the inline web UI: `tests/server/check_ui_js.py`
(`pip install esprima`; parses the script, checks handlers and element ids)
and `tests/server/e2e_ui.py` (`pip install playwright`; starts its own
server, seeds it, and drives every tab in a real browser; add
`--channel msedge` or `--channel chrome` to use an installed browser, or
`playwright install chromium` once). Both run in CI.
`docs/DEVELOPER.md` explains the module layout and the extension points
(new Sigma modifier, new action type, new output format, XPath derivation).

## Pull requests

- One topic per PR. Keep the diff focused; refactors go in their own PR.
- Add or extend a test for every behavior change; the C++ suite is a single
  `tests/test_rule_engine.cpp` with `CHECK(...)` sections; server behavior
  goes in a `tests/server/smoke_*.py` script.
- Match the surrounding style (4-space C++, `clang-format`-free but
  consistent; PEP 8 for Python). Comments explain *why*, not *what*.
- Update `docs/USAGE.md` / `docs/DEVELOPER.md` / the in-app Docs tab
  (`server/main.py`) when user-visible behavior changes, and add a line to
  `CHANGELOG.md` under *Unreleased*.
- CI must be green: agent build + tests on Windows, server smoke scripts,
  Docker image build, `pip-audit`.

## Contributing detection rules

ELF rules are standard [Sigma](https://github.com/SigmaHQ/sigma) YAML with an
`elf:` block that says what to do on a match. A good rule PR includes:

1. The rule under `rules/` (or, for the seeded kill-chain suite, in the
   server seed **and** the parity test in `tests/test_rule_engine.cpp`).
2. The ATT&CK tags (`attack.<tactic>`, `attack.t<id>`), `level`, and a
   `description` that names how to trigger it (an Atomic Red Team test
   number where one exists).
3. A synthetic-event test that proves the rule fires on the intended event
   shape and stays quiet on a near miss.

Supported Sigma subset: `contains`, `startswith`, `endswith`, `re`, `exists`,
`all`, `cidr` modifiers; `and`/`or`/`not`, parentheses, `1 of` / `all of`
conditions; `keywords`. Not supported: correlations, aggregations, `|base64`,
`|windash`, `|gt`/`|lt`.

## Security issues

See [SECURITY.md](SECURITY.md); please report privately.
