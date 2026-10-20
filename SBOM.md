# Software Bill of Materials (SBOM)

**Project:** Efficient Log Forwarder
**Generated:** 2026-10-20
**SBOM Version:** 1.1
**SPDX-License-Identifier:** See individual components below.

This document enumerates all third-party and system dependencies for both
components of the Efficient Log Forwarder:

1. **Server**: Python 3.12 FastAPI application (`server/`)
2. **Agent**: C++17 Windows executable (`src/`)

Each entry includes the component name, version, license, source URL, and
purpose. Versions are pinned to the exact releases used in builds.

---

## 1. Server (Python) Dependencies

All Python dependencies are pinned in `server/requirements.txt` and installed
into the Docker image via `pip install --no-cache-dir -r requirements.txt`.

| Component | Version | License | Source | Purpose |
|---|---|---|---|---|
| Python | 3.12 (slim) | PSF-2.0 | https://www.python.org/ | Runtime / base image (`python:3.12-slim`) |
| FastAPI | 0.150.0 | MIT | https://github.com/tiangolo/fastapi | Web framework (REST API + inline UI) |
| Uvicorn | 0.54.0 (standard) | BSD-3-Clause | https://github.com/encode/uvicorn | ASGI server |
| Pydantic | 2.14.1 | MIT | https://github.com/pydantic/pydantic | Request/response validation + Field constraints |
| PyYAML | 6.0.3 | MIT | https://github.com/yaml/pyyaml | Sigma rule YAML parsing |
| python-multipart | 0.0.32 | Apache-2.0 | https://github.com/Kludex/python-multipart | Form/file upload endpoints |
| bcrypt | 5.0.0 | Apache-2.0 | https://github.com/pyca/bcrypt | Password hashing (human users) |
| itsdangerous | 2.2.0 | BSD-3-Clause | https://github.com/pallets/itsdangerous | HMAC-signed session cookies |

### Vendored Front-end Assets

Served from `/static/*`; no CDN is contacted by the web UI.

| Component | Version | License | Source | Purpose |
|---|---|---|---|---|
| Chart.js | 4.4.4 (`server/static/chart.umd.min.js`) | MIT | https://github.com/chartjs/Chart.js | Metrics tab area charts |

### Transitive Python Dependencies

These are pulled in automatically by the direct dependencies above. They
ship inside the Docker image but are not listed in `requirements.txt`.

| Component | Pulled in by | License | Purpose |
|---|---|---|---|
| Starlette | FastAPI, Uvicorn | BSD-3-Clause | ASGI toolkit (low-level HTTP) |
| AnyIO | Starlette, Uvicorn | MIT | Async compatibility layer |
| Sniffio | AnyIO | MIT | Async library detection |
| H11 | Uvicorn (h11 protocol) | MIT | HTTP/1.1 protocol library |
| Click | Uvicorn | BSD-3-Clause | CLI argument parsing |
| typing-extensions | Pydantic, Starlette | PSF-2.0 | Backported typing primitives |
| annotated-types | Pydantic | MIT | Annotated type support |
| pydantic-core | Pydantic | MIT | Rust-backed validation core |
| typing-inspection | Pydantic | MIT | Type introspection |
| idna | Starlette/AnyIO | BSD-3-Clause | Internationalized domain names |
| certifi | (optional, for HTTPS) | MPL-2.0 | CA bundle |

### System Dependencies (Server Docker Image)

| Component | Version | License | Source | Purpose |
|---|---|---|---|---|
| Debian (slim base) | bookworm (12) | GPL-2.0+ / LGPL-2.1+ / others | https://www.debian.org/ | Base OS for `python:3.12-slim` |
| glibc | 2.36 | LGPL-2.1+ | (Debian) | C library |
| OpenSSL | 3.0.x | Apache-2.0 | (Debian) | TLS (if HTTPS termination needed) |

---

## 2. Agent (C++) Dependencies

The agent is built with CMake 3.20+ and C++17, targeting Windows (MSVC).
Third-party libraries are fetched at configure time via `FetchContent` and
built statically into the executable. The static CRT (`/MT`) is used so the
produced `.exe` has no external DLL dependencies.

| Component | Version | License | Source | Purpose |
|---|---|---|---|---|
| yaml-cpp | 0.8.0 | MIT | https://github.com/jbeder/yaml-cpp | Sigma rule YAML parsing |
| nlohmann/json | 3.11.3 | MIT | https://github.com/nlohmann/json | JSON parsing (server responses, payloads) |

### Windows System Libraries (Agent)

Linked via `target_link_libraries` in `CMakeLists.txt`. These ship with
Windows and are not redistributed.

| Library | License | Purpose |
|---|---|---|
| wevtapi.dll | Proprietary (Windows SDK) | Windows Event Log API (EvtSubscribe, EvtCreateBookmark) |
| winhttp.dll | Proprietary (Windows SDK) | HTTP client (agent → server communication) |
| ws2_32.dll | Proprietary (Windows SDK) | Winsock (networking) |
| advapi32.dll | Proprietary (Windows SDK) | SCM (service control), LSA policy |
| kernel32.dll | Proprietary (Windows SDK) | Core Win32 API |
| user32.dll | Proprietary (Windows SDK) | Window/message box (debug mode) |

### Build Toolchain (Agent)

| Component | Version | License | Purpose |
|---|---|---|---|
| CMake | 3.20+ | BSD-3-Clause | Build system |
| MSVC | 19.x (VS 2022) | Proprietary (Microsoft) | C++ compiler |
| Windows SDK | 10.x | Proprietary (Microsoft) | Headers + import libraries |
| Visual C++ Runtime | (statically linked via /MT) | Proprietary (Microsoft) | C runtime |

---

## 3. Development & Test Dependencies

These are used during development/testing but are NOT shipped in the
production Docker image or the agent binary.

| Component | Version | License | Purpose |
|---|---|---|---|
| httpx | (latest, dev only) | BSD-3-Clause | TestClient backend for the `tests/server/smoke_*.py` scripts |
| esprima (Python port) | 4.0.1 (dev only) | BSD-2-Clause | Parses the inline web UI script (`tests/server/check_ui_js.py`) |
| Playwright for Python + Chromium | (latest, dev only) | Apache-2.0 | Browser end-to-end test (`tests/server/e2e_ui.py`) |
| pip-audit | (latest, CI only) | Apache-2.0 | Vulnerability scan of `requirements.txt` |

The C++ test harness (`tests/test_rule_engine.cpp`) has no framework
dependency, only a single `CHECK` macro.

---

## 4. Security Notes

- **No dependencies with known CVEs** at the time of this SBOM generation
  (2026-10-20) for the pinned versions listed above; CI runs
  `pip-audit --strict` on every push.
- **bcrypt** is used directly (NOT passlib) to avoid the passlib/argon2
  transitive dependency surface.
- **itsdangerous** is used for HMAC-signed session cookies; no JWT library
  is included, which reduces the attack surface.
- **PyYAML** uses `yaml.safe_load()` exclusively (no `yaml.load()`), which
  prevents arbitrary object instantiation.
- **yaml-cpp** and **nlohmann/json** are built statically and linked with
  the same CRT (`/MT`) as the agent, avoiding DLL conflicts and ABI mismatches.
- **Static CRT** (`/MT`) means the agent `.exe` has no external runtime
  dependencies; it can run on any Windows 10+ host without installing the
  Visual C++ Redistributable.

---

## 5. SBOM Maintenance

This SBOM must be regenerated whenever:
- `server/requirements.txt` is modified (Python deps)
- `CMakeLists.txt` `FetchContent` blocks are modified (C++ deps)
- A dependency version is bumped

To regenerate the Python SBOM programmatically:

```bash
cd server
pip install pip-licenses
pip-licenses --format=markdown --with-urls --with-description > sbom-python.md
```

To check for known vulnerabilities in Python dependencies:

```bash
cd server
pip install pip-audit
pip-audit -r requirements.txt
```

To check for known vulnerabilities in C++ dependencies, consult:
- yaml-cpp: https://github.com/jbeder/yaml-cpp/security/advisories
- nlohmann/json: https://github.com/nlohmann/json/security/advisories
