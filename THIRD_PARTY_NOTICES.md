# Third-party notices

ELF is MIT-licensed (see [LICENSE](LICENSE)). It builds on the following
open-source components. Versions are the ones pinned in `CMakeLists.txt`,
`server/requirements.txt` and `server/static/`; the full inventory with
transitive dependencies is in [SBOM.md](SBOM.md).

## Compiled into the agent (`efficient_log_forwarder.exe`)

| Component | Version | License | Source |
|---|---|---|---|
| yaml-cpp | 0.8.0 | MIT | https://github.com/jbeder/yaml-cpp |
| nlohmann/json | 3.11.3 | MIT | https://github.com/nlohmann/json |

Both are fetched at configure time by CMake `FetchContent` and linked
statically. Their license texts are reproduced below.

## Shipped in the server image

| Component | Version | License | Source |
|---|---|---|---|
| FastAPI | 0.150.0 | MIT | https://github.com/fastapi/fastapi |
| Uvicorn | 0.54.0 | BSD-3-Clause | https://github.com/encode/uvicorn |
| Pydantic | 2.14.1 | MIT | https://github.com/pydantic/pydantic |
| PyYAML | 6.0.3 | MIT | https://github.com/yaml/pyyaml |
| python-multipart | 0.0.32 | Apache-2.0 | https://github.com/Kludex/python-multipart |
| bcrypt | 5.0.0 | Apache-2.0 | https://github.com/pyca/bcrypt |
| itsdangerous | 2.2.0 | BSD-3-Clause | https://github.com/pallets/itsdangerous |
| Chart.js (vendored, `server/static/chart.umd.min.js`) | 4.4.4 | MIT | https://github.com/chartjs/Chart.js |
| gosu (Debian package, container entrypoint) | Debian bookworm | GPL-3.0 (separate executable, not linked) | https://github.com/tianon/gosu |
| Python | 3.12 (`python:3.12-slim`) | PSF-2.0 | https://www.python.org/ |

## Detection content

- The seeded kill-chain rules are original to this project and are written in
  the [Sigma](https://github.com/SigmaHQ/sigma) format. Rules you import from
  SigmaHQ are distributed under the
  [Detection Rule License (DRL) 1.1](https://github.com/SigmaHQ/Detection-Rule-License)
  and keep that license.
- Trigger commands reference [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team)
  tests (MIT).
- The ECS field names follow the [Elastic Common Schema](https://github.com/elastic/ecs)
  (Apache-2.0 specification).

---

### MIT License (yaml-cpp, nlohmann/json, FastAPI, Pydantic, PyYAML, Chart.js)

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

- yaml-cpp: Copyright (c) 2008-2015 Jesse Beder
- nlohmann/json: Copyright (c) 2013-2022 Niels Lohmann
- FastAPI: Copyright (c) 2018 Sebastián Ramírez
- Pydantic: Copyright (c) 2017 to present Pydantic Services Inc. and individual contributors
- PyYAML: Copyright (c) 2017-2021 Ingy döt Net, Copyright (c) 2006-2016 Kirill Simonov
- Chart.js: Copyright (c) 2014-2024 Chart.js Contributors

### BSD-3-Clause (Uvicorn, itsdangerous)

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this
   list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.
3. Neither the name of the copyright holder nor the names of its contributors
   may be used to endorse or promote products derived from this software
   without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

- Uvicorn: Copyright © 2017-present, Encode OSS Ltd.
- itsdangerous: Copyright 2011 Pallets

### Apache License 2.0 (python-multipart, bcrypt)

Licensed under the Apache License, Version 2.0 (the "License"); you may not
use these files except in compliance with the License. You may obtain a copy
of the License at http://www.apache.org/licenses/LICENSE-2.0. Unless required
by applicable law or agreed to in writing, software distributed under the
License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS
OF ANY KIND, either express or implied.
