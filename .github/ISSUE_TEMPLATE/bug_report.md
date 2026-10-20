---
name: Bug report
about: Something in the agent, server or install script misbehaves
labels: bug
---

**What happened**

**What you expected**

**Steps to reproduce**
1.
2.

**Environment**
- ELF version (`efficient_log_forwarder.exe --version`, server `/health`):
- Agent host: Windows version, running as service or `--debug`:
- Server: Docker Compose / other, Python version if not Docker:
- Rule(s) involved (paste the YAML or the rule id):

**Logs**
Attach the relevant lines from `%ProgramData%\ELFAgent\logs\error.log`
(and `elf_agent.log` at `level=debug` if you can reproduce) and the
server container log. Redact hostnames, IPs and tokens.
