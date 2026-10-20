---
name: Detection rule request
about: Ask for a Sigma rule, or report one that misses / false-positives
labels: detection
---

**Technique**
ATT&CK tactic / technique id (e.g. `attack.execution`, `attack.t1059.001`):

**Event source**
Channel + EventID (e.g. Security 4688, Sysmon 1) and the fields that matter:

**Trigger**
How to produce the event in a lab (Atomic Red Team test number if one exists):

**Rule (if you have a draft)**
```yaml
title:
logsource:
  product: windows
  category:
detection:
  selection:
  condition: selection
```

**False positives**
Benign activity that looks the same, and how the rule should exclude it:
