# Reusable lists directory.
#
# Each file in this directory defines a reusable list. The file name (without
# extension) is the list name. Files may be `*.txt` or `*.list`.
#
# Format:
#   - One value per line.
#   - Lines starting with `#` are comments and are ignored.
#   - Blank lines are ignored.
#   - Leading/trailing whitespace on each value is trimmed.
#
# Rules reference a list using the `@@` prefix, e.g.:
#   Image|contains: @@sensitive_processes
#   Image|contains: [@@sensitive_processes, calc.exe]
#
# The list is expanded at rule-load time into the field's value set, so a
# missing or empty list makes the field match nothing (safe default).
#
# When the agent is connected to a server, the server is the source of truth
# for lists and will overwrite the contents of this directory on each poll.
