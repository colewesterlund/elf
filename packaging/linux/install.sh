#!/bin/bash
# Install the ELF agent on a Linux host from a locally built binary.
#
# The console's "Add New Agent" button generates a script that does the
# same steps with the binary downloaded from the console; use this one when
# building from source or installing without a console.
#
#   sudo ./install.sh --binary ./build/efficient_log_forwarder \
#        --server http://console:8000 --group default [--user elf]
#
# Steps: create the service account, create /var/lib/elf, install the
# binary to /opt/elf, write /etc/elf/config.ini, register with the console
# (when --server is given), install and start the systemd unit.
set -euo pipefail

BINARY=""
SERVER=""
GROUP="default"
USER_NAME="elf"
AGENT_ID="$(hostname -s)"
while [ $# -gt 0 ]; do
  case "$1" in
    --binary) BINARY="$2"; shift 2 ;;
    --server) SERVER="$2"; shift 2 ;;
    --group) GROUP="$2"; shift 2 ;;
    --user) USER_NAME="$2"; shift 2 ;;
    --agent-id) AGENT_ID="$2"; shift 2 ;;
    -h|--help) sed -n '2,13p' "$0"; exit 0 ;;
    *) echo "Unknown argument: $1" >&2; exit 1 ;;
  esac
done
if [ "$(id -u)" -ne 0 ]; then echo "Run as root (sudo)." >&2; exit 1; fi
if [ -z "$BINARY" ] || [ ! -f "$BINARY" ]; then echo "--binary must point at the built agent." >&2; exit 1; fi

# --- 1. Service account ------------------------------------------------------
if ! id -u "$USER_NAME" >/dev/null 2>&1; then
  useradd --system --no-create-home --shell /usr/sbin/nologin --user-group "$USER_NAME"
  echo "Created system user $USER_NAME."
fi
usermod -aG systemd-journal "$USER_NAME"

# --- 2. Directories ------------------------------------------------------------
install -d -m 0755 /opt/elf /etc/elf
install -d -m 0750 -o "$USER_NAME" -g "$USER_NAME" /var/lib/elf
for sub in logs spool state rules lists output; do
  install -d -m 0750 -o "$USER_NAME" -g "$USER_NAME" "/var/lib/elf/$sub"
done

# --- 3. Binary -------------------------------------------------------------------
systemctl stop elf-agent 2>/dev/null || true
install -m 0755 "$BINARY" /opt/elf/elf-agent

# --- 4. Register with the console ----------------------------------------------
AUTH_TOKEN=""
GROUP_ID=""
if [ -n "$SERVER" ]; then
  GROUP_ID="$(curl -fsS "$SERVER/groups/public" 2>/dev/null | tr -d ' \n' \
    | grep -o "\"name\":\"$GROUP\",\"id\":[0-9]*\|\"id\":[0-9]*,\"name\":\"$GROUP\"" | grep -o '[0-9]*' | head -1 || true)"
  BODY="{\"agent_id\":\"$AGENT_ID\",\"hostname\":\"$(hostname)\""
  [ -n "$GROUP_ID" ] && BODY="$BODY,\"group_id\":$GROUP_ID"
  BODY="$BODY}"
  RESP="$(curl -fsS -X POST "$SERVER/agents/register" -H 'Content-Type: application/json' -d "$BODY" || true)"
  AUTH_TOKEN="$(printf '%s' "$RESP" | grep -o '"auth_token":"[^"]*"' | cut -d'"' -f4 || true)"
  if [ -z "$AUTH_TOKEN" ]; then
    echo "Warning: registration with $SERVER did not return a token; the agent registers itself on first contact." >&2
  fi
fi

# --- 5. config.ini ----------------------------------------------------------------
if [ ! -f /etc/elf/config.ini ]; then
  cat > /etc/elf/config.ini <<EOF
[buffer]
retention_seconds=30

[rules]
directory=/var/lib/elf/rules

[lists]
directory=/var/lib/elf/lists

[server]
url=${SERVER:-http://localhost:8000}
poll_interval_seconds=30
agent_id=$AGENT_ID
auth_token=$AUTH_TOKEN

[logging]
level=notice
max_file_size_mb=1
max_files=3
directory=/var/lib/elf/logs

[spool]
max_spool_mb=100
directory=/var/lib/elf/spool

[destinations]
siem = file:///var/lib/elf/output/siem.jsonl
data_lake = file:///var/lib/elf/output/data_lake.jsonl
alerts = file:///var/lib/elf/output/alerts.jsonl
EOF
  chown root:"$USER_NAME" /etc/elf/config.ini
  chmod 0640 /etc/elf/config.ini
  echo "Wrote /etc/elf/config.ini."
else
  echo "Keeping the existing /etc/elf/config.ini."
fi

# --- 6. systemd unit ---------------------------------------------------------------
UNIT_SRC="$(dirname "$0")/elf-agent.service"
if [ -f "$UNIT_SRC" ]; then
  sed -e "s/^User=.*/User=$USER_NAME/" -e "s/^Group=.*/Group=$USER_NAME/" "$UNIT_SRC" > /etc/systemd/system/elf-agent.service
else
  echo "elf-agent.service not found next to this script." >&2; exit 1
fi
systemctl daemon-reload
systemctl enable --now elf-agent
echo "ELF agent installed and started as $AGENT_ID (user $USER_NAME, group $GROUP)."
echo "  Logs: /var/lib/elf/logs/elf_agent.log   Status: systemctl status elf-agent"
