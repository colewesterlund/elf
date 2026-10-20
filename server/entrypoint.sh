#!/bin/sh
# Seed baked-in agent binary + companion files into the data volume on first
# start. A named volume mount hides image content under /data, so files baked
# into /app/agent-defaults are copied into /data/agent only if they are not
# already present there. This lets a fresh install ship with a working agent
# while still letting the operator replace/override files via the web UI.
#
# Database reset: by default the SQLite DB is deleted on every container start
# so a new install comes up with no leftover agents/rules/alerts from previous
# runs. Set ELF_RESET_DB=0 to preserve the DB across restarts (useful for dev
# or when you only want to restart the server without losing registrations).
# Only the DB is wiped; uploaded/seeded agent binaries and companion files in
# /data/agent are always preserved.
set -e

DB_PATH="${ELF_DB_PATH:-/data/elf.db}"
DEST="${ELF_AGENT_BINARY_DIR:-/data/agent}"
SRC="/app/agent-defaults"

# Reset the database unless the operator explicitly opts out. A fresh install
# should have no artifacts from old runs.
RESET_DB="${ELF_RESET_DB:-1}"
if [ "$RESET_DB" = "1" ] && [ -f "$DB_PATH" ]; then
  rm -f "$DB_PATH"
  # Remove SQLite sidecar files (-wal, -shm, -journal) too.
  rm -f "$DB_PATH-wal" "$DB_PATH-shm" "$DB_PATH-journal"
  echo "[entrypoint] reset database (ELF_RESET_DB=1): removed $DB_PATH"
fi
# The newline-separated forwarded-logs text file lives next to the DB on the
# same persistent volume and is NOT covered by the DB reset above. Wipe it on
# reset too so a fresh install doesn't show stale events from a previous run.
if [ "$RESET_DB" = "1" ]; then
  LOGS_TXT="$(dirname "$DB_PATH")/logs.txt"
  if [ -f "$LOGS_TXT" ]; then
    rm -f "$LOGS_TXT"
    echo "[entrypoint] reset database (ELF_RESET_DB=1): removed $LOGS_TXT"
  fi
fi

if [ -d "$SRC" ]; then
  mkdir -p "$DEST"
  for f in "$SRC"/*; do
    [ -f "$f" ] || continue
    name=$(basename "$f")
    target="$DEST/$name"
    # Always overwrite the baked-in agent binaries so a redeploy with a new
    # image replaces any stale copy a previous install left on the volume.
    # Other companion files are only seeded when absent, so operator uploads
    # via the web UI are preserved across restarts.
    if [ "$name" = "efficient_log_forwarder.exe" ] || [ "$name" = "elf-agent" ]; then
      cp "$f" "$target"
      echo "[entrypoint] seeded/updated $name"
    elif [ ! -e "$target" ]; then
      cp "$f" "$target"
      echo "[entrypoint] seeded $name"
    fi
  done
fi

# Fix ownership of the data volume. A pre-existing named volume may be
# root-owned (e.g. created by a container that ran as root), so the non-root
# elf user can't write to it. chown it to elf:elf before dropping privileges.
# This is a no-op if the volume is already elf-owned (e.g. a fresh volume
# from this image).
echo "[entrypoint] fixing /data ownership (elf:elf)"
chown -R elf:elf /data

# Drop privileges to the non-root elf user and run uvicorn. gosu preserves
# the signal handling (Ctrl+C / docker stop) that a plain `su` would break.
exec gosu elf uvicorn main:app --host 0.0.0.0 --port 8000
