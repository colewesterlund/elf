FROM python:3.12-slim

WORKDIR /app

# Install dependencies first for better layer caching. --no-cache-dir keeps
# the image small; --no-compile skips .pyc generation (we run from source).
COPY requirements.txt .
RUN pip install --no-cache-dir --no-compile -r requirements.txt \
    && rm -rf /root/.cache

# gosu lets the entrypoint run as root (to fix volume ownership on a
# pre-existing named volume that may be root-owned) and then drop
# privileges to the non-root elf user for uvicorn. This is the standard
# Docker pattern for non-root containers with persistent volumes.
RUN apt-get update \
    && apt-get install --no-install-recommends -y gosu \
    && rm -rf /var/lib/apt/lists/*

COPY . .

# Stage the baked-in agent binary (from server/agent/) under a distinct path.
# The entrypoint copies it into the data volume on container start, overwriting
# any stale exe left on the volume by a previous install.
RUN if [ -d /app/agent ]; then mv /app/agent /app/agent-defaults; fi

# Make the entrypoint executable. It seeds baked-in agent files into the data
# volume on first start, then launches uvicorn.
RUN chmod +x entrypoint.sh

# --- Docker hardening ---
# Create a dedicated non-root user and group. The server runs as this user so
# a container escape has no root privileges inside the container.
RUN groupadd --system --gid 1001 elf \
    && useradd --system --uid 1001 --gid elf --no-create-home --shell /usr/sbin/nologin elf

# The SQLite DB lives on a mounted volume so rules/agents persist across
# container restarts. ELF_DB_PATH is read by db.py. The entrypoint wipes the
# DB on each start unless ELF_RESET_DB=0 (see entrypoint.sh).
ENV ELF_DB_PATH=/data/elf.db
ENV ELF_RESET_DB=1

# The prebuilt agent executable is served from /data/agent so new hosts can
# download it without internet access. ELF_AGENT_BINARY_DIR is read by main.py.
ENV ELF_AGENT_BINARY_DIR=/data/agent

# Prevent Python from writing .pyc files; the root filesystem is read-only
# (see docker-compose.yml). /tmp is a tmpfs for any temp space Python needs.
ENV PYTHONDONTWRITEBYTECODE=1
ENV HOME=/tmp

# Create the data directories; the volume mount in compose overrides this.
# Docker copies image content (including ownership) into a new named volume
# on first mount, so chown here ensures the elf user owns the volume.
RUN mkdir -p /data /data/agent \
    && chown -R elf:elf /app /data

EXPOSE 8000

# Health check: hit the public /health endpoint. Fails fast if uvicorn is
# hung or the app crashed. 3 consecutive failures → unhealthy.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request,sys; sys.exit(0) if urllib.request.urlopen('http://127.0.0.1:8000/health',timeout=3).status==200 else sys.exit(1)"

# NOTE: the entrypoint runs as ROOT so it can chown a pre-existing named
# volume (which may be root-owned) before dropping to the non-root elf user
# via gosu. The compose file sets read_only: true so the
# root filesystem is still immutable at runtime.

# The entrypoint seeds any baked-in agent files (from server/agent/) into the
# data volume on first start, fixes /data ownership, then drops to the elf
# user and runs uvicorn. This lets a fresh image ship with a default compiled
# binary so the operator doesn't have to upload one.
ENTRYPOINT ["/app/entrypoint.sh"]

