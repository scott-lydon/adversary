# syntax=docker/dockerfile:1.7
#
# Production image for the Adversary dashboard + scan runner.
#
# Build context expects to be the repo root, so the build is:
#   docker build -f deploy/Dockerfile -t adversary:latest .
#
# Why python:3.12-slim: matches the Hetzner host's system Python (3.12.3) so
# behavior parity between `adversary serve` running in-container vs. ad-hoc
# debug runs on the host is maximized.
FROM python:3.12-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    ADVERSARY_DATA_DIR=/data \
    HOME=/root

# System deps:
#   build-essential + libffi-dev are needed by `cryptography` (Fernet) and
#   `asyncpg` wheels when no manylinux wheel matches.
#   curl is for the HEALTHCHECK below.
#   ca-certificates is required for outbound HTTPS to the LLM providers.
RUN apt-get update \
    && apt-get install --yes --no-install-recommends \
        build-essential \
        libffi-dev \
        curl \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy only the metadata first so layer cache survives source-only edits.
COPY pyproject.toml README.md /app/
COPY src /app/src

RUN pip install --upgrade pip \
 && pip install --editable .

# /data holds adversary.db (bind-mounted from host /opt/adversary/data).
# /root/.config/adversary holds the Fernet secret key (bind-mounted from
# host /opt/adversary/secret) so credentials survive container rebuilds.
RUN install -d -m 0755 /data \
 && install -d -m 0700 /root/.config/adversary

WORKDIR /data

EXPOSE 8765

# Fail fast if the dashboard process is wedged. /healthz is served by
# adversary.dashboard.app and only returns 200 once the SqliteStore opens.
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD curl --fail --silent --show-error http://127.0.0.1:8765/healthz || exit 1

# Bind to 0.0.0.0 so the container's published port is reachable from the
# host's Caddy reverse proxy. The host's port mapping (127.0.0.1:8765:8765)
# in docker-compose.yml is what actually constrains exposure.
CMD ["adversary", "serve", "--host", "0.0.0.0", "--port", "8765"]
