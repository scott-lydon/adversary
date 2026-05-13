#!/bin/bash
#
# auto-deploy.sh
#
# Polls origin/<current-branch> and ff-merges + rebuilds the adversary
# compose stack when something new lands. Mirrors the shape of the
# Clinical Co-Pilot's /opt/openemr/auto-deploy.sh so the deploy story
# across both projects on this host stays consistent (branch-aware,
# log to /var/log/<project>-deploy.log, no-op when HEAD has not moved).
#
# Wired by deploy/install-on-hetzner.sh into root's crontab as:
#   * * * * * /opt/adversary/deploy/auto-deploy.sh
#
# Why every minute: lets you push a fix from the Mac and have the
# Hetzner dashboard reload before you switch tabs. The script exits
# 0 on no-op so cron does not spam mail every minute.

set -e

cd /opt/adversary

LOG=/var/log/adversary-deploy.log
exec >>"$LOG" 2>&1

BRANCH=$(git symbolic-ref --short -q HEAD || true)
if [ -z "$BRANCH" ]; then
    echo "$(date -Is) auto-deploy: HEAD detached, skipping. Re-attach with: git checkout main"
    exit 0
fi

OLD=$(git rev-parse HEAD)
git fetch origin "$BRANCH" --quiet
NEW=$(git rev-parse "origin/$BRANCH")

if [ "$OLD" = "$NEW" ]; then
    exit 0
fi

echo "$(date -Is) deploy: $BRANCH $OLD -> $NEW"

git merge --ff-only "origin/$BRANCH"

# Detect whether the Caddy fragment source changed in the incoming range.
# If yes, re-run the installer so the proxy config refreshes alongside
# the container. The installer is idempotent.
CADDY_CHANGED=0
if git diff --name-only "$OLD" "$NEW" | grep -qxE '^deploy/Caddyfile$|^deploy/install-on-hetzner\.sh$'; then
    CADDY_CHANGED=1
fi

# Rebuild on anything that ends up baked into the image. The Dockerfile
# does `COPY src /app/src` at build time and there is no bind mount of
# host /opt/adversary/src to /app/src in docker-compose.yml, so a pure
# `docker compose up --detach` restarts the SAME image with the SAME
# stale source. Pulling new source files into /opt/adversary/src/ on
# the host does nothing visible to the running container until we
# rebuild. (This bit us on the streaming-progress deploy: the form
# kept behaving like the old sync version because the host had the new
# code but the container kept its old copy.) Treat src/, templates/,
# any .py / .html / .css inside the package, plus the existing
# Dockerfile / compose / pyproject as build-triggering paths.
NEEDS_BUILD=0
if git diff --name-only "$OLD" "$NEW" \
    | grep -qE '^deploy/Dockerfile$|^deploy/docker-compose\.yml$|^pyproject\.toml$|^src/|\.(py|html|css|js)$'; then
    NEEDS_BUILD=1
fi

COMPOSE=/opt/adversary/deploy/docker-compose.yml

if [ "$NEEDS_BUILD" = "1" ]; then
    echo "$(date -Is) Dockerfile / compose / pyproject changed — rebuilding image"
    if ! docker compose -f "$COMPOSE" up --detach --build; then
        echo "$(date -Is) ERROR: docker compose up --build failed. Recent logs:"
        docker compose -f "$COMPOSE" logs --tail 40 adversary || true
        exit 1
    fi
else
    echo "$(date -Is) source-only change — restarting container to re-import modules"
    if ! docker compose -f "$COMPOSE" up --detach; then
        echo "$(date -Is) ERROR: docker compose up failed. Recent logs:"
        docker compose -f "$COMPOSE" logs --tail 40 adversary || true
        exit 1
    fi
fi

if [ "$CADDY_CHANGED" = "1" ]; then
    echo "$(date -Is) Caddy fragment source changed — re-running installer to refresh proxy"
    if ! bash /opt/adversary/deploy/install-on-hetzner.sh; then
        echo "$(date -Is) ERROR: installer failed during Caddy refresh."
        exit 1
    fi
fi

# Wait for the new container to report healthy. If it never does, log the
# failure loudly so the next run does not paper over a broken deploy.
for attempt in $(seq 1 20); do
    state=$(docker inspect --format='{{.State.Health.Status}}' adversary 2>/dev/null || echo missing)
    if [ "$state" = "healthy" ]; then
        echo "$(date -Is) deploy complete, container healthy after $((attempt * 2))s"
        exit 0
    fi
    sleep 2
done

echo "$(date -Is) ERROR: container did not become healthy within 40s. Recent logs:"
docker compose -f "$COMPOSE" logs --tail 40 adversary || true
exit 1
