#!/usr/bin/env bash
#
# install-on-hetzner.sh
#
# One-shot deploy of the Adversary stack on the Hetzner box (5.161.253.237).
# Idempotent — safe to re-run; will not clobber the .env, the SqliteStore,
# or the Fernet secret key.
#
# Run as root, on the host:
#   bash /opt/adversary/deploy/install-on-hetzner.sh
#
# Pre-conditions checked at the top of the script. Each fail-stop names the
# exact remediation command so a human re-running can fix and continue.

set -euo pipefail

ADV_ROOT=/opt/adversary
COMPOSE_FILE="${ADV_ROOT}/deploy/docker-compose.yml"
CADDY_FRAGMENT_SRC="${ADV_ROOT}/deploy/Caddyfile"
CADDY_FRAGMENT_DST=/etc/caddy/Caddyfile.d/adversary.caddy
CADDY_MAIN=/etc/caddy/Caddyfile
SUBDOMAIN="adversary.5-161-253-237.sslip.io"

die() {
    echo "FATAL: $*" >&2
    exit 1
}

note() {
    echo "==> $*"
}

# ---------------------------------------------------------------------------
# Pre-flight
# ---------------------------------------------------------------------------

[[ $EUID -eq 0 ]] || die "must run as root (sudo bash $0)"
[[ -d "${ADV_ROOT}" ]] || die "${ADV_ROOT} missing — clone the repo there first: git clone https://github.com/scott-lydon/adversary ${ADV_ROOT}"
[[ -f "${ADV_ROOT}/.env" ]] || die "${ADV_ROOT}/.env missing — write provider keys (OPENAI_API_KEY, TOGETHER_API_KEY, ANTHROPIC_API_KEY) and chmod 600"
[[ "$(stat -c '%a' "${ADV_ROOT}/.env")" == "600" ]] || die "${ADV_ROOT}/.env must be mode 600 (run: chmod 600 ${ADV_ROOT}/.env)"

command -v docker >/dev/null || die "docker not installed (apt install docker.io docker-compose-v2)"
docker compose version >/dev/null 2>&1 || die "docker compose v2 plugin missing (apt install docker-compose-v2)"

# ---------------------------------------------------------------------------
# Host-side state directories
# ---------------------------------------------------------------------------

note "ensuring state dirs exist"
install -d -m 0755 "${ADV_ROOT}/data"
install -d -m 0700 "${ADV_ROOT}/secret"
install -d -m 0755 "${ADV_ROOT}/regress"

# ---------------------------------------------------------------------------
# Caddy
# ---------------------------------------------------------------------------

if ! command -v caddy >/dev/null; then
    note "installing Caddy from official apt repo"
    apt-get update
    apt-get install --yes debian-keyring debian-archive-keyring apt-transport-https curl
    curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' \
        | gpg --dearmor --yes --output /usr/share/keyrings/caddy-stable-archive-keyring.gpg
    curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' \
        > /etc/apt/sources.list.d/caddy-stable.list
    apt-get update
    apt-get install --yes caddy
fi

note "wiring Caddy fragment for ${SUBDOMAIN}"
install -d -m 0755 /etc/caddy/Caddyfile.d
install -m 0644 "${CADDY_FRAGMENT_SRC}" "${CADDY_FRAGMENT_DST}"

# Make sure the main Caddyfile imports the fragment dir.
if ! grep -q 'Caddyfile.d/\*\.caddy' "${CADDY_MAIN}"; then
    echo "import /etc/caddy/Caddyfile.d/*.caddy" >> "${CADDY_MAIN}"
fi

# Generate and persist the basic-auth password.
#
# Plaintext lives at /opt/adversary/.htpasswd-source mode 600; bcrypt
# at /opt/adversary/.htpasswd-bcrypt mode 600. The bcrypt is
# sed-substituted into the Caddyfile fragment (NOT env-var-expanded;
# `caddy validate` does not load the systemd EnvironmentFile and would
# see an empty placeholder).
#
# To set or rotate the password explicitly:
#   ADVERSARY_BASIC_AUTH_PLAINTEXT='pass' bash deploy/install-on-hetzner.sh
#
# If neither the env var nor the existing file is set, a fresh random
# password is generated.
if [[ -n "${ADVERSARY_BASIC_AUTH_PLAINTEXT:-}" ]]; then
    note "ADVERSARY_BASIC_AUTH_PLAINTEXT supplied — overwriting password files"
    PLAINTEXT="${ADVERSARY_BASIC_AUTH_PLAINTEXT}"
    install -m 0600 /dev/null "${ADV_ROOT}/.htpasswd-source"
    printf '%s\n' "${PLAINTEXT}" > "${ADV_ROOT}/.htpasswd-source"
    HASH=$(caddy hash-password --plaintext "${PLAINTEXT}")
    install -m 0600 /dev/null "${ADV_ROOT}/.htpasswd-bcrypt"
    printf '%s\n' "${HASH}" > "${ADV_ROOT}/.htpasswd-bcrypt"
elif [[ ! -f "${ADV_ROOT}/.htpasswd-bcrypt" ]]; then
    note "generating random dashboard password (plaintext: ${ADV_ROOT}/.htpasswd-source, bcrypt: ${ADV_ROOT}/.htpasswd-bcrypt; both 0600)"
    PLAINTEXT=$(openssl rand -base64 18 | tr -d '/+=' | head -c 24)
    install -m 0600 /dev/null "${ADV_ROOT}/.htpasswd-source"
    printf '%s\n' "${PLAINTEXT}" > "${ADV_ROOT}/.htpasswd-source"
    HASH=$(caddy hash-password --plaintext "${PLAINTEXT}")
    install -m 0600 /dev/null "${ADV_ROOT}/.htpasswd-bcrypt"
    printf '%s\n' "${HASH}" > "${ADV_ROOT}/.htpasswd-bcrypt"
fi

HASH=$(cat "${ADV_ROOT}/.htpasswd-bcrypt")
[[ -n "${HASH}" ]] || die "${ADV_ROOT}/.htpasswd-bcrypt empty — delete it and re-run to regenerate"

note "writing Caddy fragment with embedded bcrypt hash"
# Escape the hash for sed: only $ and & need handling in replacement.
HASH_ESC=$(printf '%s' "${HASH}" | sed -e 's/[\&|]/\\&/g')
sed "s|{\$ADVERSARY_BASIC_AUTH_HASH}|${HASH_ESC}|g" \
    "${CADDY_FRAGMENT_SRC}" > "${CADDY_FRAGMENT_DST}.tmp"
chmod 0644 "${CADDY_FRAGMENT_DST}.tmp"
mv "${CADDY_FRAGMENT_DST}.tmp" "${CADDY_FRAGMENT_DST}"

note "validating Caddyfile"
caddy validate --config "${CADDY_MAIN}" --adapter caddyfile

note "(re)starting Caddy"
systemctl enable --now caddy
systemctl restart caddy

# ---------------------------------------------------------------------------
# Adversary container
# ---------------------------------------------------------------------------

note "building + starting adversary container"
docker compose -f "${COMPOSE_FILE}" up -d --build

note "waiting for /healthz"
for attempt in {1..30}; do
    if curl --fail --silent --max-time 2 http://127.0.0.1:8765/healthz >/dev/null; then
        note "dashboard healthy on 127.0.0.1:8765"
        break
    fi
    sleep 2
    if [[ $attempt -eq 30 ]]; then
        echo "FATAL: dashboard never reported healthy. Recent container logs:" >&2
        docker compose -f "${COMPOSE_FILE}" logs --tail 80 adversary >&2
        exit 1
    fi
done

note "verifying public URL https://${SUBDOMAIN}"
sleep 3  # give Caddy a moment to issue the cert on first hit
HTTP_CODE=$(curl --silent --max-time 30 --output /dev/null --write-out '%{http_code}' "https://${SUBDOMAIN}/" || true)
case "${HTTP_CODE}" in
    401)
        note "OK: 401 means TLS works and Basic-Auth is gating; password in ${ADV_ROOT}/.htpasswd-source"
        ;;
    200)
        note "OK: 200 (no auth, unexpected — check Caddyfile.d/adversary.caddy basic_auth block)"
        ;;
    *)
        echo "WARNING: unexpected HTTP ${HTTP_CODE} from https://${SUBDOMAIN}/" >&2
        echo "  Check: journalctl -u caddy -n 80" >&2
        ;;
esac

# ---------------------------------------------------------------------------
# Auto-deploy cron — mirrors the Clinical Co-Pilot's auto-deploy pattern
# (see /opt/openemr/auto-deploy.sh). Polls origin every minute, ff-merges,
# rebuilds the compose stack only when the relevant files changed.
# ---------------------------------------------------------------------------

CRON_LINE='* * * * * /opt/adversary/deploy/auto-deploy.sh'
CRON_TMP=$(mktemp)
crontab -l 2>/dev/null > "${CRON_TMP}" || true

if grep -Fqx "${CRON_LINE}" "${CRON_TMP}"; then
    note "auto-deploy cron already installed"
else
    note "installing auto-deploy cron line: ${CRON_LINE}"
    printf '%s\n' "${CRON_LINE}" >> "${CRON_TMP}"
    crontab "${CRON_TMP}"
fi
rm -f "${CRON_TMP}"

# Make sure the log file exists with sane permissions so the first cron
# invocation does not fail on a missing path.
touch /var/log/adversary-deploy.log
chmod 0644 /var/log/adversary-deploy.log

note "done"
echo
echo "Dashboard URL:    https://${SUBDOMAIN}"
echo "Login:            admin / \$(cat ${ADV_ROOT}/.htpasswd-source)"
echo "Container logs:   docker compose -f ${COMPOSE_FILE} logs -f adversary"
echo "Deploy log:       tail -f /var/log/adversary-deploy.log"
echo "Manual deploy:    bash /opt/adversary/deploy/auto-deploy.sh    # forces a check now"
