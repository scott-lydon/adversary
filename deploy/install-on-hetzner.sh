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

# Generate and persist the basic-auth password if it does not already exist.
# Plaintext is written once to /opt/adversary/.htpasswd-source (mode 600);
# the bcrypt hash is exported to /etc/caddy/adversary.env which Caddy reads.
if [[ ! -f "${ADV_ROOT}/.htpasswd-source" ]]; then
    note "generating dashboard password (saved to ${ADV_ROOT}/.htpasswd-source mode 600)"
    PLAINTEXT=$(openssl rand -base64 18 | tr -d '/+=' | head -c 24)
    echo "${PLAINTEXT}" > "${ADV_ROOT}/.htpasswd-source"
    chmod 600 "${ADV_ROOT}/.htpasswd-source"
    HASH=$(caddy hash-password --plaintext "${PLAINTEXT}")
    echo "ADVERSARY_BASIC_AUTH_HASH=${HASH}" > /etc/caddy/adversary.env
    chmod 640 /etc/caddy/adversary.env
    chgrp caddy /etc/caddy/adversary.env || true
fi

# Ensure systemd unit reads the env file with the bcrypt hash.
if ! systemctl cat caddy 2>/dev/null | grep -q '/etc/caddy/adversary.env'; then
    note "patching caddy systemd unit to source /etc/caddy/adversary.env"
    install -d -m 0755 /etc/systemd/system/caddy.service.d
    cat > /etc/systemd/system/caddy.service.d/override.conf <<EOF
[Service]
EnvironmentFile=/etc/caddy/adversary.env
EOF
    systemctl daemon-reload
fi

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

note "done"
echo
echo "Dashboard URL: https://${SUBDOMAIN}"
echo "Login:         admin / \$(cat ${ADV_ROOT}/.htpasswd-source)"
echo "Logs:          docker compose -f ${COMPOSE_FILE} logs -f adversary"
