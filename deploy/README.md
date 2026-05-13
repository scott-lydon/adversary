# Deploy

Production deploy targets the Hetzner box at `5.161.253.237` and exposes the
dashboard at `https://adversary.5-161-253-237.sslip.io` behind Caddy + TLS +
HTTP Basic-Auth.

Files in this directory:

| File | Purpose |
|---|---|
| `Dockerfile` | python:3.12-slim image; `adversary serve` is the entrypoint. |
| `docker-compose.yml` | Single-service stack, host-bound to `127.0.0.1:8765` so only Caddy reaches it. |
| `Caddyfile` | Reverse proxy + auto-TLS + Basic-Auth fragment installed at `/etc/caddy/Caddyfile.d/adversary.caddy`. |
| `install-on-hetzner.sh` | Idempotent installer. Pre-flight checks, Caddy install, password generation, container build + healthz wait. |

## First-time setup

```bash
# On the Hetzner host as root:
git clone https://github.com/scott-lydon/adversary /opt/adversary
cd /opt/adversary

# Drop provider keys (chmod 600 enforced by installer).
cat > .env <<'ENV'
OPENAI_API_KEY=sk-...
TOGETHER_API_KEY=tgp_v1_...
ANTHROPIC_API_KEY=sk-ant-...
ADVERSARY_DASHBOARD_HOST=0.0.0.0
ADVERSARY_DASHBOARD_PORT=8765
ENV
chmod 600 .env

bash deploy/install-on-hetzner.sh
```

## Re-deploy after a code change

**No action needed.** A per-minute cron on the host runs
`/opt/adversary/deploy/auto-deploy.sh`, which polls the current branch's
remote head, ff-merges any new commits, and reruns
`docker compose up --detach` (with `--build` when the Dockerfile,
`docker-compose.yml`, or `pyproject.toml` changed). It also re-runs the
installer when `deploy/Caddyfile` or the installer itself changed, so
proxy-config tweaks roll without a manual SSH.

This mirrors the Clinical Co-Pilot's `/opt/openemr/auto-deploy.sh` flow
so both projects on this host follow the same pattern.

To force an immediate redeploy without waiting for the cron tick:

```bash
ssh root@5.161.253.237 bash /opt/adversary/deploy/auto-deploy.sh
```

To watch the deploy log live:

```bash
ssh root@5.161.253.237 tail -f /var/log/adversary-deploy.log
```

The full installer is idempotent and can be re-run any time:

```bash
ssh root@5.161.253.237 bash /opt/adversary/deploy/install-on-hetzner.sh
```

## Operational notes

- **Audit log lives in `/opt/adversary/data/adversary.db`.** A `docker compose
  down && up` will not lose history; only `rm /opt/adversary/data/adversary.db`
  does.
- **Fernet secret key lives in `/opt/adversary/secret/secret.key`.** Deleting
  it breaks decryption of every credential previously registered through the
  dashboard. There is no recovery; back it up if you store live target
  credentials.
- **Basic-Auth password lives in `/opt/adversary/.htpasswd-source`** in
  plaintext (mode 600, root-only). Caddy holds only the bcrypt hash via
  `/etc/caddy/adversary.env`.
- **`/audit/tamper*` is firewalled at Caddy.** It still works locally for
  debug-only flows; never expose it via the proxy.

## Wiring the Clinical Co-Pilot as a target

The Co-Pilot sidecar runs in the same Docker host. Easiest URL from inside
the adversary container:

```
http://host.docker.internal:8801   # the Co-Pilot sidecar's published port
```

Register it through the dashboard (`/targets/new`) with kind=`copilot` and
auth=`task_token`. The dashboard auto-mints a fresh JWT every 4 minutes by
calling `mint_task_token.py` over SSH (configure with
`ADVERSARY_BFF_SSH_HOST` + `COPILOT_BFF_JWT_SIGNING_KEY` in `.env`).
