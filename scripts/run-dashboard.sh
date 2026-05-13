#!/usr/bin/env bash
# Run the local dashboard with the live-provider keys loaded.
# Usage: scripts/run-dashboard.sh [extra args forwarded to `adversary serve`]
#        defaults to --port 8765
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")"/.. && pwd)"
ENV_FILE="$HERE/.env.live"
[ -r "$ENV_FILE" ] || { echo "FATAL: $ENV_FILE missing" >&2; exit 1; }
set -a; source "$ENV_FILE"; set +a
for k in TOGETHER_API_KEY ANTHROPIC_API_KEY OPENAI_API_KEY; do
  [ -n "${!k:-}" ] || { echo "FATAL: $k empty after sourcing $ENV_FILE" >&2; exit 1; }
done
echo "starting adversary serve with live keys loaded; ctrl-C to stop"
exec "$HERE/.venv/bin/adversary" serve --port 8765 "$@"
