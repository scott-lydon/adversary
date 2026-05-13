#!/usr/bin/env bash
# Live multi-LLM scan: loads keys from .env.live, then invokes adversary scan.
# Usage:  scripts/run-live-scan.sh [extra args forwarded to `adversary scan`]
# Defaults match MANUAL_TESTS.md T12 (echo://demo, $0.50 budget, 2 campaigns).
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")"/.. && pwd)"
ENV_FILE="$HERE/.env.live"
[ -r "$ENV_FILE" ] || { echo "FATAL: $ENV_FILE missing" >&2; exit 1; }
set -a; source "$ENV_FILE"; set +a
for k in TOGETHER_API_KEY ANTHROPIC_API_KEY OPENAI_API_KEY; do
  [ -n "${!k:-}" ] || { echo "FATAL: $k empty after sourcing $ENV_FILE" >&2; exit 1; }
done
exec "$HERE/.venv/bin/adversary" scan \
  --target echo://demo \
  --budget-usd 0.50 \
  --max-campaigns 2 \
  --provider live \
  "$@"
