#!/usr/bin/env bash
# P4: Baseline Live Learning lab acceptance (PRD §13 + CTA 联调).
#
# Usage:
#   cp .env.lab.example .env.lab   # fill PORTAL_EMAIL / PORTAL_PASSWORD
#   export TENANT_ID=company-a9ae1234648ee138
#   ./scripts/verify-baseline-live-learning-lab.sh
#
# Full flow verify (after manual Portal steps):
#   ./scripts/verify-baseline-live-learning-lab.sh --expect-mode detect --expect-event-metadata
#
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
if [[ -f "$ROOT/.env.lab" ]]; then
  set -a
  # shellcheck disable=SC1091
  source "$ROOT/.env.lab"
  set +a
fi

export CONTROL_PLANE_BASE_URL="${CONTROL_PLANE_BASE_URL:-http://192.168.1.108:8081}"
export LAYERC_URL="${LAYERC_URL:-http://192.168.1.203:8001}"
export EDGE_CONSOLE_URL="${EDGE_CONSOLE_URL:-http://192.168.1.124:8090}"
export TENANT_ID="${TENANT_ID:-company-a9ae1234648ee138}"
export WORKSPACE_ID="${WORKSPACE_ID:-6}"

exec python3 "$ROOT/scripts/verify_baseline_live_learning_lab.py" "$@"
