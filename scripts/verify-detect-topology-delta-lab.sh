#!/usr/bin/env bash
# Detect mode topology_delta lab E2E (PRD §6.1 Phase 2).
#
# Usage:
#   cp .env.lab.example .env.lab   # fill PORTAL_EMAIL / PORTAL_PASSWORD
#   ./scripts/verify-detect-topology-delta-lab.sh
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
export EDGE_CONSOLE_URL="${EDGE_CONSOLE_URL:-http://192.168.1.124:8090}"
export TENANT_ID="${TENANT_ID:-company-a9ae1234648ee138}"
export WORKSPACE_ID="${WORKSPACE_ID:-6}"
export BASELINE_SENSOR_ID="${BASELINE_SENSOR_ID:-ot-edge-001}"
export DETECT_DELTA_WAIT_SEC="${DETECT_DELTA_WAIT_SEC:-360}"

exec python3 "$ROOT/scripts/verify_detect_topology_delta_lab.py" "$@"
