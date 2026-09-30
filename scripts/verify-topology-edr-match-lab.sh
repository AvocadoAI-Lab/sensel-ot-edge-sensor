#!/usr/bin/env bash
# Lab EDR × OT topology match (PRD §4.5 / §11.2 item 6).
#
# Usage:
#   cp .env.lab.example .env.lab
#   ./scripts/verify-topology-edr-match-lab.sh
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
export TENANT_ID="${TENANT_ID:-company-a9ae1234648ee138}"
export WORKSPACE_ID="${WORKSPACE_ID:-6}"
export BASELINE_SENSOR_ID="${BASELINE_SENSOR_ID:-ot-edge-001}"
export OT_SECURITY_INGEST_SECRET="${OT_SECURITY_INGEST_SECRET:-sensel-ot-ingest-lab-2026}"
export EDR_MATCH_SCENARIO="${EDR_MATCH_SCENARIO:-ubuntu108}"

exec python3 "$ROOT/scripts/verify_topology_edr_match_lab.py" "$@"
