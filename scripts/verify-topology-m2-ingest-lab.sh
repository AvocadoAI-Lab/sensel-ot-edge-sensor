#!/usr/bin/env bash
# Lab M2 syscollector ingest-time EDR match (mirror 10.x without seed IP).
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
export M2_MIRROR_OT_IP="${M2_MIRROR_OT_IP:-192.168.10.88}"

exec python3 "$ROOT/scripts/verify_topology_m2_ingest_lab.py" "$@"
