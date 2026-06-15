#!/usr/bin/env bash
# PRD §11.2 full topology Lab gate: detect delta + graph views + EDR match.
#
# Usage:
#   cp .env.lab.example .env.lab
#   ./scripts/verify-topology-full-gate-lab.sh
#
# Fast re-check (skip Pi delta wait):
#   ./scripts/verify-topology-full-gate-lab.sh --skip-delta-wait
#
# PRD §11 完整驗收（topology + M2 + CVE + §11.3 門檻）:
#   ./scripts/verify-topology-full-gate-lab.sh --prd-11
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
export EDR_MATCH_SCENARIO="${EDR_MATCH_SCENARIO:-windows-hmi}"
export OT_SECURITY_INGEST_SECRET="${OT_SECURITY_INGEST_SECRET:-sensel-ot-ingest-lab-2026}"

exec python3 "$ROOT/scripts/verify_topology_full_gate_lab.py" "$@"
