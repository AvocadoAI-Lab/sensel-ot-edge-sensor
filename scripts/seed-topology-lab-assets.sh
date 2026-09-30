#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
if [[ -f "$ROOT/.env.lab" ]]; then
  set -a
  # shellcheck disable=SC1091
  source "$ROOT/.env.lab"
  set +a
fi
export CONTROL_PLANE_BASE_URL="${CONTROL_PLANE_BASE_URL:-http://192.168.1.108:8081}"
export OT_SECURITY_INGEST_SECRET="${OT_SECURITY_INGEST_SECRET:-sensel-ot-ingest-lab-2026}"
exec python3 "$ROOT/scripts/seed_topology_lab_assets.py" "$@"
