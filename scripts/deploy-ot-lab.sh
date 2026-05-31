#!/usr/bin/env bash
# OT-B4: one-click lab deploy — Pi (123) + Control Plane Layer A/C (203) + SenseL (108).
#
# Prerequisites:
#   - sshpass installed locally
#   - SSHPASS set (default lab password: avocado@@)
#   - OT_REGISTRATION_TOKEN = Avocado AI enterprise invite code (for Pi sensor binding)
#
# Usage:
#   export SSHPASS='avocado@@'
#   export OT_REGISTRATION_TOKEN='your-invite-code'
#   ./scripts/deploy-ot-lab.sh              # deploy all three
#   ./scripts/deploy-ot-lab.sh --108-only # SenseL only
#   ./scripts/deploy-ot-lab.sh --203-only # Layer A + Layer C only
#   ./scripts/deploy-ot-lab.sh --pi-only    # Pi edge sensor only
#   ./scripts/deploy-ot-lab.sh --verify     # E2E Layer C analyze only (no deploy)
#
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CP_ROOT="${ARISTACONNECTOR_PATH:-$(dirname "$ROOT")/Aristaconnector-Control-Plane}"
GUAC_ROOT="${GUACAMOLE_PATH:-$(dirname "$ROOT")/guacamole-ai}"

PI_TARGET="${PI_TARGET:-edgex@192.168.1.123}"
CP_TARGET="${CP_TARGET:-avocado.ai@192.168.1.203}"
SENSEL_HOST="${SENSEL_HOST:-192.168.1.108}"
SENSEL_USER="${SENSEL_USER:-ubuntu}"
SENSEL_REMOTE_DIR="${SENSEL_REMOTE_DIR:-/home/ubuntu/guacamole-ai}"

CONTROL_PLANE_BASE_URL="${CONTROL_PLANE_BASE_URL:-http://${SENSEL_HOST}:8081}"
OT_SECURITY_INGEST_SECRET="${OT_SECURITY_INGEST_SECRET:-sensel-ot-ingest-lab-2026}"
LAYERC_URL="${LAYERC_URL:-http://192.168.1.203:8001}"

DEPLOY_108=1
DEPLOY_203=1
DEPLOY_PI=1
VERIFY_ONLY=0

for arg in "$@"; do
  case "$arg" in
    --108-only) DEPLOY_203=0; DEPLOY_PI=0 ;;
    --203-only) DEPLOY_108=0; DEPLOY_PI=0 ;;
    --pi-only)  DEPLOY_108=0; DEPLOY_203=0 ;;
    --verify)   VERIFY_ONLY=1; DEPLOY_108=0; DEPLOY_203=0; DEPLOY_PI=0 ;;
    -h|--help)
      sed -n '2,18p' "$0"
      exit 0
      ;;
    *) echo "Unknown arg: $arg" >&2; exit 1 ;;
  esac
done

if [[ -z "${SSHPASS:-}" ]]; then
  echo "Set SSHPASS for non-interactive SSH (lab: export SSHPASS='avocado@@')" >&2
  exit 1
fi

if ! command -v sshpass >/dev/null 2>&1; then
  echo "sshpass required" >&2
  exit 1
fi

deploy_108() {
  echo "==> [108] Deploy SenseL (guacamole-ai) to ${SENSEL_USER}@${SENSEL_HOST}"
  [[ -d "$GUAC_ROOT" ]] || { echo "Missing guacamole-ai at $GUAC_ROOT" >&2; exit 1; }
  (
    cd "$GUAC_ROOT"
    export DEPLOY_SSH_HOST="$SENSEL_HOST"
    export DEPLOY_SSH_PORT=22
    export DEPLOY_SSH_USER="$SENSEL_USER"
    export DEPLOY_REMOTE_REPO_DIR="$SENSEL_REMOTE_DIR"
    export DEPLOY_COMPOSE_SERVICES="postgres redis api"
    export DEPLOY_WITH_EDR=0
    export DEPLOY_WITH_INVESTIGATION=0
    ./scripts/deploy_docker_compose.sh
  )
  echo "==> [108] Run alembic migrations (OT security tables)"
  sshpass -e ssh -o StrictHostKeyChecking=accept-new "${SENSEL_USER}@${SENSEL_HOST}" bash -s <<REMOTE
set -euo pipefail
cd "${SENSEL_REMOTE_DIR}"
docker compose exec -T api alembic upgrade head
REMOTE
  echo "==> [108] SenseL API: ${CONTROL_PLANE_BASE_URL}/api/health"
}

deploy_203() {
  echo "==> [203] Deploy Layer A + Layer C (Control Plane) to ${CP_TARGET}"
  [[ -d "$CP_ROOT" ]] || { echo "Missing Control Plane at $CP_ROOT" >&2; exit 1; }
  (
    cd "$CP_ROOT"
    export CONTROL_PLANE_BASE_URL
    export OT_SECURITY_INGEST_SECRET
    export CONTROL_PLANE_TOKEN="${CONTROL_PLANE_TOKEN:-$OT_SECURITY_INGEST_SECRET}"
    ./scripts/deploy-layerA-remote.sh "$CP_TARGET"
  )
  echo "==> [203] Layer C API: ${LAYERC_URL}/health"
}

deploy_pi() {
  echo "==> [Pi] Deploy edge sensor to ${PI_TARGET}"
  export OT_REGISTRATION_TOKEN="${OT_REGISTRATION_TOKEN:-}"
  if [[ -z "$OT_REGISTRATION_TOKEN" ]]; then
    echo "WARNING: OT_REGISTRATION_TOKEN unset — Pi will register but may stay on tenant=default" >&2
  fi
  "$ROOT/scripts/deploy-pi-full.sh" "$PI_TARGET"
}

verify_layerc() {
  echo "==> [E2E] OT Layer C analyze profile on ${LAYERC_URL}"
  [[ -d "$CP_ROOT" ]] || { echo "Missing Control Plane at $CP_ROOT" >&2; exit 1; }
  PYTHONPATH="$CP_ROOT" python3 "$CP_ROOT/scripts/e2e-ot-layerc-analyze.py" \
    --layerc-url "$LAYERC_URL" \
    --expect-status ok
}

if [[ "$VERIFY_ONLY" == "1" ]]; then
  verify_layerc
  exit 0
fi

[[ "$DEPLOY_108" == "1" ]] && deploy_108
[[ "$DEPLOY_203" == "1" ]] && deploy_203
[[ "$DEPLOY_PI" == "1" ]] && deploy_pi
verify_layerc

echo ""
echo "==> OT lab deploy complete"
echo "  SenseL Portal:  http://${SENSEL_HOST}:8081"
echo "  Layer C API:    ${LAYERC_URL}"
echo "  EMQX MQTT:      mqtt://192.168.1.203:1883"
echo "  Pi events UI:   http://192.168.1.123:8080"
echo ""
echo "Verify Portal: 工控安全防護 → 事件 / 感測器 / 資產"
