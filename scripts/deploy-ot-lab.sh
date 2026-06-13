#!/usr/bin/env bash
# OT-B4: one-click lab deploy — Pi (124) + Control Plane Layer A/C (203) + SenseL (108).
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
#   ./scripts/deploy-ot-lab.sh --cta      # CTA PoC: deploy all + verify CTA coverage
#   ./scripts/deploy-ot-lab.sh --108-only # SenseL only
#   ./scripts/deploy-ot-lab.sh --203-only # Layer A + Layer C only
#   ./scripts/deploy-ot-lab.sh --pi-only    # Pi edge sensor only
#   ./scripts/deploy-ot-lab.sh --verify     # E2E Layer C analyze only (no deploy)
#   ./scripts/deploy-ot-lab.sh --verify-track-b  # Track B E2E only
#   ./scripts/deploy-ot-lab.sh --verify-track-b  # Track B E2E only
#   ./scripts/deploy-ot-lab.sh --track-b    # deploy all + Track B E2E gate
#   ./scripts/deploy-ot-lab.sh --sprint4    # deploy all + Sprint4 gate (S5-G1)
#   ./scripts/deploy-ot-lab.sh --verify-sprint4  # Sprint4 gate only (no deploy)
#   ./scripts/deploy-ot-lab.sh --verify-cta    # CTA coverage gate only (no deploy)
#
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CP_ROOT="${ARISTACONNECTOR_PATH:-$(dirname "$ROOT")/Aristaconnector-Control-Plane}"
GUAC_ROOT="${GUACAMOLE_PATH:-$(dirname "$ROOT")/guacamole-ai}"

if [[ -f "$ROOT/.env.lab" ]]; then
  set -a
  # shellcheck disable=SC1091
  source "$ROOT/.env.lab"
  set +a
fi

PI_TARGET="${PI_TARGET:-edgex@192.168.1.124}"
CP_TARGET="${CP_TARGET:-avocado.ai@192.168.1.203}"
SENSEL_HOST="${SENSEL_HOST:-192.168.1.108}"
SENSEL_USER="${SENSEL_USER:-ubuntu}"
SENSEL_REMOTE_DIR="${SENSEL_REMOTE_DIR:-/home/ubuntu/guacamole-ai}"

CONTROL_PLANE_BASE_URL="${CONTROL_PLANE_BASE_URL:-http://${SENSEL_HOST}:8081}"
OT_SECURITY_INGEST_SECRET="${OT_SECURITY_INGEST_SECRET:-sensel-ot-ingest-lab-2026}"
LAYERC_URL="${LAYERC_URL:-http://192.168.1.203:8001}"
TENANT_ID="${TENANT_ID:-company-a9ae1234648ee138}"

DEPLOY_108=1
DEPLOY_203=1
DEPLOY_PI=1
VERIFY_ONLY=0
VERIFY_TRACK_B=0
SPRINT4=0
VERIFY_SPRINT4=0
VERIFY_CTA=0
CTA_MODE=0
EXPECT_LLM=0

for arg in "$@"; do
  case "$arg" in
    --108-only) DEPLOY_203=0; DEPLOY_PI=0 ;;
    --203-only) DEPLOY_108=0; DEPLOY_PI=0 ;;
    --pi-only)  DEPLOY_108=0; DEPLOY_203=0 ;;
    --verify)   VERIFY_ONLY=1; DEPLOY_108=0; DEPLOY_203=0; DEPLOY_PI=0 ;;
    --verify-track-b) VERIFY_ONLY=1; VERIFY_TRACK_B=1; DEPLOY_108=0; DEPLOY_203=0; DEPLOY_PI=0 ;;
    --verify-sprint4) VERIFY_ONLY=1; VERIFY_SPRINT4=1; SPRINT4=1; EXPECT_LLM=1 ;;
    --verify-cta) VERIFY_ONLY=1; VERIFY_CTA=1; DEPLOY_108=0; DEPLOY_203=0; DEPLOY_PI=0 ;;
    --track-b)  VERIFY_TRACK_B=1 ;;
    --sprint4)  SPRINT4=1; VERIFY_SPRINT4=1; EXPECT_LLM=1 ;;
    --cta)      CTA_MODE=1; VERIFY_CTA=1 ;;
    --expect-llm) EXPECT_LLM=1 ;;
    -h|--help)
      sed -n '2,22p' "$0"
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
    if [[ "${SPRINT4:-0}" == "1" ]]; then
      export DEPLOY_COMPOSE_SERVICES="${DEPLOY_COMPOSE_SERVICES_SPRINT4:-postgres redis api portal}"
    else
      export DEPLOY_COMPOSE_SERVICES="postgres redis api"
    fi
    export DEPLOY_WITH_EDR="${DEPLOY_WITH_EDR:-1}"
    export DEPLOY_WITH_INVESTIGATION="${DEPLOY_WITH_INVESTIGATION:-auto}"
    ./scripts/deploy_docker_compose.sh
  )
  echo "==> [108] Run alembic migrations (OT security tables)"
  sshpass -e ssh -o StrictHostKeyChecking=accept-new "${SENSEL_USER}@${SENSEL_HOST}" bash -s <<REMOTE
set -euo pipefail
cd "${SENSEL_REMOTE_DIR}"
docker compose exec -T api bash -c 'cd sensel_control_plane && alembic upgrade head' || echo "WARN: alembic skipped (check sensel_control_plane path)"
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
    export OT_LLM_ENRICH="${OT_LLM_ENRICH:-0}"
    export OT_LLM_MODEL="${OT_LLM_MODEL:-gemma2:2b}"
    export OT_LLM_MAX_TOKENS="${OT_LLM_MAX_TOKENS:-512}"
    export OT_BEHAVIOR_AE_ENABLED="${OT_BEHAVIOR_AE_ENABLED:-0}"
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
  _lab_sshpass="${SSHPASS:-}"
  export SSHPASS="${PI_SSHPASS:-edgex}"
  "$ROOT/scripts/deploy-pi-full.sh" "$PI_TARGET"
  export SSHPASS="$_lab_sshpass"
}

verify_layerc() {
  echo "==> [E2E] OT Layer C analyze profile on ${LAYERC_URL}"
  [[ -d "$CP_ROOT" ]] || { echo "Missing Control Plane at $CP_ROOT" >&2; exit 1; }
  if [[ "$EXPECT_LLM" == "1" ]]; then
    PYTHONPATH="$CP_ROOT" python3 "$CP_ROOT/scripts/e2e-ot-layerc-analyze.py" \
      --layerc-url "$LAYERC_URL" \
      --expect-status ok \
      --expect-llm
  else
    PYTHONPATH="$CP_ROOT" python3 "$CP_ROOT/scripts/e2e-ot-layerc-analyze.py" \
      --layerc-url "$LAYERC_URL" \
      --expect-status ok
  fi
}

verify_sprint4_lab() {
  echo "==> [S5-G1] Sprint 4 lab acceptance gate"
  chmod +x "$ROOT/scripts/verify-sprint4-lab.sh" 2>/dev/null || true
  SPRINT4_ARGS=()
  if [[ "$EXPECT_LLM" == "1" ]]; then
    SPRINT4_ARGS+=(--expect-llm)
  else
    SPRINT4_ARGS+=(--no-llm)
  fi
  export SENSEL_API_URL="${CONTROL_PLANE_BASE_URL}"
  export LAYERC_URL PI_TARGET WORKSPACE_ID
  "$ROOT/scripts/verify-sprint4-lab.sh" "${SPRINT4_ARGS[@]}"
}

if [[ "$SPRINT4" == "1" ]]; then
  export OT_LLM_ENRICH="${OT_LLM_ENRICH:-1}"
  export OT_LLM_MODEL="${OT_LLM_MODEL:-gemma2:2b}"
  export OT_LLM_MAX_TOKENS="${OT_LLM_MAX_TOKENS:-512}"
  export OT_BEHAVIOR_AE_ENABLED="${OT_BEHAVIOR_AE_ENABLED:-1}"
  export DEPLOY_COMPOSE_SERVICES_SPRINT4="${DEPLOY_COMPOSE_SERVICES_SPRINT4:-postgres redis api portal}"
  echo "==> Sprint 4 mode: OT_LLM_ENRICH=$OT_LLM_ENRICH OT_BEHAVIOR_AE_ENABLED=$OT_BEHAVIOR_AE_ENABLED EXPECT_LLM=$EXPECT_LLM"
fi

verify_cta_lab() {
  echo "==> [CTA] Coverage lab acceptance gate"
  chmod +x "$ROOT/scripts/verify-cta-lab.sh" 2>/dev/null || true
  export LAYERC_URL CONTROL_PLANE_BASE_URL TENANT_ID CP_TARGET SENSEL_HOST
  if "$ROOT/scripts/verify-cta-lab.sh"; then
    return 0
  fi
  if [[ "${CTA_MODE:-0}" == "1" ]]; then
    echo "WARN: CTA verify failed after deploy (see above)" >&2
    return 0
  fi
  return 1
}

if [[ "$VERIFY_ONLY" == "1" ]]; then
  if [[ "$VERIFY_CTA" == "1" ]]; then
    verify_cta_lab
    exit $?
  fi
  if [[ "$VERIFY_SPRINT4" == "1" ]]; then
    verify_sprint4_lab
    exit $?
  fi
  if [[ "$VERIFY_TRACK_B" == "1" ]]; then
    echo "==> [E2E] Track B CTI closed loop"
    export SMB_INTEL_API_KEY="${SMB_INTEL_API_KEY:-}"
    export POLICY_SYNC_TENANT_ID="${POLICY_SYNC_TENANT_ID:-sensel-platform}"
    export PI_TARGET="${PI_TARGET:-edgex@192.168.1.123}"
    export SSHPASS="${SSHPASS:-edgex}"
    "$ROOT/scripts/verify-track-b-e2e.sh" ${TRACK_B_EXPECT_CORRELATE:+--expect-correlate} ${TRACK_B_PROBE_IP:+--probe-ip "$TRACK_B_PROBE_IP"}
    exit $?
  fi
  verify_layerc
  exit 0
fi

[[ "$DEPLOY_108" == "1" ]] && deploy_108
[[ "$DEPLOY_203" == "1" ]] && deploy_203
[[ "$DEPLOY_PI" == "1" ]] && deploy_pi

if [[ "$VERIFY_SPRINT4" == "1" ]]; then
  verify_sprint4_lab
elif [[ "$VERIFY_CTA" == "1" ]]; then
  verify_cta_lab || true
else
  verify_layerc
fi

if [[ "$VERIFY_TRACK_B" == "1" ]]; then
  echo "==> [E2E] Track B CTI closed loop"
  export SMB_INTEL_API_KEY="${SMB_INTEL_API_KEY:-}"
  export POLICY_SYNC_TENANT_ID="${POLICY_SYNC_TENANT_ID:-sensel-platform}"
  export PI_TARGET="${PI_TARGET:-edgex@192.168.1.123}"
  export SSHPASS="${SSHPASS:-edgex}"
  "$ROOT/scripts/verify-track-b-e2e.sh" ${TRACK_B_EXPECT_CORRELATE:+--expect-correlate} ${TRACK_B_PROBE_IP:+--probe-ip "$TRACK_B_PROBE_IP"}
fi

echo ""
echo "==> OT lab deploy complete"
echo "  SenseL Portal:  http://${SENSEL_HOST}:8081"
echo "  Layer C API:    ${LAYERC_URL}"
echo "  EMQX MQTT:      mqtt://192.168.1.203:1883"
echo "  Pi Edge Console: http://192.168.1.124:8090"
echo ""
echo "CTA verify: ./scripts/verify-cta-lab.sh  (or ./scripts/deploy-ot-lab.sh --verify-cta)"
echo "Verify Portal: 工控安全防護 → CTA 覆蓋率 / 事件 / 感測器 / 資產"
