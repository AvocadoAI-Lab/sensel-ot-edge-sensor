#!/usr/bin/env bash
# Stop existing EdgeX on Pi and deploy full SenseL + EdgeX MVP stack.
# Usage:
#   ./scripts/deploy-pi-full.sh [--profile lab|production] [user@host]
set -euo pipefail

PROFILE="lab"
TARGET="edgex@192.168.1.123"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --profile)
      PROFILE="${2:-lab}"
      shift 2
      ;;
    --profile=*)
      PROFILE="${1#*=}"
      shift
      ;;
    *)
      TARGET="$1"
      shift
      ;;
  esac
done

REMOTE_DIR="~/sensel-ot-edge-sensor"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"

if [[ "${PROFILE}" != "lab" && "${PROFILE}" != "production" ]]; then
  echo "Unknown profile: ${PROFILE} (use lab or production)" >&2
  exit 1
fi

COMPOSE_FILES="-f docker-compose.yml -f docker-compose.pi4.yml -f docker-compose.lab-61850.yml"
if [[ "${PROFILE}" == "lab" ]]; then
  COMPOSE_FILES="${COMPOSE_FILES} -f docker-compose.pi-lab.yml"
else
  COMPOSE_FILES="${COMPOSE_FILES} -f docker-compose.pi-production.yml"
fi

SSH_CMD=(ssh)
if [[ -n "${SSHPASS:-}" ]] && command -v sshpass >/dev/null 2>&1; then
  export RSYNC_RSH="sshpass -e ssh -o StrictHostKeyChecking=no"
  SSH_CMD=(sshpass -e ssh -o StrictHostKeyChecking=no)
fi

echo "==> Syncing repo to ${TARGET}:${REMOTE_DIR} (profile=${PROFILE})"
rsync -avz --delete \
  --exclude .git \
  --exclude data/ \
  --exclude '__pycache__' \
  --exclude '*.pyc' \
  --exclude .venv \
  --exclude node_modules \
  "${ROOT}/" "${TARGET}:${REMOTE_DIR}/"

echo "==> Stopping old stacks and starting full SenseL stack"
"${SSH_CMD[@]}" "${TARGET}" env \
  OT_REGISTRATION_TOKEN="${OT_REGISTRATION_TOKEN:-}" \
  MQTT_TENANT_ID="${MQTT_TENANT_ID:-default}" \
  DEPLOY_PROFILE="${PROFILE}" \
  COMPOSE_FILES="${COMPOSE_FILES}" \
  bash -s <<'REMOTE'
set -euo pipefail
cd ~/sensel-ot-edge-sensor
mkdir -p data/agent data/pcap data/assets config/policy
chmod +x scripts/*.sh scripts/*.py 2>/dev/null || true

if [[ ! -f config/policy/baseline.json ]]; then
  cp config/policy/baseline.example.json config/policy/baseline.json
fi

if [[ ! -f data/agent/capture.env ]]; then
  cat > data/agent/capture.env <<CAP
CAPTURE_INTERFACE=eth0
CAPTURE_BPF_FILTER=(ether proto 0x88b8) or (tcp port 102)
MQTT_TENANT_ID=${MQTT_TENANT_ID:-default}
CAP
fi

cat > .env <<ENV
SITE_ID=factory-lab-001
SENSOR_ID=ot-edge-pi4-001
SENSOR_TYPE=ot-edge-sensor
SENSEL_API_URL=http://192.168.1.108:8081
SENSEL_API_KEY=sensel-ot-ingest-lab-2026
OT_REGISTRATION_TOKEN=${OT_REGISTRATION_TOKEN:-}
SENSEL_VERIFY_TLS=false
MGMT_INTERFACE=eth0
CAPTURE_INTERFACE=eth0
CAPTURE_BPF_FILTER=(ether proto 0x88b8) or (tcp port 102)
GOOSE_INTERFACE=eth0
MMS_INTERFACE=eth0
MMS_SRC_IP=192.168.10.88
MMS_DST_IP=192.168.10.50
LOCAL_MQTT_HOST=127.0.0.1
LOCAL_MQTT_PORT=1884
NORTHBOUND_MQTT_ENABLED=true
CONTROL_PLANE_MQTT_HOST=192.168.1.203
CONTROL_PLANE_MQTT_PORT=1883
MQTT_TENANT_ID=${MQTT_TENANT_ID:-default}
MQTT_REQUIRE_TENANT=$([[ "${DEPLOY_PROFILE}" == "production" ]] && echo true || echo false)
EDGE_CONSOLE_DOCKER_RESTART=true
EDGE_CONSOLE_AUTO_RESTART_AGENT=true
DEPLOY_TARGET=pi4
LOG_LEVEL=info
ENV

echo "==> Stopping SenseL edge-only stack (if running)"
docker compose -f docker-compose.edge-only.yml -f docker-compose.lab-61850.yml down --remove-orphans 2>/dev/null || true

echo "==> Stopping existing EdgeX at ~/edgex"
if [[ -f ~/edgex/docker-compose.yml ]]; then
  docker compose -f ~/edgex/docker-compose.yml down --remove-orphans || true
fi

echo "==> Waiting for port release"
sleep 5
ss -tlnp | grep -E ':5432|:1883|:59880|:59881|:59890' || echo "  ports clear"

echo "==> Building and starting full stack (${DEPLOY_PROFILE})"
docker compose ${COMPOSE_FILES} up -d --build

echo "==> Lab URLs"
PI_IP=$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src") print $(i+1)}' | head -1)
PI_IP=${PI_IP:-192.168.1.123}
echo "  Edge Console:  http://${PI_IP}:8090  ← 設定企業邀請碼 / 註冊"
if [[ "${DEPLOY_PROFILE}" == "lab" ]]; then
  echo "  Events Viewer: http://${PI_IP}:8080"
fi
echo "  EdgeX UI (optional): docker compose ... -f docker-compose.pi-ui.yml --profile lab-ui up -d → :4000"

echo "==> Container status"
docker compose ${COMPOSE_FILES} ps

echo "==> Waiting for EdgeX core-data"
for i in $(seq 1 30); do
  if curl -sf http://127.0.0.1:59880/api/v3/ping >/dev/null 2>&1; then
    echo "  core-data ready"
    break
  fi
  sleep 2
done

echo "==> Service logs (tail)"
docker logs sensel-edge-console --tail 5 2>&1 || true
docker logs sensel-edge-agent --tail 8 2>&1 || true
docker logs sensel-packet-sensor --tail 8 2>&1 || true
docker logs edgex-device-modbus --tail 5 2>&1 || true
REMOTE

echo "==> Full stack deploy complete (${PROFILE}). SSH: ssh ${TARGET}"
echo "    Verify onboarding: EDGE_CONSOLE_URL=http://<pi>:8090 INVITE_CODE=... SENSEL_API_KEY=... ./scripts/verify-pi-onboarding.sh"
