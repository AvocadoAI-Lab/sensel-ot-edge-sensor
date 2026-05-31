#!/usr/bin/env bash
# Stop existing EdgeX on Pi and deploy full SenseL + EdgeX MVP stack.
# Usage: ./scripts/deploy-pi-full.sh [user@host]
set -euo pipefail

TARGET="${1:-edgex@192.168.1.123}"
REMOTE_DIR="~/sensel-ot-edge-sensor"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"

SSH_CMD=(ssh)
if [[ -n "${SSHPASS:-}" ]] && command -v sshpass >/dev/null 2>&1; then
  export RSYNC_RSH="sshpass -e ssh -o StrictHostKeyChecking=no"
  SSH_CMD=(sshpass -e ssh -o StrictHostKeyChecking=no)
fi

echo "==> Syncing repo to ${TARGET}:${REMOTE_DIR}"
rsync -avz --delete \
  --exclude .git \
  --exclude data/ \
  --exclude '__pycache__' \
  --exclude '*.pyc' \
  --exclude .venv \
  --exclude node_modules \
  "${ROOT}/" "${TARGET}:${REMOTE_DIR}/"

echo "==> Stopping old stacks and starting full SenseL stack"
"${SSH_CMD[@]}" "${TARGET}" bash -s <<'REMOTE'
set -euo pipefail
cd ~/sensel-ot-edge-sensor
mkdir -p data/agent data/pcap data/assets config/policy
chmod +x scripts/*.sh scripts/*.py 2>/dev/null || true

if [[ ! -f config/policy/baseline.json ]]; then
  cp config/policy/baseline.example.json config/policy/baseline.json
fi

cat > .env <<'ENV'
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

echo "==> Building and starting full stack"
docker compose -f docker-compose.yml -f docker-compose.pi4.yml -f docker-compose.pi-lab.yml -f docker-compose.lab-61850.yml up -d --build

echo "==> Lab URLs"
PI_IP=$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src") print $(i+1)}' | head -1)
PI_IP=${PI_IP:-192.168.1.123}
echo "  Events Viewer: http://${PI_IP}:8080"
echo "  EdgeX UI (optional): docker compose ... -f docker-compose.pi-ui.yml --profile lab-ui up -d → :4000"

echo "==> Container status"
docker compose -f docker-compose.yml -f docker-compose.pi4.yml -f docker-compose.pi-lab.yml -f docker-compose.lab-61850.yml ps

echo "==> Waiting for EdgeX core-data"
for i in $(seq 1 30); do
  if curl -sf http://127.0.0.1:59880/api/v3/ping >/dev/null 2>&1; then
    echo "  core-data ready"
    break
  fi
  sleep 2
done

echo "==> Service logs (tail)"
docker logs sensel-edge-agent --tail 8 2>&1 || true
docker logs sensel-packet-sensor --tail 8 2>&1 || true
docker logs edgex-device-modbus --tail 5 2>&1 || true
REMOTE

echo "==> Full stack deploy complete. SSH: ssh ${TARGET}"
