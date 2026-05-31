#!/usr/bin/env bash
# Deploy SenseL edge stack to a lab Pi (alongside existing EdgeX).
# Usage: ./scripts/deploy-pi.sh [user@host]
set -euo pipefail

TARGET="${1:-edgex@192.168.1.123}"
REMOTE_DIR="~/sensel-ot-edge-sensor"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"

echo "==> Syncing repo to ${TARGET}:${REMOTE_DIR}"
rsync -avz --delete \
  --exclude .git \
  --exclude data/ \
  --exclude '__pycache__' \
  --exclude '*.pyc' \
  --exclude .venv \
  --exclude node_modules \
  "${ROOT}/" "${TARGET}:${REMOTE_DIR}/"

echo "==> Creating lab .env and starting stack"
ssh "${TARGET}" bash -s <<'REMOTE'
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
SENSEL_API_URL=http://mock-sensel:8765
SENSEL_VERIFY_TLS=false
MGMT_INTERFACE=eth0
CAPTURE_INTERFACE=eth0
CAPTURE_BPF_FILTER=(ether proto 0x88b8) or (tcp port 102)
GOOSE_INTERFACE=eth0
LOCAL_MQTT_HOST=127.0.0.1
LOCAL_MQTT_PORT=1884
DEPLOY_TARGET=pi4
LOG_LEVEL=info
ENV

echo "==> Building and starting SenseL services (existing EdgeX untouched)"
docker compose -f docker-compose.edge-only.yml -f docker-compose.lab-61850.yml rm -sf 61850-sim-mms 2>/dev/null || true
docker compose -f docker-compose.edge-only.yml -f docker-compose.lab-61850.yml up -d --build

echo "==> Container status"
docker compose -f docker-compose.edge-only.yml -f docker-compose.lab-61850.yml ps

echo "==> Health check"
sleep 5
docker logs sensel-packet-sensor --tail 20 2>&1 || true
docker logs sensel-edge-agent --tail 10 2>&1 || true
REMOTE

echo "==> Deploy complete. SSH: ssh ${TARGET}"
