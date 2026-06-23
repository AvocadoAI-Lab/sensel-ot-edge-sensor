#!/usr/bin/env bash
# Deploy IT NDR stack (no EdgeX) to a lab Ubuntu sensor host.
#
# Usage:
#   export SSHPASS='avocado@@'
#   ./scripts/deploy-ndr-it.sh [user@host]
#
# Default target: sensel@192.168.1.198 (ndr-198 fleet sensor)
set -euo pipefail

TARGET="${1:-sensel@192.168.1.198}"
REMOTE_DIR="~/sensel-ot-edge-sensor"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"

COMPOSE_FILES="-f docker-compose.openwrt.yml -f docker-compose.ndr-it.yml -f docker-compose.suricata.yml"

SSH_CMD=(ssh -o StrictHostKeyChecking=accept-new)
if [[ -n "${SSHPASS:-}" ]] && command -v sshpass >/dev/null 2>&1; then
  export RSYNC_RSH="sshpass -e ssh -o StrictHostKeyChecking=no"
  SSH_CMD=(sshpass -e ssh -o StrictHostKeyChecking=accept-new)
fi

echo "==> Syncing repo to ${TARGET}:${REMOTE_DIR}"
if command -v rsync >/dev/null 2>&1 && "${SSH_CMD[@]}" "${TARGET}" "command -v rsync" >/dev/null 2>&1; then
  rsync -avz --delete --omit-dir-times \
    --exclude .git \
    --exclude data/ \
    --exclude '__pycache__' \
    --exclude '*.pyc' \
    --exclude .venv \
    --exclude node_modules \
    --exclude 'config/suricata' \
    --exclude '*.bak' \
    --exclude '/.env' \
    "${ROOT}/" "${TARGET}:${REMOTE_DIR}/"
else
  echo "    rsync unavailable — using tar over ssh"
  tar -C "${ROOT}" -czf - \
    --exclude .git \
    --exclude data \
    --exclude '__pycache__' \
    --exclude .venv \
    --exclude node_modules \
    --exclude 'config/suricata' \
    --exclude .env \
    . | "${SSH_CMD[@]}" "${TARGET}" "mkdir -p ${REMOTE_DIR} && tar -xzf - -C ${REMOTE_DIR}"
fi

echo "==> Pushing suricata.yaml (unix-command + app-layer; dir is root-owned on target)"
if [[ -f "${ROOT}/config/suricata/suricata.yaml" ]]; then
  if command -v sshpass >/dev/null 2>&1 && [[ -n "${SSHPASS:-}" ]]; then
    sshpass -e scp -o StrictHostKeyChecking=no \
      "${ROOT}/config/suricata/suricata.yaml" "${TARGET}:/tmp/suricata.yaml.from-repo"
  else
    scp -o StrictHostKeyChecking=no \
      "${ROOT}/config/suricata/suricata.yaml" "${TARGET}:/tmp/suricata.yaml.from-repo"
  fi
fi

echo "==> Remote: stop EdgeX stack, configure IT NDR, start Suricata NDR"
"${SSH_CMD[@]}" "${TARGET}" env \
  MQTT_TENANT_ID="${MQTT_TENANT_ID:-company-e2e}" \
  SENSEL_API_URL="${SENSEL_API_URL:-http://192.168.1.108:8081}" \
  CONTROL_PLANE_MQTT_HOST="${CONTROL_PLANE_MQTT_HOST:-192.168.1.203}" \
  CAPTURE_INTERFACE="${CAPTURE_INTERFACE:-eth0}" \
  SURICATA_INTERFACE="${SURICATA_INTERFACE:-eth0}" \
  SENSOR_ID="${SENSOR_ID:-ndr-198}" \
  OT_REGISTRATION_TOKEN="${OT_REGISTRATION_TOKEN:-}" \
  bash -s <<'REMOTE'
set -euo pipefail
cd ~/sensel-ot-edge-sensor
COMPOSE_FILES="-f docker-compose.openwrt.yml -f docker-compose.ndr-it.yml -f docker-compose.suricata.yml"
mkdir -p data/agent data/pcap data/assets data/suricata config/policy
chmod +x scripts/*.sh scripts/*.py 2>/dev/null || true

if [[ ! -f config/policy/baseline.json ]]; then
  cp config/policy/baseline.example.json config/policy/baseline.json
fi

# IT NDR: capture all traffic (no OT-only BPF). Override via CAPTURE_BPF_FILTER env.
IT_BPF="${CAPTURE_BPF_FILTER:-}"

if [[ ! -f data/agent/capture.env ]]; then
  cat > data/agent/capture.env <<CAP
CAPTURE_INTERFACE=${CAPTURE_INTERFACE:-eth0}
CAPTURE_BPF_FILTER=${IT_BPF}
MQTT_TENANT_ID=${MQTT_TENANT_ID:-company-e2e}
CAP
fi

if [[ ! -f .env ]]; then
  cp .env.openwrt.example .env
fi

patch_env() {
  local key="$1" val="$2"
  if grep -q "^${key}=" .env 2>/dev/null; then
    sed -i "s|^${key}=.*|${key}=${val}|" .env
  else
    echo "${key}=${val}" >> .env
  fi
}

patch_env SITE_ID "factory-lab-001"
patch_env SENSOR_ID "${SENSOR_ID:-ndr-198}"
patch_env SENSOR_TYPE "it-ndr-edge"
patch_env NDR_PROFILE "it_ndr"
patch_env IDS_RULE_FEED_PROFILE "it_ndr"
patch_env SENSEL_API_URL "${SENSEL_API_URL:-http://192.168.1.108:8081}"
patch_env SENSEL_VERIFY_TLS "false"
patch_env NORTHBOUND_MQTT_ENABLED "true"
patch_env CONTROL_PLANE_MQTT_HOST "${CONTROL_PLANE_MQTT_HOST:-192.168.1.203}"
patch_env CONTROL_PLANE_MQTT_PORT "1883"
patch_env MQTT_TENANT_ID "${MQTT_TENANT_ID:-company-e2e}"
patch_env CAPTURE_INTERFACE "${CAPTURE_INTERFACE:-eth0}"
patch_env SURICATA_INTERFACE "${SURICATA_INTERFACE:-eth0}"
patch_env CAPTURE_BPF_FILTER "${IT_BPF}"
patch_env DEPLOY_TARGET "ubuntu"
patch_env POLICY_SYNC_ENABLED "true"
patch_env IOC_MATCH_ENABLED "true"
patch_env SIGHTING_REPORT_ENABLED "true"
patch_env IDS_RULE_ENABLED "true"
patch_env IDS_RULE_MQTT_ENABLED "true"
patch_env SURICATA_SOURCE_ENABLED "true"
patch_env DATA_DIR "./data"
patch_env PCAP_MAX_DISK_MB "1024"
patch_env PCAP_RETENTION_MINUTES "60"
patch_env LOG_LEVEL "info"

if [[ -n "${OT_REGISTRATION_TOKEN:-}" ]]; then
  patch_env OT_REGISTRATION_TOKEN "${OT_REGISTRATION_TOKEN}"
fi

echo "==> Stopping full EdgeX stack (if running)"
docker compose -f docker-compose.yml -f docker-compose.minimal-edgex.yml down --remove-orphans 2>/dev/null || true
docker compose -f docker-compose.yml down --remove-orphans 2>/dev/null || true

echo "==> Waiting for port release"
sleep 3

# config/suricata is container-seeded (root-owned). Install repo suricata.yaml
# so unix-command (suricatasc reload) and app-layer parsers are present.
if [[ -f /tmp/suricata.yaml.from-repo ]]; then
  docker run --rm \
    -v "$PWD/config/suricata:/etc/suricata" \
    -v /tmp/suricata.yaml.from-repo:/src.yaml:ro \
    jasonish/suricata:latest cp /src.yaml /etc/suricata/suricata.yaml
fi

echo "==> Building and starting IT NDR stack (Suricata, no EdgeX)"
docker compose ${COMPOSE_FILES} up -d --build

if [[ -f /tmp/suricata.yaml.from-repo ]]; then
  docker compose ${COMPOSE_FILES} restart suricata
  sleep 3
fi

echo "==> Container status"
docker compose ${COMPOSE_FILES} ps

echo "==> Service logs (tail)"
sleep 5
docker logs sensel-edge-agent --tail 10 2>&1 || true
docker logs sensel-packet-sensor --tail 10 2>&1 || true
docker logs sensel-suricata --tail 8 2>&1 || true
docker logs sensel-edge-console --tail 5 2>&1 || true

HOST_IP=$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src") print $(i+1)}' | head -1)
HOST_IP=${HOST_IP:-192.168.1.198}
echo ""
echo "==> IT NDR URLs"
echo "  Edge Console: http://${HOST_IP}:8090"
echo "  Sensor ID:    ${SENSOR_ID:-ndr-198}"
REMOTE

echo "==> IT NDR deploy complete. SSH: ssh ${TARGET}"
