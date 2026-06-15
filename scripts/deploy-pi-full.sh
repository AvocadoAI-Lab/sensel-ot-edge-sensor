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

COMPOSE_FILES="-f docker-compose.yml -f docker-compose.pi4.yml -f docker-compose.lab-61850.yml -f docker-compose.pi-reliability.yml"
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
  MDNS_NAME="${MDNS_NAME:-sensel}" \
  CONSOLE_PORT="${CONSOLE_PORT:-8090}" \
  CONSOLE_HTTPS_PORT="${CONSOLE_HTTPS_PORT:-8443}" \
  CONSOLE_TLS_HOSTS="${CONSOLE_TLS_HOSTS:-${MDNS_NAME:-sensel}.local,localhost,127.0.0.1}" \
  SUDO_PASS="${SUDO_PASS:-${SSHPASS:-}}" \
  bash -s <<'REMOTE'
set -euo pipefail
cd ~/sensel-ot-edge-sensor
COMPOSE_FILES="-f docker-compose.yml -f docker-compose.pi4.yml -f docker-compose.lab-61850.yml -f docker-compose.pi-reliability.yml"
if [[ "${DEPLOY_PROFILE}" == "production" ]]; then
  COMPOSE_FILES="${COMPOSE_FILES} -f docker-compose.pi-production.yml"
else
  COMPOSE_FILES="${COMPOSE_FILES} -f docker-compose.pi-lab.yml"
fi
mkdir -p data/agent data/pcap data/assets config/policy
chmod +x scripts/*.sh scripts/*.py 2>/dev/null || true

if [[ ! -f config/policy/baseline.json ]]; then
  cp config/policy/baseline.example.json config/policy/baseline.json
fi

LAB_CAPTURE_BPF='(ether proto 0x88b8) or (tcp port 102) or (udp port 53) or (tcp port 389)'
LAB_MQTT_FLAGS=(
  OPERATIONAL_MODE_MQTT_ENABLED=true
  BASELINE_PROFILE_MQTT_ENABLED=true
  TOPOLOGY_OVERRIDE_MQTT_ENABLED=true
  TOPOLOGY_SNAPSHOT_DETECT_INTERVAL_SEC=60
)
mkdir -p data/agent
if [[ "${DEPLOY_PROFILE}" == "lab" ]]; then
  if [[ -f data/agent/capture.env ]] && grep -q '^CAPTURE_BPF_FILTER=' data/agent/capture.env; then
    sed -i "s|^CAPTURE_BPF_FILTER=.*|CAPTURE_BPF_FILTER=${LAB_CAPTURE_BPF}|" data/agent/capture.env
  elif [[ ! -f data/agent/capture.env ]]; then
    cat > data/agent/capture.env <<CAP
CAPTURE_INTERFACE=eth0
CAPTURE_BPF_FILTER=${LAB_CAPTURE_BPF}
MQTT_TENANT_ID=${MQTT_TENANT_ID:-default}
CAP
  fi
elif [[ ! -f data/agent/capture.env ]]; then
  cat > data/agent/capture.env <<CAP
CAPTURE_INTERFACE=eth0
CAPTURE_BPF_FILTER=(ether proto 0x88b8) or (tcp port 102)
MQTT_TENANT_ID=${MQTT_TENANT_ID:-default}
CAP
fi

./scripts/seed-pi-env.sh
if [[ "${DEPLOY_PROFILE}" == "lab" ]] && [[ -f .env ]]; then
  for kv in "${LAB_MQTT_FLAGS[@]}"; do
    key="${kv%%=*}"
    if grep -q "^${key}=" .env; then
      sed -i "s|^${key}=.*|${kv}|" .env
    else
      echo "${kv}" >> .env
    fi
  done
fi
if [[ -n "${OT_REGISTRATION_TOKEN:-}" ]] && ! grep -q '^OT_REGISTRATION_TOKEN=.' .env 2>/dev/null; then
  echo "OT_REGISTRATION_TOKEN=${OT_REGISTRATION_TOKEN}" >> .env
fi
if [[ "${DEPLOY_PROFILE}" == "production" ]] && ! grep -q '^MQTT_REQUIRE_TENANT=' .env 2>/dev/null; then
  echo "MQTT_REQUIRE_TENANT=true" >> .env
fi
if ! grep -q '^MQTT_TENANT_ID=' .env 2>/dev/null; then
  echo "MQTT_TENANT_ID=${MQTT_TENANT_ID:-default}" >> .env
fi

./scripts/wait-for-upstream.sh

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
# Lab 61850: mqtt-feature only — no phase2 (opc-ua/s7) or modbus-lab unless explicitly enabled
docker compose ${COMPOSE_FILES} up -d --build

echo "==> Publishing mDNS name (${MDNS_NAME:-sensel}.local) for the Edge Console"
chmod +x deploy/avahi/setup-mdns.sh 2>/dev/null || true
if [[ -f deploy/avahi/setup-mdns.sh ]]; then
  if sudo -n true 2>/dev/null; then
    sudo env MDNS_NAME="${MDNS_NAME:-sensel}" CONSOLE_PORT="${CONSOLE_PORT:-8090}" CONSOLE_HTTPS_PORT="${CONSOLE_HTTPS_PORT:-8443}" \
      bash deploy/avahi/setup-mdns.sh || echo "  mDNS setup failed (non-fatal)"
  elif [[ -n "${SUDO_PASS:-}" ]]; then
    echo "${SUDO_PASS}" | sudo -S env MDNS_NAME="${MDNS_NAME:-sensel}" CONSOLE_PORT="${CONSOLE_PORT:-8090}" CONSOLE_HTTPS_PORT="${CONSOLE_HTTPS_PORT:-8443}" \
      bash deploy/avahi/setup-mdns.sh || echo "  mDNS setup failed (non-fatal)"
  else
    echo "  Skipping mDNS: no sudo. Run manually: sudo MDNS_NAME=${MDNS_NAME:-sensel} ./deploy/avahi/setup-mdns.sh"
  fi
fi

echo "==> Installing offline Wi-Fi failover watchdog (systemd timer)"
chmod +x deploy/netwatch/setup-failover.sh deploy/netwatch/net-failover.sh 2>/dev/null || true
if [[ -f deploy/netwatch/setup-failover.sh ]]; then
  WPF="${HOME}/sensel-ot-edge-sensor/data/agent/wifi-priority.json"
  if sudo -n true 2>/dev/null; then
    sudo env WIFI_PRIORITY_FILE="${WPF}" bash deploy/netwatch/setup-failover.sh || echo "  failover setup failed (non-fatal)"
  elif [[ -n "${SUDO_PASS:-}" ]]; then
    echo "${SUDO_PASS}" | sudo -S env WIFI_PRIORITY_FILE="${WPF}" bash deploy/netwatch/setup-failover.sh || echo "  failover setup failed (non-fatal)"
  else
    echo "  Skipping failover: no sudo. Run manually: sudo WIFI_PRIORITY_FILE=${WPF} ./deploy/netwatch/setup-failover.sh"
  fi
fi

echo "==> Lab URLs"
PI_IP=$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src") print $(i+1)}' | head -1)
PI_IP=${PI_IP:-192.168.1.123}
echo "  Edge Console:  http://${PI_IP}:8090  ← 設定企業邀請碼 / 註冊"
echo "  By name:       https://${MDNS_NAME:-sensel}.local:${CONSOLE_HTTPS_PORT:-8443}  (mDNS + 本地 CA 簽發)"
echo "                 http://${MDNS_NAME:-sensel}.local:${CONSOLE_PORT:-8090}   (HTTP)"
echo "  綠鎖零警告：每台用戶端安裝一次本地 CA 根憑證："
echo "                 curl -fsSL http://${MDNS_NAME:-sensel}.local:${CONSOLE_PORT:-8090}/sensel-root-ca.crt -o sensel-root-ca.crt"
echo "                 macOS: sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain sensel-root-ca.crt"
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
chmod +x scripts/apply-lab-61850-edgex.sh 2>/dev/null || true
./scripts/apply-lab-61850-edgex.sh
docker logs edgex-device-mqtt --tail 8 2>&1 || true

echo "==> Pi stack health gate"
./scripts/verify-pi-stack-health.sh ${COMPOSE_FILES} || true
REMOTE

echo "==> Full stack deploy complete (${PROFILE}). SSH: ssh ${TARGET}"
echo "    Verify onboarding: EDGE_CONSOLE_URL=http://<pi>:8090 INVITE_CODE=... SENSEL_API_KEY=... ./scripts/verify-pi-onboarding.sh"
