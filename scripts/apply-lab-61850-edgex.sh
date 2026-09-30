#!/usr/bin/env bash
# Apply IEC 61850 lab EdgeX profile: mqtt-feature only; stop modbus + phase2.
#
# Local:
#   ./scripts/apply-lab-61850-edgex.sh
#
# Remote Pi:
#   SSHPASS=edgex ./scripts/apply-lab-61850-edgex.sh edgex@192.168.1.123
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TARGET="${1:-}"

COMPOSE_FILES="-f docker-compose.yml -f docker-compose.pi4.yml -f docker-compose.lab-61850.yml"
if [[ -f "$ROOT/docker-compose.pi-lab.yml" ]]; then
  COMPOSE_FILES="${COMPOSE_FILES} -f docker-compose.pi-lab.yml"
fi
# pi4.yml carries a suricata resource-limit override (no image), so the
# suricata overlay that defines the image must be included alongside it.
if [[ -f "$ROOT/docker-compose.suricata.yml" ]]; then
  COMPOSE_FILES="${COMPOSE_FILES} -f docker-compose.suricata.yml"
fi

run_remote() {
  local host="$1"
  SSH_CMD=(ssh -o StrictHostKeyChecking=no)
  if [[ -n "${SSHPASS:-}" ]] && command -v sshpass >/dev/null 2>&1; then
    SSH_CMD=(sshpass -e ssh -o StrictHostKeyChecking=no)
  fi
  "${SSH_CMD[@]}" "$host" env REMOTE_DIR="${REMOTE_DIR:-~/sensel-ot-edge-sensor}" bash -s <<'REMOTE'
set -euo pipefail
cd "${REMOTE_DIR}"
COMPOSE_FILES="-f docker-compose.yml -f docker-compose.pi4.yml -f docker-compose.lab-61850.yml"
[[ -f docker-compose.pi-lab.yml ]] && COMPOSE_FILES="${COMPOSE_FILES} -f docker-compose.pi-lab.yml"
# pi4.yml overrides the suricata service (no image) — pair it with the overlay.
[[ -f docker-compose.suricata.yml ]] && COMPOSE_FILES="${COMPOSE_FILES} -f docker-compose.suricata.yml"

META="http://127.0.0.1:59881"
for name in relay-01 s7-plc-01 opcua-demo-01; do
  code="$(curl -s -o /dev/null -w "%{http_code}" -X DELETE "${META}/api/v3/device/name/${name}" 2>/dev/null || echo 000)"
  echo "  metadata DELETE ${name} -> HTTP ${code}"
done

echo "==> Stop modbus + phase2 device services"
docker stop edgex-device-modbus edgex-device-opc-ua edgex-device-s7 edgex-modbus-simulator 2>/dev/null || true
docker rm -f edgex-device-modbus edgex-device-opc-ua edgex-device-s7 2>/dev/null || true

echo "==> Recreate device-mqtt with lab-61850 device dir"
docker compose ${COMPOSE_FILES} up -d --force-recreate device-mqtt

echo "==> Container status (EdgeX device services)"
docker ps -a --format "table {{.Names}}\t{{.Status}}" | grep -E "edgex-device|NAMES" || true

for i in $(seq 1 20); do
  st="$(docker inspect -f '{{.State.Status}}' edgex-device-mqtt 2>/dev/null || echo missing)"
  if [[ "$st" == "running" ]]; then
    echo "  edgex-device-mqtt running"
    break
  fi
  sleep 2
done

curl -sf "${META}/api/v3/device/all" | python3 -c "
import json, sys
raw = json.load(sys.stdin)
devs = raw.get('devices', raw) if isinstance(raw, dict) else raw
for d in devs if isinstance(devs, list) else []:
    print('  device', d.get('name'), '->', d.get('serviceName'))
" 2>/dev/null || echo "  (could not list devices)"
REMOTE
}

run_local() {
  cd "$ROOT"
  META="http://127.0.0.1:59881"
  for name in relay-01 s7-plc-01 opcua-demo-01; do
    code="$(curl -s -o /dev/null -w "%{http_code}" -X DELETE "${META}/api/v3/device/name/${name}" 2>/dev/null || echo 000)"
    echo "  metadata DELETE ${name} -> HTTP ${code}"
  done

  docker stop edgex-device-modbus edgex-device-opc-ua edgex-device-s7 edgex-modbus-simulator 2>/dev/null || true
  docker rm -f edgex-device-modbus edgex-device-opc-ua edgex-device-s7 2>/dev/null || true

  docker compose ${COMPOSE_FILES} up -d --force-recreate device-mqtt
  docker ps -a --format "table {{.Names}}\t{{.Status}}" | grep -E "edgex-device|NAMES" || true
}

echo "==> Apply lab-61850 EdgeX profile (mqtt-feature only)"
if [[ -n "$TARGET" ]]; then
  echo "    target=${TARGET}"
  run_remote "$TARGET"
else
  run_local
fi
echo "==> Done"
