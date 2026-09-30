#!/usr/bin/env bash
# Start Suricata sidecar on Pi 4 (Docker) for native packet-sensor bridge.
set -euo pipefail

ROOT="/home/fju/sensel-ot-edge-sensor"
SURICATA_INTERFACE="${SURICATA_INTERFACE:-eth0}"
IMAGE="jasonish/suricata:latest"
CONTAINER="sensel-suricata"

mkdir -p "${ROOT}/config/suricata/rules" "${ROOT}/data/suricata"

if ! command -v docker >/dev/null 2>&1; then
  echo "docker not installed; run: curl -fsSL https://get.docker.com | sh" >&2
  exit 1
fi

if [[ ! -f "${ROOT}/config/suricata/suricata.yaml" ]]; then
  echo "missing ${ROOT}/config/suricata/suricata.yaml" >&2
  exit 1
fi

if sudo docker ps -a --format '{{.Names}}' | grep -qx "${CONTAINER}"; then
  sudo docker rm -f "${CONTAINER}" >/dev/null 2>&1 || true
fi

echo "==> Pulling ${IMAGE}"
sudo docker pull "${IMAGE}"

echo "==> Starting ${CONTAINER} on ${SURICATA_INTERFACE}"
sudo docker run -d \
  --name "${CONTAINER}" \
  --restart unless-stopped \
  --network host \
  --cap-add NET_ADMIN \
  --cap-add NET_RAW \
  --cap-add SYS_NICE \
  -v "${ROOT}/config/suricata:/etc/suricata" \
  -v "${ROOT}/data/suricata:/var/log/suricata" \
  "${IMAGE}" \
  -c /etc/suricata/suricata.yaml \
  -i "${SURICATA_INTERFACE}"

for i in $(seq 1 30); do
  if sudo docker logs "${CONTAINER}" 2>&1 | grep -qE "Engine started|rules successfully loaded"; then
    echo "Suricata engine started"
    break
  fi
  sleep 2
  if [[ "${i}" -eq 30 ]]; then
    echo "Suricata slow start; check: sudo docker logs ${CONTAINER}" >&2
  fi
done

sudo docker ps --filter "name=${CONTAINER}" --format 'table {{.Names}}\t{{.Status}}'
sudo docker stats --no-stream "${CONTAINER}" || true
