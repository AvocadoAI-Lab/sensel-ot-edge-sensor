#!/usr/bin/env bash
# Repair baseline live learning lab: CP @ 108, MQTT/Layer A @ 203, Edge @ 124.
# Usage: SSHPASS='avocado@@' PI_SSHPASS='edgex' ./scripts/fix-baseline-mqtt-lab.sh
set -euo pipefail

CP_HOST="${CP_HOST:-192.168.1.108}"
CP_USER="${CP_USER:-ubuntu}"
CP_REPO="${CP_REPO:-/home/ubuntu/guacamole-ai}"
MQTT_HOST="${MQTT_HOST:-192.168.1.203}"
LAYERA_USER="${LAYERA_USER:-avocado.ai}"
AC_REPO="${AC_REPO:-/Users/avocado.ai/Aristaconnector-Control-Plane}"
PI_TARGET="${PI_TARGET:-edgex@192.168.1.124}"
INGEST_SECRET="${OT_SECURITY_INGEST_SECRET:-sensel-ot-ingest-lab-2026}"
SENSOR_ID="${BASELINE_SENSOR_ID:-ot-edge-001}"

if [[ -z "${SSHPASS:-}" ]]; then
  echo "Set SSHPASS (108/203: avocado@@, Pi: edgex via PI_SSHPASS)" >&2
  exit 1
fi

ssh_108() {
  sshpass -e ssh -o StrictHostKeyChecking=no "${CP_USER}@${CP_HOST}" "$@"
}

ssh_203() {
  sshpass -e ssh -o StrictHostKeyChecking=no "${LAYERA_USER}@${MQTT_HOST}" "$@"
}

ssh_pi() {
  local pi_pass="${PI_SSHPASS:-edgex}"
  SSHPASS="$pi_pass" sshpass -e ssh -o StrictHostKeyChecking=no "${PI_TARGET}" "$@"
}

echo "==> [203] Rollback mistaken CP stack (keep Layer A only)"
ssh_203 bash -s <<REMOTE
set -euo pipefail
export PATH="/usr/local/bin:\$PATH"
if [[ -d "/Users/avocado.ai/guacamole-ai" ]]; then
  cd "/Users/avocado.ai/guacamole-ai"
  docker compose stop api postgres redis 2>/dev/null || true
  docker compose rm -f api postgres redis 2>/dev/null || true
  echo "203 guacamole CP stopped"
fi
pkill -f run_baseline_observe_ingest.py 2>/dev/null || true
REMOTE

echo "==> [203] Ensure Layer A (EMQX + Redpanda + mqtt-bridge)"
ssh_203 bash -s <<REMOTE
set -euo pipefail
export PATH="/usr/local/bin:\$PATH"
LAYERA="${AC_REPO}/sensel-dataplane/deployments/layerA"
docker network create controlplane_net 2>/dev/null || true
docker network create sensel-dataplane 2>/dev/null || true
cd "\$LAYERA"
cat > docker-compose.override.yml <<'YAML'
services:
  redpanda:
    command: redpanda start --smp 1 --memory 1G --reserve-memory 0M --overprovisioned --node-id 0 --kafka-addr internal://0.0.0.0:9092,external://0.0.0.0:19092 --advertise-kafka-addr internal://redpanda:9092,external://192.168.1.203:19092 --pandaproxy-addr internal://0.0.0.0:8082,external://0.0.0.0:18082 --advertise-pandaproxy-addr internal://redpanda:8082,external://192.168.1.203:18082 --rpc-addr redpanda:33145 --advertise-rpc-addr redpanda:33145
YAML
docker compose up -d emqx redpanda redpanda-init mqtt-bridge
sleep 10
nc -zv 127.0.0.1 1883
nc -zv 127.0.0.1 19092
REMOTE

echo "==> [108] Enable MQTT broker ${MQTT_HOST} on Control Plane"
ssh_108 bash -s <<REMOTE
set -euo pipefail
export PATH="/usr/local/bin:\$PATH"
ENV_FILE="${CP_REPO}/sensel_control_plane/.env"
touch "\$ENV_FILE"
upsert() {
  local k="\$1" v="\$2"
  if grep -q "^\${k}=" "\$ENV_FILE" 2>/dev/null; then
    sed -i.bak "s|^\${k}=.*|\${k}=\${v}|" "\$ENV_FILE"
  else
    echo "\${k}=\${v}" >> "\$ENV_FILE"
  fi
}
upsert MQTT_ENABLED true
upsert MQTT_BROKER ${MQTT_HOST}
upsert MQTT_PORT 1883
upsert OT_SECURITY_INGEST_SECRET ${INGEST_SECRET}
upsert OT_EDGE_SENSOR_API_KEY ${INGEST_SECRET}
upsert PUBLIC_BASE_URL http://${CP_HOST}:8081
upsert SMB_ENABLED true
grep -q '^SMB_JWT_SECRET=' "\$ENV_FILE" || upsert SMB_JWT_SECRET local-docker-smb-jwt-change-me
grep -E '^MQTT_|^OT_SECURITY|^PUBLIC_BASE' "\$ENV_FILE"
cd "${CP_REPO}"
docker compose up -d api
sleep 8
docker compose exec -T api bash -c 'cd sensel_control_plane && alembic upgrade head' || true
curl -sf "http://127.0.0.1:8081/api/health" && echo " API OK"
docker compose exec -T api python3 -c "
from sensel_control_plane.core.config import get_settings
s=get_settings()
print('mqtt', s.mqtt_enabled, s.mqtt_broker, s.mqtt_port)
"
REMOTE

echo "==> [108] Discard active baseline sessions for ${SENSOR_ID}"
ssh_108 bash -s <<REMOTE
set -euo pipefail
export PATH="/usr/local/bin:\$PATH"
cd "${CP_REPO}"
docker compose exec -T postgres psql -U sensel -d sensel -c "
UPDATE smb_ot_baseline_operational_sessions
SET status = 'discarded', updated_at = NOW()::text
WHERE sensor_id = '${SENSOR_ID}'
  AND status IN ('starting', 'active', 'stalled', 'pending', 'stopping');
" 2>/dev/null || echo "WARN: session cleanup skipped"
REMOTE

echo "==> [124] Rollback Edge API to ${CP_HOST}, MQTT to ${MQTT_HOST}"
ssh_pi bash -s <<REMOTE
set -euo pipefail
cd ~/sensel-ot-edge-sensor
touch .env
upsert() {
  local k="\$1" v="\$2"
  if grep -q "^\${k}=" .env 2>/dev/null; then
    sed -i "s|^\${k}=.*|\${k}=\${v}|" .env
  else
    echo "\${k}=\${v}" >> .env
  fi
}
upsert SENSEL_API_URL http://${CP_HOST}:8081
upsert CONTROL_PLANE_MQTT_HOST ${MQTT_HOST}
upsert POLICY_SYNC_MQTT_HOST ${MQTT_HOST}
upsert POLICY_SYNC_MQTT_ENABLED true
upsert OPERATIONAL_MODE_MQTT_ENABLED true
upsert BASELINE_PROFILE_MQTT_ENABLED true
upsert OBSERVE_TICK_ENABLED true
upsert NORTHBOUND_MQTT_ENABLED true
grep -E 'SENSEL_API_URL|MQTT_HOST|OPERATIONAL|OBSERVE_TICK|POLICY_SYNC' .env | head -12
export PATH="/usr/local/bin:\$PATH"
COMPOSE="docker compose -f docker-compose.yml -f docker-compose.pi4.yml -f docker-compose.lab-61850.yml -f docker-compose.pi-reliability.yml -f docker-compose.pi-lab.yml"
\$COMPOSE up -d --force-recreate sensel-edge-agent packet-sensor 2>/dev/null || \$COMPOSE up -d
docker exec -u root sensel-edge-agent python3 -c "
import json
from pathlib import Path
p = Path('/app/data/platform.json')
if p.exists():
    d = json.loads(p.read_text())
    d['sensel_api_url'] = 'http://${CP_HOST}:8081'
    p.write_text(json.dumps(d, indent=2) + '\n')
    print('platform.json ->', d['sensel_api_url'])
" 2>/dev/null || true
\$COMPOSE restart sensel-edge-agent 2>/dev/null || true
sleep 8
\$COMPOSE logs sensel-edge-agent --tail 6 | grep -E "${CP_HOST}|${MQTT_HOST}|operational|health" || \$COMPOSE logs sensel-edge-agent --tail 4
REMOTE

echo "==> [203] Start baseline observe ingest -> CP ${CP_HOST}"
ssh_203 bash -s <<REMOTE
set -euo pipefail
pkill -f run_baseline_observe_ingest.py 2>/dev/null || true
mkdir -p "${AC_REPO}/logs"
nohup env \
  PYTHONPATH="${AC_REPO}" \
  CONTROL_PLANE_BASE_URL=http://${CP_HOST}:8081 \
  OT_SECURITY_INGEST_SECRET=${INGEST_SECRET} \
  BASELINE_OBSERVE_KAFKA_BOOTSTRAP=127.0.0.1:19092 \
  python3 "${AC_REPO}/scripts/run_baseline_observe_ingest.py" \
  >> "${AC_REPO}/logs/baseline_observe_ingest.log" 2>&1 &
sleep 3
pgrep -fl run_baseline_observe_ingest || echo "WARN: ingest process not found"
tail -4 "${AC_REPO}/logs/baseline_observe_ingest.log" 2>/dev/null || true
REMOTE

echo ""
echo "Done. Portal: http://${CP_HOST}:8081/dashboard/smb-portal"
echo "MQTT broker: mqtt://${MQTT_HOST}:1883"
echo "Edge Console: http://192.168.1.124:8090"
echo "Next: Portal (108) -> discard old session -> 開始學習 (eth0) -> wait 60s for tick"
