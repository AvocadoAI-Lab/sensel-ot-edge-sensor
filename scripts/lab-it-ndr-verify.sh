#!/usr/bin/env bash
# Lab: migrate CP, seed IT rules, redeploy edge ndr-198, smoke-check feed + suricata -T
set -euo pipefail

CP_HOST="${CP_HOST:-192.168.1.108}"
EDGE_HOST="${EDGE_HOST:-192.168.1.198}"
CP_USER="${CP_USER:-sensel}"
EDGE_USER="${EDGE_USER:-sensel}"
TENANT="${TENANT:-company-a9ae1234648ee138}"
WORKSPACE_ID="${WORKSPACE_ID:-1}"
SENSOR_ID="${SENSOR_ID:-ndr-198}"

run_cp() {
  ssh -o StrictHostKeyChecking=no "${CP_USER}@${CP_HOST}" "$@"
}

run_edge() {
  ssh -o StrictHostKeyChecking=no "${EDGE_USER}@${EDGE_HOST}" "$@"
}

echo "==> [108] alembic upgrade head"
run_cp 'cd ~/guacamole-ai/sensel_control_plane 2>/dev/null || cd ~/Aristaconnector-Control-Plane/sensel_control_plane 2>/dev/null || cd /opt/guacamole-ai/sensel_control_plane; docker compose exec -T sensel-control-plane alembic upgrade head'

echo "==> [108] seed IT NDR rules + patch sensor ${SENSOR_ID}"
run_cp "docker compose exec -T sensel-control-plane python3 /app/e2e/it-ndr/seed_it_rules.py --tenant ${TENANT} --workspace-id ${WORKSPACE_ID} --patch-sensors ${SENSOR_ID}"

echo "==> [198] redeploy IT NDR stack (agent only rebuild)"
run_edge 'cd ~/sensel-ot-edge-sensor && docker compose -f docker-compose.openwrt.yml -f docker-compose.ndr-it.yml -f docker-compose.suricata.yml up -d --build sensel-edge-agent edge-console'

echo "==> [198] wait agent cycle"
sleep 15

echo "==> [198] suricata syntax test"
run_edge 'docker exec sensel-suricata suricata -T -c /etc/suricata/suricata.yaml'

echo "==> [198] ids rule status"
run_edge 'cat ~/sensel-ot-edge-sensor/data/agent/ids-rule-status.json 2>/dev/null || echo "(no status yet)"'

echo "==> Done. Portal: NDR tab + 防護管理中心; Edge Console: http://${EDGE_HOST}:8090 policy page"
