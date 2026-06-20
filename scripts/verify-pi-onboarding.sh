#!/usr/bin/env bash
# Verify Pi Edge Console onboarding against SenseL Portal.
#
# Required env:
#   EDGE_CONSOLE_URL   e.g. http://192.168.1.123:8090
#   INVITE_CODE        enterprise invite from Portal (成員 → 產生邀請碼)
#   SENSEL_API_KEY     M2M ingest key
#
# Optional (Portal user session — M2M key cannot call SMB routes):
#   PORTAL_BEARER_TOKEN  SMB login JWT
#   WORKSPACE_ID         default 6
#   SENSOR_ID          default ot-edge-verify-001
#   SITE_ID            default factory-lab-001
#   MQTT_HOST          default 192.168.1.203
set -euo pipefail

EDGE_CONSOLE_URL="${EDGE_CONSOLE_URL:?EDGE_CONSOLE_URL required}"
INVITE_CODE="${INVITE_CODE:?INVITE_CODE required}"
SENSEL_API_KEY="${SENSEL_API_KEY:?SENSEL_API_KEY required}"
SENSEL_API_URL="${SENSEL_API_URL:-http://192.168.1.108:8081}"
WORKSPACE_ID="${WORKSPACE_ID:-6}"
SENSOR_ID="${SENSOR_ID:-ot-edge-verify-001}"
SITE_ID="${SITE_ID:-factory-lab-001}"
MQTT_HOST="${MQTT_HOST:-192.168.1.203}"

BASE="${EDGE_CONSOLE_URL%/}"

echo "==> Configure Edge Console"
curl -sf -X PUT "${BASE}/api/config" \
  -H "Content-Type: application/json" \
  -d "$(cat <<JSON
{
  "sensor_id": "${SENSOR_ID}",
  "site_id": "${SITE_ID}",
  "sensel_api_url": "${SENSEL_API_URL}",
  "sensel_api_key": "${SENSEL_API_KEY}",
  "registration_token": "${INVITE_CODE}",
  "mqtt_host": "${MQTT_HOST}",
  "mqtt_port": 1883,
  "sensel_verify_tls": false
}
JSON
)" >/dev/null

echo "==> Register sensor"
REGISTER_JSON=$(curl -sf -X POST "${BASE}/api/register/test" \
  -H "Content-Type: application/json" \
  -d '{"save_first": true}')
echo "${REGISTER_JSON}"

TENANT_ID=$(python3 - <<'PY' "${REGISTER_JSON}"
import json, sys
data = json.loads(sys.argv[1])
if not data.get("ok"):
    raise SystemExit("register failed")
tid = data.get("tenant_id") or ""
if not tid or tid == "default":
    raise SystemExit(f"unexpected tenant_id: {tid!r}")
print(tid)
PY
)

echo "==> Verify Portal sensor list (workspace ${WORKSPACE_ID})"
if [[ -n "${PORTAL_BEARER_TOKEN:-}" ]]; then
  SENSORS=$(curl -sf "${SENSEL_API_URL}/api/v1/smb/workspaces/${WORKSPACE_ID}/ot-security/sensors" \
    -H "Authorization: Bearer ${PORTAL_BEARER_TOKEN}" \
    -H "X-Workspace-Id: ${WORKSPACE_ID}")

  python3 - <<'PY' "${SENSORS}" "${SENSOR_ID}" "${TENANT_ID}"
import json, sys
payload = json.loads(sys.argv[1])
sensor_id = sys.argv[2]
tenant_id = sys.argv[3]
items = payload.get("items") or []
match = next((s for s in items if s.get("sensor_id") == sensor_id), None)
if match is None:
    raise SystemExit(f"sensor {sensor_id} not found in portal list")
if match.get("tenant_id") != tenant_id:
    raise SystemExit(f"tenant mismatch portal={match.get('tenant_id')} register={tenant_id}")
print(f"OK sensor={sensor_id} tenant={tenant_id}")
PY
else
  echo "  (skip — set PORTAL_BEARER_TOKEN to verify Portal sensor list)"
fi

echo "==> Edge Console status"
curl -sf "${BASE}/api/status" | python3 -m json.tool

echo "==> Onboarding E2E passed"
