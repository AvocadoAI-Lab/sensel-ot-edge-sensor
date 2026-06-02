#!/usr/bin/env bash
# Publish blacklist artifact to MQTT for Track B-S5 lab verification.
#
# Fetches current feed from 108 (or uses inline JSON) and publishes to EMQX topic
# sensel/{tenant}/policy/blacklist so edge-agent PolicyMqttSubscriber updates ioc-cache.
#
# Usage:
#   export SMB_INTEL_API_KEY='...'
#   ./scripts/publish-track-b-lab-blacklist-mqtt.sh
#   TRACK_B_TEST_IOC_IP=203.0.113.88 ./scripts/publish-track-b-lab-blacklist-mqtt.sh --bump
#
set -euo pipefail

SENSEL_HOST="${SENSEL_HOST:-192.168.1.108}"
MQTT_HOST="${POLICY_SYNC_MQTT_HOST:-${CONTROL_PLANE_MQTT_HOST:-192.168.1.203}}"
MQTT_PORT="${POLICY_SYNC_MQTT_PORT:-${CONTROL_PLANE_MQTT_PORT:-1883}}"
TENANT="${POLICY_SYNC_TENANT_ID:-sensel-platform}"
TOPIC="${POLICY_SYNC_MQTT_TOPIC:-sensel/${TENANT}/policy/blacklist}"
API_KEY="${SMB_INTEL_API_KEY:-}"
TEST_IP="${TRACK_B_TEST_IOC_IP:-203.0.113.99}"
BUMP=0

for arg in "$@"; do
  case "$arg" in
    --bump) BUMP=1 ;;
  esac
done

if ! command -v mosquitto_pub >/dev/null 2>&1; then
  echo "mosquitto_pub required (brew install mosquitto)" >&2
  exit 1
fi

payload=""
if [[ -n "$API_KEY" ]]; then
  payload="$(curl -sf -H "X-API-Key: ${API_KEY}" \
    "http://${SENSEL_HOST}:8081/api/v1/feed/${TENANT}/blacklist.json")"
fi

if [[ -z "$payload" ]]; then
  echo "Could not fetch feed; using minimal inline artifact" >&2
  payload="$(python3 - <<PY
import json, time
print(json.dumps({
  "tenant_id": "${TENANT}",
  "version": time.strftime("mqtt-lab-%Y%m%d-%H%M%S"),
  "ttl_default_seconds": 86400,
  "manifest": {"sha256": "lab-mqtt-manual"},
  "items": [{
    "item_id": "lab-mqtt-item",
    "ioc_type": "ipv4",
    "value": "${TEST_IP}",
    "confidence": 90,
    "revoke": False,
  }],
}))
PY
)"
elif [[ "$BUMP" == "1" ]]; then
  payload="$(python3 - <<PY
import json, sys, time
d=json.loads(sys.stdin.read())
d["version"]=time.strftime("mqtt-lab-%Y%m%d-%H%M%S")
d.setdefault("manifest", {})["sha256"]=f"mqtt-{int(time.time())}"
items=d.get("items") or []
if not any(str(i.get("value"))=="${TEST_IP}" for i in items if isinstance(i, dict)):
    items.append({"item_id":"lab-mqtt-bump","ioc_type":"ipv4","value":"${TEST_IP}","confidence":90,"revoke":False})
d["items"]=items
print(json.dumps(d))
PY
<<<"$payload")"
fi

echo "==> Publishing to mqtt://${MQTT_HOST}:${MQTT_PORT}/${TOPIC}"
mosquitto_pub -h "$MQTT_HOST" -p "$MQTT_PORT" -t "$TOPIC" -q 1 -m "$payload"
echo "==> Published $(echo "$payload" | python3 -c 'import json,sys; d=json.load(sys.stdin); print(d.get("version"), "items", len(d.get("items",[])))')"
