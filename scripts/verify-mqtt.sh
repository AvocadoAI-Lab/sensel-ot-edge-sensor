#!/usr/bin/env bash
# Verify Packet Sensor → local-mqtt → device-mqtt → core-data (S1-03)
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

METADATA_URL="${EDGEX_METADATA_URL:-http://127.0.0.1:59881}"
DATA_URL="${EDGEX_DATA_URL:-http://127.0.0.1:59880}"
DEVICE_NAME="${MQTT_FEATURE_DEVICE_NAME:-packet-sensor-features}"
TIMEOUT_SEC="${MQTT_VERIFY_TIMEOUT:-120}"
DATA_TOPIC="${EDGEX_FEATURE_DATA_TOPIC:-incoming/data/packet-sensor-features/FeatureSummary}"

log() { printf '==> %s\n' "$*"; }

if ! command -v curl >/dev/null 2>&1; then
  echo "curl is required" >&2
  exit 1
fi

if ! docker inspect -f '{{.State.Status}}' sensel-local-mqtt >/dev/null 2>&1; then
  echo "sensel-local-mqtt not running. Start stack: make up" >&2
  exit 1
fi

log "local-mqtt: $(docker inspect -f '{{.State.Status}}' sensel-local-mqtt)"
log "device-mqtt: $(docker inspect -f '{{.State.Status}}' edgex-device-mqtt 2>/dev/null || echo not found)"
log "packet-sensor: $(docker inspect -f '{{.State.Status}}' sensel-packet-sensor 2>/dev/null || echo not found)"

log "Checking device '${DEVICE_NAME}' in core-metadata..."
if ! curl -sf "${METADATA_URL}/api/v3/device/name/${DEVICE_NAME}" >/dev/null; then
  echo "Device '${DEVICE_NAME}' not found in core-metadata (${METADATA_URL})" >&2
  echo "Check: docker logs edgex-device-mqtt --tail 50" >&2
  exit 1
fi
log "Device registered in core-metadata"

log "Waiting up to ${TIMEOUT_SEC}s for FeatureSummary readings in core-data..."
deadline=$((SECONDS + TIMEOUT_SEC))
events_json=""
while (( SECONDS < deadline )); do
  if events_json="$(curl -sf "${DATA_URL}/api/v3/event/device/name/${DEVICE_NAME}?limit=5" 2>/dev/null)"; then
    if printf '%s' "$events_json" | grep -q '"totalCount":[1-9]'; then
      if printf '%s' "$events_json" | grep -q "PacketRate\|UniqueMacCount"; then
        break
      fi
    fi
  fi
  sleep 5
done

if [[ -z "$events_json" ]] || ! printf '%s' "$events_json" | grep -q '"totalCount":[1-9]'; then
  echo "No FeatureSummary events for '${DEVICE_NAME}' within ${TIMEOUT_SEC}s" >&2
  echo "Hints:" >&2
  echo "  - docker logs sensel-packet-sensor --tail 50 | grep -i edgex" >&2
  echo "  - docker logs edgex-device-mqtt --tail 50" >&2
  echo "  - mosquitto_sub -h 127.0.0.1 -p 1884 -t '${DATA_TOPIC}' -C 1 -W 5" >&2
  exit 1
fi

log "Telemetry OK — sample event payload:"
if command -v python3 >/dev/null 2>&1; then
  printf '%s' "$events_json" | python3 -m json.tool 2>/dev/null | head -50
else
  echo "$events_json" | head -c 2000
  echo
fi

log "MQTT → device-mqtt → Core Data verification passed"
