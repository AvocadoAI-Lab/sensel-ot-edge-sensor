#!/usr/bin/env bash
# Verify Modbus simulator → device-modbus → core-data telemetry path (S1-02)
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

METADATA_URL="${EDGEX_METADATA_URL:-http://127.0.0.1:59881}"
DATA_URL="${EDGEX_DATA_URL:-http://127.0.0.1:59880}"
DEVICE_NAME="${MODBUS_DEVICE_NAME:-relay-01}"
TIMEOUT_SEC="${MODBUS_VERIFY_TIMEOUT:-120}"

log() { printf '==> %s\n' "$*"; }

if ! command -v curl >/dev/null 2>&1; then
  echo "curl is required" >&2
  exit 1
fi

if ! docker inspect -f '{{.State.Status}}' edgex-modbus-simulator >/dev/null 2>&1; then
  echo "edgex-modbus-simulator container not running. Start stack: make up" >&2
  exit 1
fi

log "Modbus simulator container: $(docker inspect -f '{{.State.Status}}' edgex-modbus-simulator)"
log "device-modbus container: $(docker inspect -f '{{.State.Status}}' edgex-device-modbus 2>/dev/null || echo not found)"

log "Checking device '${DEVICE_NAME}' in core-metadata..."
if ! curl -sf "${METADATA_URL}/api/v3/device/name/${DEVICE_NAME}" >/dev/null; then
  echo "Device '${DEVICE_NAME}' not found in core-metadata (${METADATA_URL})" >&2
  echo "Check device-modbus logs: docker logs edgex-device-modbus" >&2
  exit 1
fi
log "Device registered in core-metadata"

log "Waiting up to ${TIMEOUT_SEC}s for readings in core-data..."
deadline=$((SECONDS + TIMEOUT_SEC))
events_json=""
while (( SECONDS < deadline )); do
  if events_json="$(curl -sf "${DATA_URL}/api/v3/event/device/name/${DEVICE_NAME}?limit=5" 2>/dev/null)"; then
    if [[ -n "$events_json" && "$events_json" != "[]" && "$events_json" != "null" ]]; then
      break
    fi
  fi
  sleep 5
done

if [[ -z "$events_json" || "$events_json" == "[]" || "$events_json" == "null" ]]; then
  echo "No events received for '${DEVICE_NAME}' within ${TIMEOUT_SEC}s" >&2
  echo "Hints:" >&2
  echo "  - docker logs edgex-device-modbus --tail 50" >&2
  echo "  - docker logs edgex-core-data --tail 50" >&2
  echo "  - confirm autoEvents in config/edgex/devices/modbus-relay.yaml" >&2
  exit 1
fi

log "Telemetry OK — sample event payload:"
if command -v python3 >/dev/null 2>&1; then
  printf '%s' "$events_json" | python3 -m json.tool 2>/dev/null | head -40
else
  echo "$events_json" | head -c 2000
  echo
fi

log "Modbus → Core Data verification passed"
