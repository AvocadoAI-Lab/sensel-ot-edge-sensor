#!/usr/bin/env bash
# MQTT credential auto-land E2E (v0.2 Control Plane):
# register response (mqtt_username/password/host/port) → edge applies to live
# config + northbound client → persists 0600 secret → reload picks it up.
#
# Self-contained: no running stack required. Exercises the edge-agent
# registration + config reload path against a sample Control Plane response.
#
# Examples:
#   ./scripts/verify-mqtt-provisioning-e2e.sh
#   ./scripts/verify-mqtt-provisioning-e2e.sh --json
#
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

exec python3 "$ROOT/scripts/verify_mqtt_provisioning_e2e.py" "$@"
