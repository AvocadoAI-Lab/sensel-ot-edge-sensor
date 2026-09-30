#!/usr/bin/env bash
# Start native sensel-edge-agent on Pi 4 (MQTT northbound to PC Control Plane)
set -euo pipefail

ROOT="/home/fju/sensel-ot-edge-sensor"
AGENT_DIR="${ROOT}/services/sensel-edge-agent"
LOG="/tmp/sensel-edge-agent.log"
PC_MQTT_HOST="${CONTROL_PLANE_MQTT_HOST:-192.168.50.134}"
PC_MQTT_PORT="${CONTROL_PLANE_MQTT_PORT:-1883}"

mkdir -p "${ROOT}/data/assets" "${ROOT}/data/agent"

# Docker paths (/app/...) -> native Pi tree
if [[ ! -L /app ]] || [[ "$(readlink -f /app 2>/dev/null)" != "${ROOT}" ]]; then
  echo "==> Link /app -> ${ROOT} (edge-agent docker path compat)"
  echo "${PW:-0000}" | sudo -S ln -sfn "${ROOT}" /app
fi

pkill -f 'sensel-edge-agent.*src.main' 2>/dev/null || true
pkill -f "${AGENT_DIR}/.venv/bin/python -m src.main" 2>/dev/null || true
sleep 1

if [[ ! -d "${AGENT_DIR}/.venv" ]]; then
  echo "==> Creating edge-agent venv"
  python3 -m venv "${AGENT_DIR}/.venv"
fi
echo "==> Installing edge-agent dependencies"
"${AGENT_DIR}/.venv/bin/pip" install -q -r "${AGENT_DIR}/requirements.txt"

echo "==> Starting sensel-edge-agent (MQTT -> ${PC_MQTT_HOST}:${PC_MQTT_PORT})"
cd "${AGENT_DIR}"
source .venv/bin/activate
export SENSOR_CONFIG_PATH="${ROOT}/config/sensor.pi-edge-agent.yaml"
export PYTHONPATH="${AGENT_DIR}"
export SITE_ID=factory-lab-pi
export SENSOR_ID=ot-edge-pi4
export MQTT_TENANT_ID=default
export MQTT_REQUIRE_TENANT=false
export NORTHBOUND_MQTT_ENABLED=true
export CONTROL_PLANE_MQTT_HOST="${PC_MQTT_HOST}"
export CONTROL_PLANE_MQTT_PORT="${PC_MQTT_PORT}"
export POLICY_SYNC_MQTT_HOST="${PC_MQTT_HOST}"
export POLICY_SYNC_MQTT_PORT="${PC_MQTT_PORT}"
export POLICY_SYNC_MQTT_ENABLED=true
export BASELINE_PROFILE_MQTT_ENABLED=true
export OPERATIONAL_MODE_MQTT_ENABLED=true
export OPERATIONAL_MODE_PATH="${ROOT}/data/agent/operational-mode.json"
export OPERATIONAL_MODE_STAMP_PATH="${ROOT}/data/agent/operational-mode.stamp"
export LEARNING_SESSION_PATH="${ROOT}/data/agent/learning-session.json"
export LIVE_OBSERVED_PATH="${ROOT}/data/assets/baseline/live-observed.json"
export SENSEL_VERIFY_TLS=false
export EDGEX_DEVICE_MANAGEMENT_ENABLED=false
export BASELINE_PROFILE_PATH="${ROOT}/data/agent/baseline-profile.json"
export BASELINE_PROFILE_STAMP_PATH="${ROOT}/data/agent/baseline-profile.stamp"
export DETECTION_POLICY_MQTT_ENABLED=false
export TOPOLOGY_OVERRIDE_MQTT_ENABLED=false
export SENSEL_API_URL=http://192.168.50.134:8088
export SENSEL_API_KEY=pi-lab-mqtt-only
export OT_REGISTRATION_TOKEN=
export AGENT_RUNTIME_PATH="${ROOT}/data/agent/agent-runtime.json"
export MQTT_CREDENTIALS_PATH="${ROOT}/data/agent/mqtt-credentials.json"
export NORTHBOUND_WIRE_STATE_PATH="${ROOT}/data/agent/northbound-wire-state.json"
export SURICATA_SOURCE_ENABLED="${SURICATA_SOURCE_ENABLED:-true}"
export SURICATA_RULES_PATH="${SURICATA_RULES_PATH:-${ROOT}/config/suricata/rules/local.rules}"
export SURICATA_RULE_VERSION="${SURICATA_RULE_VERSION:-pi-lab-v0.1}"

nohup python -m src.main >"${LOG}" 2>&1 &
echo $! > /tmp/sensel-edge-agent.pid
sleep 5

if pgrep -f "sensel-edge-agent.*src.main" >/dev/null || pgrep -f "python -m src.main" >/dev/null; then
  echo "edge-agent running pid=$(cat /tmp/sensel-edge-agent.pid 2>/dev/null || pgrep -f 'src.main' | head -1)"
else
  echo "edge-agent failed; tail ${LOG}" >&2
  tail -n 40 "${LOG}" >&2 || true
  exit 1
fi

tail -n 20 "${LOG}" || true
