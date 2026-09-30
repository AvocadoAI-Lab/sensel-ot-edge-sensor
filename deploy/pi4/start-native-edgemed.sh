#!/usr/bin/env bash
# Start llama-server + EdgeMed + native packet-sensor (EdgeMed HTTP bridge) on Pi 4
set -euo pipefail

ROOT="/home/fju/sensel-ot-edge-sensor"
EDGEMED="${ROOT}/services/edgemed"
PS_DIR="${ROOT}/services/packet-sensor"
LLAMA_DIR="/home/fju/edgemed-slm/llama-b10276"
LLAMA_MODEL="/home/fju/edgemed-slm/models/SmolLM2-360M-Instruct-Q4_K_M.gguf"
LOG_LLAMA="/tmp/llama-server.log"
LOG_ED="/tmp/edgemed-uvicorn.log"
LOG_PS="/tmp/packet-sensor.log"

mkdir -p "${ROOT}/data/assets" "${ROOT}/data/agent" "${ROOT}/data/pcap"

if [[ ! -f "${ROOT}/config/policy/baseline.json" ]]; then
  cp "${ROOT}/config/policy/baseline.example.json" "${ROOT}/config/policy/baseline.json"
fi

pkill -f 'uvicorn app.main:app' 2>/dev/null || true
pkill -f 'llama-server' 2>/dev/null || true
pkill -f 'python -m src.main' 2>/dev/null || true
sudo pkill -f 'python -m src.main' 2>/dev/null || true
sleep 1

if [[ -x "${LLAMA_DIR}/llama-server" && -f "${LLAMA_MODEL}" ]]; then
  echo "==> Starting llama-server on :8081"
  export LD_LIBRARY_PATH="${LLAMA_DIR}:${LD_LIBRARY_PATH:-}"
  cd "${LLAMA_DIR}"
  nohup ./llama-server \
    -m "${LLAMA_MODEL}" \
    --host 127.0.0.1 --port 8081 \
    -c 2048 -n 160 -t 2 -ngl 0 \
    >"${LOG_LLAMA}" 2>&1 &
  echo $! > /tmp/llama-server.pid
  for i in $(seq 1 45); do
    if curl -sf http://127.0.0.1:8081/health >/dev/null 2>&1 || curl -sf http://127.0.0.1:8081/ >/dev/null 2>&1; then
      echo "llama-server OK"
      break
    fi
    sleep 2
    if [[ "${i}" -eq 45 ]]; then
      echo "llama-server slow start; continuing with template fallback" >&2
    fi
  done
else
  echo "llama-server binary/model missing; SLM will use template fallback" >&2
fi

echo "==> Starting EdgeMed on :8000"
cd "${EDGEMED}"
if [[ ! -d .venv ]]; then
  python3 -m venv .venv
  source .venv/bin/activate
  pip install -U pip wheel
  pip install -r requirements.txt
else
  source .venv/bin/activate
fi
export OMP_NUM_THREADS=1 OPENBLAS_NUM_THREADS=1
export SLM_BACKEND="${SLM_BACKEND:-llama_cpp_server}"
export EDGEMED_LLAMA_SERVER="${EDGEMED_LLAMA_SERVER:-http://127.0.0.1:8081}"
nohup uvicorn app.main:app --host 0.0.0.0 --port 8000 >"${LOG_ED}" 2>&1 &
echo $! > /tmp/edgemed-uvicorn.pid

for i in $(seq 1 30); do
  if curl -sf http://127.0.0.1:8000/health >/dev/null; then
    echo "EdgeMed health OK"
    break
  fi
  sleep 2
  if [[ "${i}" -eq 30 ]]; then
    echo "EdgeMed failed to start; tail ${LOG_ED}" >&2
    tail -n 40 "${LOG_ED}" >&2 || true
    exit 1
  fi
done

echo "==> Starting packet-sensor (edgemed backend + SLM investigate)"
cd "${PS_DIR}"
source .venv/bin/activate
export SENSOR_CONFIG_PATH="${ROOT}/config/sensor.pi-edgemed.yaml"
export PYTHONPATH="${PS_DIR}"
export CAPTURE_INTERFACE="${CAPTURE_INTERFACE:-eth0}"
export INFERENCE_BACKEND=edgemed
export EDGEMED_BASE_URL=http://127.0.0.1:8000
export EDGEMED_INVESTIGATE_ENABLED=true
export MODEL_INFERENCE_ENABLED=true
export SURICATA_SOURCE_ENABLED="${SURICATA_SOURCE_ENABLED:-true}"
export SURICATA_EVE_JSON_PATH="${SURICATA_EVE_JSON_PATH:-${ROOT}/data/suricata/eve.json}"
export SURICATA_SOURCE_POLL_SEC="${SURICATA_SOURCE_POLL_SEC:-2}"

echo "${PW:-0000}" | sudo -S -E env \
  SENSOR_CONFIG_PATH="${SENSOR_CONFIG_PATH}" \
  PYTHONPATH="${PYTHONPATH}" \
  CAPTURE_INTERFACE="${CAPTURE_INTERFACE}" \
  INFERENCE_BACKEND="${INFERENCE_BACKEND}" \
  EDGEMED_BASE_URL="${EDGEMED_BASE_URL}" \
  EDGEMED_INVESTIGATE_ENABLED="${EDGEMED_INVESTIGATE_ENABLED}" \
  MODEL_INFERENCE_ENABLED="${MODEL_INFERENCE_ENABLED}" \
  SURICATA_SOURCE_ENABLED="${SURICATA_SOURCE_ENABLED}" \
  SURICATA_EVE_JSON_PATH="${SURICATA_EVE_JSON_PATH}" \
  SURICATA_SOURCE_POLL_SEC="${SURICATA_SOURCE_POLL_SEC}" \
  nohup "${PS_DIR}/.venv/bin/python" -m src.main >>"${LOG_PS}" 2>&1 &
sleep 3
pgrep -f "${PS_DIR}/.venv/bin/python -m src.main" | head -1 > /tmp/packet-sensor.pid || true

sleep 3
pgrep -af 'llama-server|uvicorn app.main|src.main' || true
echo "Logs: ${LOG_LLAMA} ${LOG_ED} ${LOG_PS}"

if [[ "${START_SURICATA:-true}" == "true" ]] && [[ -x "${ROOT}/deploy/pi4/start-suricata.sh" ]]; then
  echo "==> Starting Suricata sidecar (Docker)"
  bash "${ROOT}/deploy/pi4/start-suricata.sh"
fi

echo "==> Starting sensel-edge-agent (MQTT northbound)"
bash "${ROOT}/deploy/pi4/start-edge-agent.sh"
