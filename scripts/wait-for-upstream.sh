#!/usr/bin/env bash
# Wait for lab upstream (108 SenseL API + 203 EMQX) before starting edge stack.
#
# Usage:
#   ./scripts/wait-for-upstream.sh
#   WAIT_UPSTREAM=0 ./scripts/wait-for-upstream.sh   # skip
#   CONTROL_PLANE_MQTT_HOST=192.168.1.203 SENSEL_API_URL=http://192.168.1.108:8081 ./scripts/wait-for-upstream.sh
set -euo pipefail

if [[ "${WAIT_UPSTREAM:-1}" == "0" ]] || [[ "${WAIT_UPSTREAM:-}" == "false" ]]; then
  echo "==> WAIT_UPSTREAM disabled; skipping upstream probe"
  exit 0
fi

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
_load_env_var() {
  local key="$1"
  local line val
  line="$(grep -m1 "^${key}=" "${ROOT}/.env" 2>/dev/null || true)"
  [[ -n "$line" ]] || return 0
  val="${line#*=}"
  if [[ "$val" =~ ^\".*\"$ ]]; then
    val="${val:1:${#val}-2}"
  elif [[ "$val" =~ ^\'.*\'$ ]]; then
    val="${val:1:${#val}-2}"
  fi
  export "${key}=${val}"
}
if [[ -f "${ROOT}/.env" ]]; then
  for key in WAIT_UPSTREAM WAIT_UPSTREAM_MAX_SEC WAIT_UPSTREAM_INTERVAL_SEC \
    CONTROL_PLANE_MQTT_HOST CONTROL_PLANE_MQTT_PORT SENSEL_API_URL; do
    _load_env_var "$key"
  done
fi

MQTT_HOST="${CONTROL_PLANE_MQTT_HOST:-192.168.1.203}"
MQTT_PORT="${CONTROL_PLANE_MQTT_PORT:-1883}"
API_URL="${SENSEL_API_URL:-http://192.168.1.108:8081}"
MAX_SEC="${WAIT_UPSTREAM_MAX_SEC:-300}"
INTERVAL="${WAIT_UPSTREAM_INTERVAL_SEC:-5}"

probe_tcp() {
  local host="$1" port="$2"
  python3 - "$host" "$port" <<'PY'
import socket, sys
host, port = sys.argv[1], int(sys.argv[2])
s = socket.socket()
s.settimeout(3)
try:
    s.connect((host, port))
except OSError:
    sys.exit(1)
finally:
    s.close()
sys.exit(0)
PY
}

probe_http() {
  local url="$1"
  python3 - "$url" <<'PY'
import sys, urllib.request
url = sys.argv[1].rstrip("/") + "/api/health"
try:
    with urllib.request.urlopen(url, timeout=8) as resp:
        sys.exit(0 if 200 <= resp.status < 300 else 1)
except Exception:
    sys.exit(1)
PY
}

echo "==> Waiting for upstream (max ${MAX_SEC}s)"
echo "    MQTT  ${MQTT_HOST}:${MQTT_PORT}"
echo "    HTTP  ${API_URL}/api/health"

deadline=$(( $(date +%s) + MAX_SEC ))
mqtt_ok=0
http_ok=0
while [[ $(date +%s) -lt $deadline ]]; do
  if [[ $mqtt_ok -eq 0 ]] && probe_tcp "$MQTT_HOST" "$MQTT_PORT"; then
    mqtt_ok=1
    echo "  MQTT ready"
  fi
  if [[ $http_ok -eq 0 ]] && probe_http "$API_URL"; then
    http_ok=1
    echo "  SenseL API ready"
  fi
  if [[ $mqtt_ok -eq 1 && $http_ok -eq 1 ]]; then
    echo "==> Upstream ready"
    exit 0
  fi
  sleep "$INTERVAL"
done

echo "==> Upstream wait timed out (mqtt=${mqtt_ok} http=${http_ok}); starting stack anyway" >&2
exit 0
