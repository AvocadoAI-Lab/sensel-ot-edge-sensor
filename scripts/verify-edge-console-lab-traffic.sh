#!/usr/bin/env bash
# Smoke: Edge Console lab traffic API + UI (P0).
#
# Usage:
#   EDGE_CONSOLE_URL=http://192.168.1.123:8090 ./scripts/verify-edge-console-lab-traffic.sh
set -euo pipefail

EDGE_CONSOLE_URL="${EDGE_CONSOLE_URL:-http://127.0.0.1:8090}"

pass() { echo "PASS  $*"; }
fail() { echo "FAIL  $*" >&2; exit 1; }

curl_json() {
  curl -fsS "${EDGE_CONSOLE_URL}$1"
}

echo "==> Edge Console lab traffic smoke"
echo "    URL: ${EDGE_CONSOLE_URL}"

status="$(curl_json /api/lab/traffic/status)"
echo "$status" | python3 -c "
import json,sys
d=json.load(sys.stdin)
assert 'enabled' in d and 'publishers' in d and 'capture' in d, d
assert isinstance(d['presets'], list), d
print('enabled=', d.get('enabled'), 'docker_ctrl=', d.get('docker_control_enabled'))
" || fail "/api/lab/traffic/status schema"
pass "/api/lab/traffic/status"

html="$(curl -fsS "${EDGE_CONSOLE_URL}/")"
echo "$html" | grep -q 'id="labTrafficPanel"' || fail "index missing labTrafficPanel"
pass "UI lab traffic panel"

js="$(curl -fsS "${EDGE_CONSOLE_URL}/app.js")"
echo "$js" | grep -q '/api/lab/traffic/status' || fail "app.js missing lab traffic API"
echo "$js" | grep -q 'labTrafficPreset' || fail "app.js missing labTrafficPreset"
pass "UI app.js wired"

echo "==> SMOKE OK (no docker mutations in smoke)"
