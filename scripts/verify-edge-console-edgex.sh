#!/usr/bin/env bash
# Smoke test: Edge Console EdgeX proxy APIs (S3)
#
# Usage:
#   EDGE_CONSOLE_URL=http://192.168.1.123:8090 ./scripts/verify-edge-console-edgex.sh
set -euo pipefail

EDGE_CONSOLE_URL="${EDGE_CONSOLE_URL:-http://127.0.0.1:8090}"

pass() { echo "PASS  $*"; }
fail() { echo "FAIL  $*" >&2; exit 1; }

curl_json() {
  curl -fsS "${EDGE_CONSOLE_URL}$1"
}

echo "==> Edge Console EdgeX API smoke"
echo "    URL: ${EDGE_CONSOLE_URL}"

health="$(curl_json /api/health)"
echo "$health" | python3 -c 'import json,sys; d=json.load(sys.stdin); assert d.get("service")=="edge-console"' \
  || fail "/api/health"
pass "/api/health"

# APIs require auth when password set — lab often has no password
platform="$(curl_json /api/edgex/platform 2>/dev/null || true)"
if [[ -z "$platform" ]]; then
  echo "WARN  /api/edgex/platform requires login or unreachable"
else
  echo "$platform" | python3 -c '
import json,sys
d=json.load(sys.stdin)
assert "services" in d and isinstance(d["services"], list), d
print("reachable=", d.get("reachable"), "services=", len(d["services"]))
' || fail "/api/edgex/platform schema"
  pass "/api/edgex/platform"
fi

devices="$(curl_json /api/edgex/devices 2>/dev/null || true)"
if [[ -n "$devices" ]]; then
  echo "$devices" | python3 -c '
import json,sys
d=json.load(sys.stdin)
assert "devices" in d and isinstance(d["devices"], list), d
print("count=", d.get("count"), "source=", d.get("source"))
' || fail "/api/edgex/devices schema"
  pass "/api/edgex/devices"
fi

html="$(curl -fsS "${EDGE_CONSOLE_URL}/")"
echo "$html" | grep -q 'id="tab-edgex"' || fail "index missing tab-edgex"
echo "$html" | grep -q 'data-tab="devices"' || fail "index missing devices nav"
pass "UI has EdgeX + devices tabs"

js="$(curl -fsS "${EDGE_CONSOLE_URL}/app.js")"
echo "$js" | grep -q 'loadEdgexPlatform' || fail "app.js missing loadEdgexPlatform"
echo "$js" | grep -q '/api/edgex/devices' || fail "app.js missing edgex devices API"
pass "UI app.js wired"

phase2="$(curl_json /api/edgex/phase2/status 2>/dev/null || true)"
if [[ -n "$phase2" ]]; then
  echo "$phase2" | python3 -c 'import json,sys; d=json.load(sys.stdin); print("phase2_enabled=", d.get("enabled"))' \
    || fail "/api/edgex/phase2/status schema"
  pass "/api/edgex/phase2/status"
fi

wizard="$(curl_json /api/edgex/wizard/templates 2>/dev/null || true)"
if [[ -n "$wizard" ]]; then
  echo "$wizard" | python3 -c 'import json,sys; d=json.load(sys.stdin); assert "templates" in d' || fail "wizard templates"
  pass "/api/edgex/wizard/templates"
fi

echo "==> SMOKE OK"
