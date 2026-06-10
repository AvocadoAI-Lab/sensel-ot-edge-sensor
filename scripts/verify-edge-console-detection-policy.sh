#!/usr/bin/env bash
# Smoke: Edge Console applied detection policy API + UI (P1 read-only).
#
# Usage:
#   EDGE_CONSOLE_URL=http://192.168.1.123:8090 ./scripts/verify-edge-console-detection-policy.sh
set -euo pipefail

EDGE_CONSOLE_URL="${EDGE_CONSOLE_URL:-http://127.0.0.1:8090}"

pass() { echo "PASS  $*"; }
fail() { echo "FAIL  $*" >&2; exit 1; }

curl_json() {
  curl -fsS "${EDGE_CONSOLE_URL}$1"
}

echo "==> Edge Console detection policy smoke"
echo "    URL: ${EDGE_CONSOLE_URL}"

applied="$(curl_json /api/detection-policy/applied)"
echo "$applied" | python3 -c "
import json,sys
d=json.load(sys.stdin)
assert 'loaded' in d, d
if d.get('loaded'):
    assert d.get('rules_count', 0) >= 0
    assert 'mms_summary' in d
    print('loaded=True version=', d.get('version'), 'rules=', d.get('rules_count'))
else:
    assert 'fallback' in d
    print('loaded=False fallback=', (d.get('fallback') or {}).get('kind'))
" || fail "/api/detection-policy/applied schema"
pass "/api/detection-policy/applied"

html="$(curl -fsS "${EDGE_CONSOLE_URL}/")"
echo "$html" | grep -q 'id="tab-policy"' || fail "index missing tab-policy"
echo "$html" | grep -q 'data-tab="policy"' || fail "index missing policy nav"
pass "UI policy tab"

js="$(curl -fsS "${EDGE_CONSOLE_URL}/app.js")"
echo "$js" | grep -q '/api/detection-policy/applied' || fail "app.js missing detection policy API"
echo "$js" | grep -q 'loadAppliedPolicy' || fail "app.js missing loadAppliedPolicy"
echo "$js" | grep -q 'policyRulesRows' || fail "app.js missing policyRulesRows table"
pass "UI app.js wired"

echo "==> SMOKE OK"
