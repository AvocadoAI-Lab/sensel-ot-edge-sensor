#!/usr/bin/env bash
# Smoke test: Edge Console API + traffic UI assets + packet-sensor live stats.
#
# Usage:
#   EDGE_CONSOLE_URL=http://192.168.1.123:8090 ./scripts/verify-edge-console-traffic.sh
#   PI_TARGET=edgex@192.168.1.123 ./scripts/verify-edge-console-traffic.sh --remote
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
EDGE_CONSOLE_URL="${EDGE_CONSOLE_URL:-http://127.0.0.1:8090}"
PI_TARGET="${PI_TARGET:-edgex@192.168.1.123}"
REMOTE=0
EXPECT_SRC_IP="${EXPECT_SRC_IP:-192.168.10.88}"

for arg in "$@"; do
  case "$arg" in
    --remote) REMOTE=1 ;;
    -h|--help)
      sed -n '2,8p' "$0"
      exit 0
      ;;
    *) echo "Unknown arg: $arg" >&2; exit 1 ;;
  esac
done

pass() { echo "PASS  $*"; }
fail() { echo "FAIL  $*" >&2; exit 1; }

curl_json() {
  local path="$1"
  curl -fsS "${EDGE_CONSOLE_URL}${path}"
}

echo "==> Edge Console traffic smoke test"
echo "    URL: ${EDGE_CONSOLE_URL}"

# --- API ---
health="$(curl_json /api/health)"
echo "$health" | python3 -c 'import json,sys; d=json.load(sys.stdin); assert d.get("service")=="edge-console", d' \
  || fail "/api/health unexpected payload"
pass "/api/health"

traffic="$(curl_json /api/traffic/live)"
echo "$traffic" | python3 -c "
import json,sys
d=json.load(sys.stdin)
assert 'metrics' in d, d
assert 'recent_packets' in d, d
m=d['metrics']
assert isinstance(m.get('instant_rate'), (int,float)), m
print('live=', d.get('live'), 'rate=', m.get('instant_rate'), 'packets=', len(d.get('recent_packets') or []))
" || fail "/api/traffic/live schema"
pass "/api/traffic/live"

events="$(curl_json '/api/events/recent?limit=20')"
echo "$events" | python3 -c 'import json,sys; d=json.load(sys.stdin); assert "events" in d and isinstance(d["events"], list), d' \
  || fail "/api/events/recent schema"
pass "/api/events/recent count=$(echo "$events" | python3 -c 'import json,sys; print(len(json.load(sys.stdin).get("events",[])))')"

# Optional: expect mirrored MMS source IP in live traffic
if [[ -n "$EXPECT_SRC_IP" ]]; then
  echo "$traffic" | python3 -c "
import json,sys
ip='${EXPECT_SRC_IP}'
d=json.load(sys.stdin)
tops=[x.get('ip') for x in d.get('top_ips',[])]
recent=[p.get('src_ip') for p in d.get('recent_packets',[])]
ok = ip in tops or ip in recent
print('expect_ip', ip, 'top_ips', tops[:3], 'recent_hit', ip in recent)
sys.exit(0 if ok else 2)
" && pass "traffic includes source IP ${EXPECT_SRC_IP}" \
    || echo "WARN  traffic API ok but ${EXPECT_SRC_IP} not in top/recent (lab publishers may be off)"
fi

# --- UI assets ---
html="$(curl -fsS "${EDGE_CONSOLE_URL}/")"
echo "$html" | grep -q 'id="tab-traffic"' || fail "index.html missing tab-traffic"
echo "$html" | grep -q 'data-tab="traffic"' || fail "index.html missing traffic tab button"
pass "UI index has traffic tab"

js="$(curl -fsS "${EDGE_CONSOLE_URL}/app.js")"
echo "$js" | grep -q 'loadTraffic' || fail "app.js missing loadTraffic"
echo "$js" | grep -q '/api/traffic/live' || fail "app.js missing traffic API call"
pass "UI app.js wired to /api/traffic/live"

# --- Remote container checks ---
if [[ "$REMOTE" == "1" ]]; then
  SSH_CMD=(ssh -o StrictHostKeyChecking=no)
  if [[ -n "${SSHPASS:-}" ]] && command -v sshpass >/dev/null 2>&1; then
    SSH_CMD=(sshpass -e ssh -o StrictHostKeyChecking=no)
  fi
  echo "==> Remote checks on ${PI_TARGET}"
  "${SSH_CMD[@]}" "$PI_TARGET" bash -s <<'REMOTE'
set -euo pipefail
docker ps --format '{{.Names}}' | grep -q '^sensel-edge-console$' || { echo "missing sensel-edge-console"; exit 1; }
docker ps --format '{{.Names}}' | grep -q '^sensel-packet-sensor$' || { echo "missing sensel-packet-sensor"; exit 1; }
docker logs sensel-edge-console --tail 3 2>&1 | grep -qi uvicorn || echo "WARN edge-console log (no uvicorn line in tail)"
docker logs sensel-packet-sensor --tail 20 2>&1 | grep -E 'Capture stats|Capture backend' | tail -1
test -f ~/sensel-ot-edge-sensor/data/assets/capture-live.json && echo "capture-live.json present"
REMOTE
  pass "remote containers + capture-live.json"
fi

echo "==> SMOKE OK"
