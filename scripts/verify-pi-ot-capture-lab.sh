#!/usr/bin/env bash
# Pi lab: OT capture health — container status + capture-live GOOSE/MMS counters.
#
# Run on the Pi:
#   cd ~/sensel-ot-edge-sensor && ./scripts/verify-pi-ot-capture-lab.sh
#
# From laptop (lab Pi default .124):
#   SSHPASS=edgex PI_TARGET=edgex@192.168.1.124 \
#     ./scripts/verify-pi-ot-capture-lab.sh --remote
#
# Env:
#   CAPTURE_IF=eth0     mirror interface
#   SNIFF_SEC=3         tcpdump sample seconds (0 = skip)
#   REPO_DIR=...        repo path on Pi
set -euo pipefail

PI_TARGET="${PI_TARGET:-edgex@192.168.1.124}"
REMOTE=0

for arg in "$@"; do
  case "$arg" in
    --remote) REMOTE=1 ;;
    -h|--help)
      sed -n '2,14p' "$0"
      exit 0
      ;;
    *) echo "Unknown arg: $arg" >&2; exit 1 ;;
  esac
done

BODY=$(cat <<'EOF'
set -uo pipefail

REPO_DIR="${REPO_DIR:-$HOME/sensel-ot-edge-sensor}"
CAPTURE_IF="${CAPTURE_IF:-eth0}"
SNIFF_SEC="${SNIFF_SEC:-3}"
ASSETS="${REPO_DIR}/data/assets"
LIVE_HOST="${ASSETS}/capture-live.json"
OBSERVED_HOST="${ASSETS}/baseline/live-observed.json"
AGENT="${REPO_DIR}/data/agent"
MODE_JSON="${AGENT}/operational-mode.json"

read_json() {
  local path="$1"
  if [[ -r "$path" ]]; then
    cat "$path"
    return 0
  fi
  local rel="${path#*data/assets/}"
  if docker ps --format '{{.Names}}' | grep -qx sensel-packet-sensor; then
    docker exec sensel-packet-sensor cat "/app/data/assets/${rel}" 2>/dev/null && return 0
  fi
  return 1
}

hr() { printf '\n%s\n' "────────────────────────────────────────"; }
ok() { printf '  ✓ %s\n' "$*"; }
warn() { printf '  ⚠ %s\n' "$*"; }
bad() { printf '  ✗ %s\n' "$*"; }

hr
echo "==> 1) Core + 61850 lab containers"
for name in sensel-packet-sensor sensel-edge-agent sensel-edge-console \
            sensel-goose-publisher sensel-mms-publisher sensel-it-traffic-publisher; do
  if docker ps --format '{{.Names}}' | grep -qx "$name"; then
    st="$(docker inspect "$name" --format '{{.State.Status}}')"
    ok "$name ($st)"
  else
    bad "$name — not running (OT lab traffic may be missing)"
  fi
done

hr
echo "==> 2) packet-sensor capture config"
if docker ps --format '{{.Names}}' | grep -qx sensel-packet-sensor; then
  docker exec sensel-packet-sensor printenv 2>/dev/null \
    | grep -E '^(CAPTURE_INTERFACE|CAPTURE_BPF_FILTER|SENSOR_ID|SITE_ID)=' \
    | sed 's/^/  /' || true
  echo "  recent logs:"
  docker logs sensel-packet-sensor --tail 5 2>&1 | sed 's/^/    /'
else
  bad "sensel-packet-sensor not running"
fi

hr
echo "==> 3) capture-live.json (GOOSE / MMS / L2-L3)"
LIVE_JSON="$(read_json "$LIVE_HOST" || true)"
if [[ -z "$LIVE_JSON" ]]; then
  bad "cannot read capture-live.json (host or container)"
else
  LIVE_AGE="$(python3 - <<PY
import os, time
p = "$LIVE_HOST"
try:
    print(int(time.time() - os.path.getmtime(p)))
except OSError:
    print(-1)
PY
)"
  LIVE_JSON="$LIVE_JSON" LIVE_AGE="$LIVE_AGE" python3 - <<'PY'
import json, os
d = json.loads(os.environ["LIVE_JSON"])
keys = [
    "total_packets", "instant_rate", "packet_rate",
    "unique_ips", "unique_macs",
    "goose_messages", "mms_reads", "mms_writes", "mms_sessions",
    "capture_interface", "capture_bpf", "idle_sec",
]
age = int(os.environ.get("LIVE_AGE", "-1"))
if age >= 0:
    print(f"  file_age_sec={age}")
for k in keys:
    if k in d:
        print(f"  {k}={d[k]!r}")
tops = d.get("top_ips") or []
if tops:
    print("  top_ips:", ", ".join(f"{x.get('ip')}({x.get('count')})" for x in tops[:5]))
goose = int(d.get("goose_messages") or 0)
mms_w = int(d.get("mms_writes") or 0)
mms_r = int(d.get("mms_reads") or 0)
if goose == 0 and mms_w == 0 and mms_r == 0:
    print("  WARN: goose_messages=0 and mms_reads/writes=0")
else:
    print("  OK: OT protocol counters non-zero on capture-live")
PY
  if [[ "$LIVE_AGE" -ge 0 && "$LIVE_AGE" -gt 120 ]]; then
    warn "capture-live older than 120s — sensor may be stalled or idle"
  fi
fi

hr
echo "==> 4) live-observed.json (baseline learning snapshot)"
OBS_JSON="$(read_json "$OBSERVED_HOST" || true)"
if [[ -z "$OBS_JSON" ]]; then
  warn "cannot read live-observed.json (no learning snapshot yet?)"
else
  OBS_JSON="$OBS_JSON" python3 - <<'PY'
import json, os
d = json.loads(os.environ["OBS_JSON"])
stats = d.get("stats") or {}
obs = d.get("observed") or {}
iec = obs.get("iec61850") or {}
print("  schema:", d.get("schema"))
print("  stats.packets:", stats.get("packets"))
print("  stats.unique_ips:", stats.get("unique_ips"))
print("  goose_publishers:", len(iec.get("goose_publishers") or []))
print("  mms_ieds:", len(iec.get("mms_ieds") or []))
print("  modbus_servers:", len(obs.get("modbus_servers") or []))
print("  comm_pairs:", len(obs.get("comm_pairs") or []))
PY
fi

hr
echo "==> 5) operational mode (learning / listen / detect)"
if [[ -f "$MODE_JSON" ]]; then
  python3 - <<PY
import json
from pathlib import Path
a = json.loads(Path("$MODE_JSON").read_text())
print("  mode:", a.get("mode"))
print("  session_id:", a.get("session_id"))
print("  baseline_profile_id:", a.get("baseline_profile_id"))
cap = a.get("capture") or {}
print("  capture.interface:", cap.get("interface"))
PY
else
  warn "missing $MODE_JSON"
fi

hr
echo "==> 6) 61850 publisher logs (last 3 lines each)"
for name in sensel-goose-publisher sensel-mms-publisher sensel-it-traffic-publisher; do
  if docker ps --format '{{.Names}}' | grep -qx "$name"; then
    echo "  --- $name ---"
    docker logs "$name" --tail 3 2>&1 | sed 's/^/    /'
  fi
done

if [[ "$SNIFF_SEC" != "0" ]] && command -v tcpdump >/dev/null 2>&1; then
  hr
  echo "==> 7) Live sniff on ${CAPTURE_IF} (${SNIFF_SEC}s) — GOOSE 0x88b8 + MMS tcp/102"
  sudo timeout "$SNIFF_SEC" tcpdump -ni "$CAPTURE_IF" \
    '(ether proto 0x88b8) or (tcp port 102)' -c 20 2>&1 \
    | sed 's/^/  /' || warn "tcpdump found no GOOSE/MMS frames (or need sudo)"
fi

hr
echo "==> Interpretation"
echo "  • goose_messages / mms_* > 0  → sensor sees OT on mirror; learning should populate GOOSE/MMS."
echo "  • total_packets > 0 but goose/mms = 0 → IT/L2-L3 only (check SPAN, publishers, interface)."
echo "  • publishers running but counters 0 → traffic not on ${CAPTURE_IF} or BPF blocks frames."
echo "  • Restart publishers: docker restart sensel-goose-publisher sensel-mms-publisher"
EOF
)

if [[ "$REMOTE" == "1" ]]; then
  SSH_CMD=(ssh -o StrictHostKeyChecking=accept-new)
  if [[ -n "${SSHPASS:-}" ]] && command -v sshpass >/dev/null 2>&1; then
    SSH_CMD=(sshpass -e ssh -o StrictHostKeyChecking=accept-new)
  fi
  echo "==> Remote OT capture check: ${PI_TARGET}"
  CAPTURE_IF="${CAPTURE_IF:-eth0}" SNIFF_SEC="${SNIFF_SEC:-3}" \
    REPO_DIR="${REPO_DIR:-~/sensel-ot-edge-sensor}" \
    "${SSH_CMD[@]}" "$PI_TARGET" "bash -s" <<< "$BODY"
else
  eval "$BODY"
fi
