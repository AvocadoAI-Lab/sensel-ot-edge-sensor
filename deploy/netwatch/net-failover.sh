#!/usr/bin/env bash
# SenseL offline failover (oneshot; driven by a systemd timer).
#
# When the appliance has NO outbound Internet for a few consecutive checks, it
# brings up the operator-pinned fallback Wi-Fi networks (phone hotspot / switch
# Wi-Fi, whose passwords NetworkManager already stored) in priority order — the
# same order configured in the Edge Console (System Maintenance), read from the
# shared wifi-priority.json.
#
# This complements NetworkManager autoconnect (which already reconnects pinned
# APs when Wi-Fi is free): it specifically handles the "link is up but there is
# no Internet" case, where NM does not roam on its own.
set -euo pipefail

PRIORITY_FILE="${WIFI_PRIORITY_FILE:-/home/edgex/sensel-ot-edge-sensor/data/agent/wifi-priority.json}"
STATE_DIR="${NETWATCH_STATE_DIR:-/run/sensel-netwatch}"
FAIL_THRESHOLD="${NETWATCH_FAIL_THRESHOLD:-2}"   # consecutive offline checks before acting
CONNECT_WAIT="${NETWATCH_CONNECT_WAIT:-30}"      # seconds to wait per nmcli activation

CHECK_URLS=("http://connectivitycheck.gstatic.com/generate_204" "http://www.msftconnecttest.com/connecttest.txt")
PING_HOSTS=("1.1.1.1" "8.8.8.8")

mkdir -p "${STATE_DIR}"
FAILCNT_FILE="${STATE_DIR}/failcount"

log() { echo "[net-failover] $*"; }

online() {
  local u code h
  for u in "${CHECK_URLS[@]}"; do
    code="$(curl -s -m 4 -o /dev/null -w '%{http_code}' "$u" 2>/dev/null || echo 000)"
    [[ "$code" == "204" || "$code" == "200" ]] && return 0
  done
  for h in "${PING_HOSTS[@]}"; do
    ping -c1 -W2 "$h" >/dev/null 2>&1 && return 0
  done
  return 1
}

read_pinned() {
  # Print pinned SSIDs (one per line) in priority order. Prefer python3; fall
  # back to a tolerant grep so a missing python3 doesn't disable failover.
  [[ -f "${PRIORITY_FILE}" ]] || return 0
  if command -v python3 >/dev/null 2>&1; then
    python3 - "${PRIORITY_FILE}" <<'PY' 2>/dev/null || true
import json, sys
try:
    d = json.load(open(sys.argv[1]))
    order = d.get("order") if isinstance(d, dict) else d
    for s in (order or []):
        if isinstance(s, str) and s:
            print(s)
except Exception:
    pass
PY
  else
    tr -d '\n' < "${PRIORITY_FILE}" | grep -oE '"order"[[:space:]]*:[[:space:]]*\[[^]]*\]' \
      | grep -oE '"[^"]+"' | sed -n '2,$p' | sed 's/^"//; s/"$//'
  fi
}

if online; then
  echo 0 > "${FAILCNT_FILE}"
  exit 0
fi

cnt="$(( $(cat "${FAILCNT_FILE}" 2>/dev/null || echo 0) + 1 ))"
echo "${cnt}" > "${FAILCNT_FILE}"
if [[ "${cnt}" -lt "${FAIL_THRESHOLD}" ]]; then
  log "offline (${cnt}/${FAIL_THRESHOLD}) — waiting before failover"
  exit 0
fi

log "offline for ${cnt} checks — attempting Wi-Fi failover"
nmcli radio wifi on >/dev/null 2>&1 || true
nmcli dev wifi rescan >/dev/null 2>&1 || true
sleep 3

mapfile -t SSIDS < <(read_pinned)

if [[ "${#SSIDS[@]}" -eq 0 ]]; then
  # No explicit pins: nudge NetworkManager to autoconnect the highest-priority
  # visible saved network on its own.
  log "no pinned fallbacks; relying on NetworkManager autoconnect"
  exit 0
fi

for ssid in "${SSIDS[@]}"; do
  log "trying fallback AP: ${ssid}"
  if nmcli -w "${CONNECT_WAIT}" connection up "${ssid}" >/dev/null 2>&1; then
    sleep 3
    if online; then
      log "connectivity restored via ${ssid}"
      echo 0 > "${FAILCNT_FILE}"
      exit 0
    fi
  fi
done

log "no fallback AP restored connectivity"
exit 0
