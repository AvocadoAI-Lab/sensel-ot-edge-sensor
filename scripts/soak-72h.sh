#!/usr/bin/env bash
# D4: 72-hour lab soak — periodic health + E2E pipeline checks (Pi → 203 → 108).
#
# Usage:
#   export SSHPASS='...'         # 108 / 203 SSH credential
#   export PI_SSHPASS='...'      # Pi SSH credential
#   ./scripts/soak-72h.sh                    # foreground, 72h
#   ./scripts/soak-72h.sh --background       # nohup on current host
#   ./scripts/soak-72h.sh --interval 900     # seconds between probes (default 900 = 15m)
#   ./scripts/soak-72h.sh --duration 259200  # seconds (default 72h)
#
# Logs: data/soak/72h-<start-ts>/soak.log + summary.json
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DURATION_SEC="${SOAK_DURATION_SEC:-259200}"   # 72h
INTERVAL_SEC="${SOAK_INTERVAL_SEC:-900}"      # 15m
BACKGROUND=0

PI_TARGET="${PI_TARGET:-edgex@192.168.1.123}"
: "${PI_SSHPASS:?set PI_SSHPASS for the Pi validation identity}"
: "${SSHPASS:?set SSHPASS for the Control Plane/portal validation identity}"
CP203_HOST="${CP203_HOST:-192.168.1.203}"
PORTAL108_URL="${PORTAL108_URL:-http://192.168.1.108:8081}"
LAYERC_URL="${LAYERC_URL:-http://${CP203_HOST}:8001}"
TENANT_ID="${SOAK_TENANT_ID:-company-a9ae1234648ee138}"
MAX_EVENT_STALE_SEC="${SOAK_MAX_EVENT_STALE_SEC:-600}"  # pipeline must see event within 10m

for arg in "$@"; do
  case "$arg" in
    --background) BACKGROUND=1 ;;
    --interval) shift; INTERVAL_SEC="${1:?--interval needs seconds}"; shift || true ;;
    --duration) shift; DURATION_SEC="${1:?--duration needs seconds}"; shift || true ;;
    -h|--help)
      sed -n '2,14p' "$0"
      exit 0
      ;;
  esac
done

LOG_DIR="${SOAK_LOG_DIR:-$ROOT/data/soak/72h-$(date -u +%Y%m%dT%H%M%SZ)}"
mkdir -p "$LOG_DIR"
LOG_FILE="$LOG_DIR/soak.log"
SUMMARY_JSON="$LOG_DIR/summary.json"
PID_FILE="$LOG_DIR/soak.pid"

if [[ "$BACKGROUND" == "1" ]]; then
  if [[ -f "$PID_FILE" ]] && kill -0 "$(cat "$PID_FILE")" 2>/dev/null; then
    echo "Soak already running pid=$(cat "$PID_FILE") log=$LOG_FILE" >&2
    exit 0
  fi
  SOAK_LOG_DIR="$LOG_DIR" nohup "$0" >>"$LOG_FILE" 2>&1 &
  echo $! >"$PID_FILE"
  echo "Started 72h soak pid=$(cat "$PID_FILE")"
  echo "Log: $LOG_FILE"
  exit 0
fi

log() {
  printf '%s %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*" | tee -a "$LOG_FILE"
}

ssh_pi() {
  SSHPASS="$PI_SSHPASS" sshpass -e ssh -o StrictHostKeyChecking=accept-new -o ConnectTimeout=10 "$PI_TARGET" "$@"
}

ssh_108() {
  SSHPASS="$SSHPASS" sshpass -e ssh -o StrictHostKeyChecking=accept-new -o ConnectTimeout=10 ubuntu@192.168.1.108 "$@"
}

probe_curl() {
  local name="$1" url="$2"
  if curl -sf --max-time 15 "$url" >/dev/null; then
    echo "ok"
  else
    echo "fail"
  fi
}

probe_pi() {
  local status mqtt events
  status="$(ssh_pi 'curl -sf --max-time 10 http://127.0.0.1:8090/api/status' 2>/dev/null || echo '{}')"
  mqtt="$(python3 -c "import json,sys; d=json.loads(sys.argv[1]); print(d.get('cards',{}).get('mqtt',{}).get('ok',False))" "$status" 2>/dev/null || echo False)"
  events="$(python3 -c "import json,sys; d=json.loads(sys.argv[1]); print(d.get('metrics',{}).get('events_24h',0))" "$status" 2>/dev/null || echo 0)"
  local agents
  agents="$(ssh_pi 'docker inspect -f "{{.State.Status}}" sensel-edge-agent sensel-packet-sensor 2>/dev/null | tr "\n" ","' 2>/dev/null || echo missing)"
  if [[ "$mqtt" == "True" ]] && [[ "$agents" == *running* ]]; then
    echo "ok mqtt events_24h=${events} containers=${agents}"
  else
    echo "fail mqtt=${mqtt} containers=${agents}"
  fi
}

probe_203_local() {
  local docker_bin=""
  if [[ -x /usr/local/bin/docker ]]; then
    docker_bin=/usr/local/bin/docker
  elif command -v docker >/dev/null 2>&1; then
    docker_bin=docker
  fi
  local health=fail containers=0 ot=0 ingest=0
  if curl -sf --max-time 10 "${LAYERC_URL}/health" >/dev/null 2>&1; then
    health=ok
  fi
  if [[ -n "$docker_bin" ]]; then
    containers="$("$docker_bin" ps --format '{{.Names}}' 2>/dev/null | grep -cE 'layera-mqtt-bridge|layera-layerc-bridge|layera-layerc-api|layerb-worker|layera-emqx' || true)"
    ot="$("$docker_bin" logs layera-mqtt-bridge --since 15m 2>&1 | grep -c 'ot-edge/' || true)"
    ingest="$("$docker_bin" logs layera-layerc-bridge --since 15m 2>&1 | grep -c 'ot_security ingest posted' || true)"
  fi
  if [[ "$health" == ok && "${containers:-0}" -ge 4 ]]; then
    echo "ok layerc=${health} containers=${containers} mqtt_ot_15m=${ot} ingest_15m=${ingest}"
  else
    echo "fail layerc=${health} containers=${containers} mqtt_ot_15m=${ot} ingest_15m=${ingest}"
  fi
}

probe_203_remote() {
  SSHPASS="$SSHPASS" sshpass -e ssh -o StrictHostKeyChecking=accept-new -o ConnectTimeout=10 "avocado.ai@${CP203_HOST}" '
    h=$(curl -sf --max-time 10 http://127.0.0.1:8001/health >/dev/null && echo ok || echo fail)
    d=$(/usr/local/bin/docker ps --format "{{.Names}}" 2>/dev/null | grep -cE "layera-mqtt-bridge|layera-layerc-bridge|layera-layerc-api|layerb-worker|layera-emqx" || echo 0)
    ot=$(/usr/local/bin/docker logs layera-mqtt-bridge --since 15m 2>&1 | grep -c "ot-edge/" || echo 0)
    ingest=$(/usr/local/bin/docker logs layera-layerc-bridge --since 15m 2>&1 | grep -c "ot_security ingest posted" || echo 0)
    if [[ "$h" == ok && "$d" -ge 4 ]]; then
      echo "ok layerc=${h} containers=${d} mqtt_ot_15m=${ot} ingest_15m=${ingest}"
    else
      echo "fail layerc=${h} containers=${d} mqtt_ot_15m=${ot} ingest_15m=${ingest}"
    fi
  ' 2>/dev/null || echo "fail ssh_203"
}

probe_portal() {
  local health count max_ts stale
  health="$(probe_curl portal "${PORTAL108_URL}/api/health")"
  read -r count max_ts <<<"$(ssh_108 "docker exec sensel-postgres psql -U sensel -d sensel -tAc \"SELECT count(*), coalesce(max(detected_at),'') FROM smb_ot_security_events WHERE tenant_id='${TENANT_ID}';\"" 2>/dev/null | tr '|' ' ' || echo '0 ')"
  count="${count// /}"
  max_ts="${max_ts// /}"
  stale=999999
  if [[ -n "$max_ts" ]]; then
    stale="$(python3 - <<PY
from datetime import datetime, timezone
ts = "${max_ts}".replace("Z", "+00:00")
try:
    dt = datetime.fromisoformat(ts)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    print(int((datetime.now(timezone.utc) - dt).total_seconds()))
except Exception:
    print(999999)
PY
)"
  fi
  if [[ "$health" == ok && "${count:-0}" -gt 0 && "$stale" -lt "$MAX_EVENT_STALE_SEC" ]]; then
    echo "ok health=${health} events=${count} last_age_sec=${stale}"
  else
    echo "fail health=${health} events=${count} last_age_sec=${stale}"
  fi
}

TOTAL_OK=0
TOTAL_FAIL=0
START_EPOCH="$(date +%s)"
END_EPOCH=$((START_EPOCH + DURATION_SEC))

log "SOAK START duration_sec=${DURATION_SEC} interval_sec=${INTERVAL_SEC} end_utc=$(date -u -r "$END_EPOCH" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -d "@$END_EPOCH" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || echo "$END_EPOCH")"
log "LOG_DIR=${LOG_DIR} TENANT=${TENANT_ID}"

while [[ "$(date +%s)" -lt "$END_EPOCH" ]]; do
  ITER_FAIL=0
  pi_r="$(probe_pi)" || pi_r="fail probe_error"
  [[ "$pi_r" == ok* ]] || ITER_FAIL=1

  if curl -sf --max-time 5 "http://127.0.0.1:8001/health" >/dev/null 2>&1; then
    cp_r="$(probe_203_local)"
  else
    cp_r="$(probe_203_remote)"
  fi
  [[ "$cp_r" == ok* || "$cp_r" == layerc=ok* ]] || ITER_FAIL=1

  portal_r="$(probe_portal)" || portal_r="fail probe_error"
  [[ "$portal_r" == ok* ]] || ITER_FAIL=1

  if [[ "$ITER_FAIL" -eq 0 ]]; then
    TOTAL_OK=$((TOTAL_OK + 1))
    log "PROBE PASS pi={${pi_r}} cp203={${cp_r}} portal={${portal_r}}"
  else
    TOTAL_FAIL=$((TOTAL_FAIL + 1))
    log "PROBE FAIL pi={${pi_r}} cp203={${cp_r}} portal={${portal_r}}"
  fi

  python3 - <<PY
import json, pathlib
path = pathlib.Path("${SUMMARY_JSON}")
data = {
    "started_epoch": ${START_EPOCH},
    "end_epoch": ${END_EPOCH},
    "probes_ok": ${TOTAL_OK},
    "probes_fail": ${TOTAL_FAIL},
    "last_probe_utc": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
    "log_dir": "${LOG_DIR}",
}
path.write_text(json.dumps(data, indent=2) + "\n")
PY

  sleep "$INTERVAL_SEC"
done

log "SOAK END probes_ok=${TOTAL_OK} probes_fail=${TOTAL_FAIL}"
if [[ "$TOTAL_FAIL" -eq 0 && "$TOTAL_OK" -gt 0 ]]; then
  log "RESULT PASS"
  exit 0
fi
log "RESULT FAIL (failures=${TOTAL_FAIL})"
exit 1
