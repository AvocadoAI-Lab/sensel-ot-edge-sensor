#!/usr/bin/env bash
# S5-F1: Verify 203 Layer B/C docker healthchecks (layerc-api + layerb-worker).
#
# Usage:
#   export SSHPASS='avocado@@'
#   ./scripts/verify-203-compose-health.sh
#
#   ./scripts/verify-203-compose-health.sh --local   # on 203 host directly
#
set -euo pipefail

CP203_HOST="${CP203_HOST:-192.168.1.203}"
CP203_USER="${CP203_USER:-avocado.ai}"
LAYERC_URL="${LAYERC_URL:-http://${CP203_HOST}:8001}"
LOCAL=0
FAILURES=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --local) LOCAL=1; shift ;;
    -h|--help)
      sed -n '2,12p' "$0"
      exit 0
      ;;
    *) echo "Unknown arg: $1" >&2; exit 1 ;;
  esac
done

pass() { echo "[PASS] $*"; }
fail() { echo "[FAIL] $*" >&2; FAILURES=$((FAILURES + 1)); }

run_checks() {
  export PATH="/usr/local/bin:/Applications/Docker.app/Contents/Resources/bin:/usr/bin:/bin:${PATH:-}"
  local docker_bin=""
  if [[ -x /usr/local/bin/docker ]]; then docker_bin=/usr/local/bin/docker
  elif command -v docker >/dev/null 2>&1; then docker_bin=docker
  fi
  if [[ -z "$docker_bin" ]]; then
    echo "DOCKER_MISSING"
    return 2
  fi

  for cname in layerb-worker layera-layerc-api; do
    if ! "$docker_bin" inspect "$cname" >/dev/null 2>&1; then
      echo "MISSING|${cname}"
      continue
    fi
    local running status
    running="$("$docker_bin" inspect --format='{{.State.Running}}' "$cname" 2>/dev/null || echo false)"
    status="$("$docker_bin" inspect --format='{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}' "$cname" 2>/dev/null || echo unknown)"
    echo "CONTAINER|${cname}|${running}|${status}"
  done

  if curl -sf --max-time 10 http://127.0.0.1:8001/health >/dev/null; then
    echo "LAYERC_HTTP|ok"
  else
    echo "LAYERC_HTTP|fail"
  fi
}

echo "==> S5-F1 203 compose health (${CP203_USER}@${CP203_HOST})"

if [[ "$LOCAL" == "1" ]]; then
  output="$(run_checks 2>&1 || true)"
else
  if ! command -v sshpass >/dev/null 2>&1; then
    fail "sshpass required (install via brew install sshpass, or run on 203 with --local)"
    exit 1
  fi
  output="$(SSHPASS="${SSHPASS:-avocado@@}" sshpass -e ssh -o StrictHostKeyChecking=no -o ConnectTimeout=10 \
    "${CP203_USER}@${CP203_HOST}" 'bash -s' <<'REMOTE'
set -euo pipefail
export PATH="/usr/local/bin:/Applications/Docker.app/Contents/Resources/bin:/usr/bin:/bin:${PATH:-}"
docker_bin=""
if [[ -x /usr/local/bin/docker ]]; then docker_bin=/usr/local/bin/docker
elif command -v docker >/dev/null 2>&1; then docker_bin=docker
fi
if [[ -z "$docker_bin" ]]; then echo "DOCKER_MISSING"; exit 0; fi
for cname in layerb-worker layera-layerc-api; do
  if ! "$docker_bin" inspect "$cname" >/dev/null 2>&1; then
    echo "MISSING|${cname}"
    continue
  fi
  running="$("$docker_bin" inspect --format='{{.State.Running}}' "$cname" 2>/dev/null || echo false)"
  status="$("$docker_bin" inspect --format='{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}' "$cname" 2>/dev/null || echo unknown)"
  echo "CONTAINER|${cname}|${running}|${status}"
done
if curl -sf --max-time 10 http://127.0.0.1:8001/health >/dev/null; then
  echo "LAYERC_HTTP|ok"
else
  echo "LAYERC_HTTP|fail"
fi
REMOTE
  )"
fi

if [[ "$output" == *"DOCKER_MISSING"* ]]; then
  fail "docker not found on 203"
  exit 1
fi

healthy_count=0
while IFS= read -r line; do
  [[ -z "$line" ]] && continue
  IFS='|' read -r kind arg1 arg2 arg3 <<< "$line"
  case "$kind" in
    CONTAINER)
      if [[ "$arg2" == "true" && "$arg3" == "healthy" ]]; then
        pass "F1-${arg1} docker health=healthy"
        healthy_count=$((healthy_count + 1))
      else
        fail "F1-${arg1} running=${arg2} health=${arg3}"
      fi
      ;;
    MISSING)
      fail "F1-container missing: ${arg1}"
      ;;
    LAYERC_HTTP)
      if [[ "$arg1" == "ok" ]]; then
        pass "F1-layerc-http ${LAYERC_URL}/health"
      else
        fail "F1-layerc-http unreachable on 203 :8001"
      fi
      ;;
  esac
done <<< "$output"

if [[ "$healthy_count" -lt 2 ]]; then
  fail "F1-healthcheck-count ${healthy_count}/2 healthy"
else
  pass "F1-healthcheck-count 2/2"
fi

if [[ "$FAILURES" -gt 0 ]]; then
  echo "S5-F1 203 COMPOSE HEALTH FAILED (${FAILURES})" >&2
  exit 1
fi
echo "S5-F1 203 COMPOSE HEALTH PASS"
exit 0
