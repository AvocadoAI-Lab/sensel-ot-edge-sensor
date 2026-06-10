#!/usr/bin/env bash
# S5-F1 Pi: verify edge-agent, edge-console, packet-sensor Docker healthchecks.
#
# Usage:
#   ./scripts/verify-pi-stack-health.sh
#   ./scripts/verify-pi-stack-health.sh -f docker-compose.yml -f docker-compose.pi4.yml ...
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

COMPOSE_ARGS=()
if [[ $# -gt 0 ]]; then
  COMPOSE_ARGS=("$@")
else
  COMPOSE_ARGS=(
    -f docker-compose.yml
    -f docker-compose.pi4.yml
    -f docker-compose.lab-61850.yml
    -f docker-compose.pi-lab.yml
    -f docker-compose.pi-reliability.yml
  )
fi

pass() { echo "PASS  $*"; }
fail() { echo "FAIL  $*" >&2; FAILED=1; }

FAILED=0
SERVICES=(sensel-edge-agent sensel-edge-console sensel-packet-sensor)

echo "==> Pi stack health (compose ${COMPOSE_ARGS[*]})"

for name in "${SERVICES[@]}"; do
  if ! docker inspect "$name" >/dev/null 2>&1; then
    fail "${name} container missing"
    continue
  fi
  running="$(docker inspect -f '{{.State.Status}}' "$name" 2>/dev/null || echo missing)"
  health="$(docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}' "$name" 2>/dev/null || echo unknown)"
  if [[ "$running" != "running" ]]; then
    fail "${name} status=${running}"
    continue
  fi
  if [[ "$health" == "healthy" ]]; then
    pass "${name} healthy"
  elif [[ "$health" == "none" ]]; then
    fail "${name} has no healthcheck (add docker-compose.pi-reliability.yml)"
  else
    fail "${name} health=${health}"
  fi
done

if [[ -f data/agent/agent-runtime.json ]]; then
  pass "agent-runtime.json present"
else
  fail "agent-runtime.json missing"
fi

if [[ $FAILED -eq 0 ]]; then
  echo "==> All Pi stack health checks passed"
  exit 0
fi
echo "==> Pi stack health checks failed" >&2
exit 1
