#!/usr/bin/env bash
# S5-G1: Sprint 4 one-click lab acceptance gate (108 + 203 + Pi smoke + Layer C + Portal).
#
# Prerequisites:
#   - Lab nodes reachable (108 / 203 / 123)
#   - Portal user JWT: PORTAL_BEARER_TOKEN or PORTAL_EMAIL + PORTAL_PASSWORD
#
# Usage:
#   export SSHPASS='avocado@@'
#   export PORTAL_EMAIL='...' PORTAL_PASSWORD='...'
#   ./scripts/verify-sprint4-lab.sh
#
#   ./scripts/verify-sprint4-lab.sh --skip-pi    # skip Pi SSH checks
#   ./scripts/verify-sprint4-lab.sh --no-llm     # Layer C without LLM gate
#
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CP_ROOT="${ARISTACONNECTOR_PATH:-$(dirname "$ROOT")/Aristaconnector-Control-Plane}"

SENSEL_API_URL="${SENSEL_API_URL:-http://192.168.1.108:8081}"
LAYERC_URL="${LAYERC_URL:-http://192.168.1.203:8001}"
PI_TARGET="${PI_TARGET:-edgex@192.168.1.123}"
WORKSPACE_ID="${WORKSPACE_ID:-6}"
EXPECT_LLM=1
SKIP_PI=0
FAILURES=0

if [[ -f "$ROOT/.env.lab" ]]; then
  set -a
  # shellcheck disable=SC1091
  source "$ROOT/.env.lab"
  set +a
fi

while [[ $# -gt 0 ]]; do
  case "$1" in
    --skip-pi) SKIP_PI=1; shift ;;
    --no-llm) EXPECT_LLM=0; shift ;;
    --expect-llm) EXPECT_LLM=1; shift ;;
    -h|--help)
      sed -n '2,18p' "$0"
      exit 0
      ;;
    *) echo "Unknown arg: $1" >&2; exit 1 ;;
  esac
done

pass() { echo "[PASS] $*"; }
fail() { echo "[FAIL] $*" >&2; FAILURES=$((FAILURES + 1)); }

curl_ok() {
  local name="$1" url="$2"
  if curl -sf --max-time 15 "$url" >/dev/null; then
    pass "$name $url"
  else
    fail "$name unreachable: $url"
  fi
}

echo "==> S5-G1 Sprint 4 lab verify"
echo "    108=${SENSEL_API_URL} 203=${LAYERC_URL} pi=${PI_TARGET} expect_llm=${EXPECT_LLM}"

curl_ok "G1-108-api" "${SENSEL_API_URL}/api/health"
curl_ok "G1-203-layerc" "${LAYERC_URL}/health"

echo "==> G1-203-compose-health (S5-F1)"
if "$ROOT/scripts/verify-203-compose-health.sh"; then
  pass "G1-203-compose-health"
else
  fail "G1-203-compose-health (layerc-api / layerb-worker docker health)"
fi

if [[ "$SKIP_PI" == "0" ]]; then
  PI_PASS="${PI_SSHPASS:-edgex}"
  PI_SSH=(ssh -o StrictHostKeyChecking=no -o ConnectTimeout=8)
  if command -v sshpass >/dev/null 2>&1; then
    export SSHPASS="$PI_PASS"
    PI_SSH=(sshpass -e ssh -o StrictHostKeyChecking=no -o ConnectTimeout=8)
  fi
  if "${PI_SSH[@]}" "$PI_TARGET" 'docker ps --format "{{.Names}}" | grep -q sensel-edge-agent'; then
    pass "G1-pi-edge-agent running"
  else
    fail "G1-pi-edge-agent not running on ${PI_TARGET}"
  fi
  if "${PI_SSH[@]}" "$PI_TARGET" 'test -s ~/sensel-ot-edge-sensor/data/assets/security-events.jsonl'; then
    pass "G1-pi-security-events-jsonl"
  else
    fail "G1-pi-security-events-jsonl missing or empty"
  fi
else
  echo "==> Skipping Pi SSH checks (--skip-pi)"
fi

echo "==> G1-layerc-analyze (${LAYERC_URL})"
[[ -d "$CP_ROOT" ]] || { fail "Control Plane repo missing at $CP_ROOT"; exit 1; }
LAYERC_ARGS=(--layerc-url "$LAYERC_URL" --expect-status ok)
if [[ "$EXPECT_LLM" == "1" ]]; then
  LAYERC_ARGS+=(--expect-llm)
fi
if PYTHONPATH="$CP_ROOT" python3 "$CP_ROOT/scripts/e2e-ot-layerc-analyze.py" "${LAYERC_ARGS[@]}"; then
  pass "G1-layerc-analyze"
else
  fail "G1-layerc-analyze"
fi

echo "==> G1-portal-layerc (${SENSEL_API_URL})"
export SENSEL_API_URL WORKSPACE_ID
if [[ "$EXPECT_LLM" == "1" ]]; then
  if "$ROOT/scripts/verify-portal-layerc.sh" --expect-llm; then
    pass "G1-portal-layerc"
  else
    fail "G1-portal-layerc (set PORTAL_BEARER_TOKEN or PORTAL_EMAIL + PORTAL_PASSWORD)"
  fi
else
  if "$ROOT/scripts/verify-portal-layerc.sh"; then
    pass "G1-portal-layerc"
  else
    fail "G1-portal-layerc (set PORTAL_BEARER_TOKEN or PORTAL_EMAIL + PORTAL_PASSWORD)"
  fi
fi

echo ""
if [[ "$FAILURES" -gt 0 ]]; then
  echo "S5-G1 SPRINT4 LAB VERIFY FAILED (${FAILURES} checks)" >&2
  exit 1
fi
echo "S5-G1 SPRINT4 LAB VERIFY PASS"
exit 0
