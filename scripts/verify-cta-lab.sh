#!/usr/bin/env bash
# CTA PoC lab acceptance: Layer C coverage API, aggregator health, CP health.
#
# Usage:
#   export TENANT_ID=company-a9ae1234648ee138
#   export LAYERC_URL=http://192.168.1.203:8001
#   export CONTROL_PLANE_BASE_URL=http://192.168.1.108:8081
#   ./scripts/verify-cta-lab.sh
#
set -euo pipefail

LAYERC_URL="${LAYERC_URL:-http://192.168.1.203:8001}"
CONTROL_PLANE_BASE_URL="${CONTROL_PLANE_BASE_URL:-http://192.168.1.108:8081}"
TENANT_ID="${TENANT_ID:-company-a9ae1234648ee138}"
CP_TARGET="${CP_TARGET:-avocado.ai@192.168.1.203}"
SENSEL_HOST="${SENSEL_HOST:-192.168.1.108}"
STRICT="${CTA_VERIFY_STRICT:-0}"

failures=0
warn() { echo "WARN: $*" >&2; }
fail() { echo "FAIL: $*" >&2; failures=$((failures + 1)); }

echo "==> CTA lab verify tenant=${TENANT_ID}"

# Layer C health
if curl -sf --max-time 8 "${LAYERC_URL}/health" >/dev/null; then
  echo "OK  Layer C health ${LAYERC_URL}/health"
else
  fail "Layer C health unreachable at ${LAYERC_URL}/health"
fi

# Layer C coverage JSON
coverage_json=""
if coverage_json="$(curl -sf --max-time 12 "${LAYERC_URL}/api/cta/coverage?tenant_id=${TENANT_ID}" 2>/dev/null)"; then
  echo "OK  GET /api/cta/coverage"
else
  fail "GET /api/cta/coverage failed"
fi

if [[ -n "$coverage_json" ]]; then
  if command -v python3 >/dev/null 2>&1; then
    python3 - <<'PY' "$coverage_json" || fail "coverage JSON schema check failed"
import json, sys
data = json.loads(sys.argv[1])
summary = data.get("summary")
if not isinstance(summary, dict):
    raise SystemExit("missing summary object")
for key in ("detected", "total", "fully_covered", "gaps"):
    if key not in summary:
        raise SystemExit(f"missing summary.{key}")
techniques = data.get("techniques")
if not isinstance(techniques, list):
    raise SystemExit("missing techniques array")
print(f"  summary: detected={summary.get('detected')} fully_covered={summary.get('fully_covered')} gaps={len(summary.get('gaps') or [])}")
PY
  else
    echo "  (skip JSON schema — python3 unavailable)"
  fi
fi

# CP health
if curl -sf --max-time 8 "${CONTROL_PLANE_BASE_URL}/api/health" >/dev/null; then
  echo "OK  CP health ${CONTROL_PLANE_BASE_URL}/api/health"
else
  fail "CP health unreachable at ${CONTROL_PLANE_BASE_URL}/api/health"
fi

# Aggregator container health (optional when SSH available)
if [[ -n "${SSHPASS:-}" ]] && command -v sshpass >/dev/null 2>&1; then
  agg_status="$(sshpass -e ssh -o StrictHostKeyChecking=accept-new -o PreferredAuthentications=password -o PubkeyAuthentication=no \
    "${CP_TARGET}" 'docker inspect -f "{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}" layera-cta-coverage-aggregator 2>/dev/null || echo missing' 2>/dev/null || echo skip)"
  case "$agg_status" in
    healthy) echo "OK  cta-coverage-aggregator healthy" ;;
    skip|missing) warn "cta-coverage-aggregator not checked (${agg_status})" ;;
    *) fail "cta-coverage-aggregator status=${agg_status}" ;;
  esac
else
  warn "SSHPASS unset — skipping aggregator container check"
fi

if [[ "$failures" -gt 0 ]]; then
  echo "==> CTA verify FAILED (${failures} checks)" >&2
  exit 1
fi

echo "==> CTA verify PASSED"
exit 0
