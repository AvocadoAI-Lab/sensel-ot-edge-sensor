#!/usr/bin/env bash
# S5-E1: Verify 108 Portal live OT events expose Layer C card fields.
#
# SMB routes require a Portal user JWT (M2M ingest key is not enough).
#
# Required (one of):
#   PORTAL_BEARER_TOKEN   JWT from Portal login
#   PORTAL_EMAIL + PORTAL_PASSWORD
#
# Optional:
#   SENSEL_API_URL        default http://192.168.1.108:8081
#   WORKSPACE_ID          default 6 (Avocado AI company workspace)
#   EXPECT_LLM=1          require llm_enriched + recommended_actions
#
# Usage:
#   export PORTAL_BEARER_TOKEN='eyJ...'
#   ./scripts/verify-portal-layerc.sh
#
#   export PORTAL_EMAIL='admin@example.com' PORTAL_PASSWORD='...'
#   ./scripts/verify-portal-layerc.sh --expect-llm
#
#   ./scripts/verify-portal-layerc.sh --export-json docs/llm-eval-samples.jsonl
#
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SENSEL_API_URL="${SENSEL_API_URL:-http://192.168.1.108:8081}"
WORKSPACE_ID="${WORKSPACE_ID:-6}"
EXPECT_LLM=0
EXPORT_JSON=""
EXTRA=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    --expect-llm) EXPECT_LLM=1; shift ;;
    --export-json=*) EXPORT_JSON="${1#*=}"; shift ;;
    --export-json)
      shift
      EXPORT_JSON="${1:?--export-json requires a path}"
      shift
      ;;
    -h|--help)
      sed -n '2,26p' "$0"
      exit 0
      ;;
    *) EXTRA+=("$1"); shift ;;
  esac
done

ARGS=(
  --portal-url "$SENSEL_API_URL"
  --workspace-id "$WORKSPACE_ID"
)

if [[ -n "${PORTAL_BEARER_TOKEN:-}" ]]; then
  ARGS+=(--token "$PORTAL_BEARER_TOKEN")
fi
if [[ -n "${PORTAL_EMAIL:-}" ]]; then
  ARGS+=(--email "$PORTAL_EMAIL")
fi
if [[ -n "${PORTAL_PASSWORD:-}" ]]; then
  ARGS+=(--password "$PORTAL_PASSWORD")
fi
if [[ "$EXPECT_LLM" == "1" ]]; then
  ARGS+=(--expect-llm)
fi
if [[ -n "$EXPORT_JSON" ]]; then
  mkdir -p "$(dirname "$EXPORT_JSON")"
  ARGS+=(--export-json "$EXPORT_JSON")
fi

chmod +x "$ROOT/scripts/verify_portal_layerc.py" 2>/dev/null || true
if ((${#EXTRA[@]})); then
  exec python3 "$ROOT/scripts/verify_portal_layerc.py" "${ARGS[@]}" "${EXTRA[@]}"
fi
exec python3 "$ROOT/scripts/verify_portal_layerc.py" "${ARGS[@]}"
