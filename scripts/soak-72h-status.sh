#!/usr/bin/env bash
# Show status of a running or completed 72h soak.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SOAK_ROOT="${SOAK_ROOT:-$ROOT/data/soak}"

latest="$(ls -td "$SOAK_ROOT"/72h-* 2>/dev/null | head -1 || true)"
if [[ -z "$latest" ]]; then
  echo "No soak runs under $SOAK_ROOT"
  exit 1
fi

echo "Run: $latest"
if [[ -f "$latest/soak.pid" ]]; then
  pid="$(cat "$latest/soak.pid")"
  if kill -0 "$pid" 2>/dev/null; then
    echo "Status: RUNNING pid=$pid"
  else
    echo "Status: STOPPED (stale pid=$pid)"
  fi
fi

if [[ -f "$latest/summary.json" ]]; then
  cat "$latest/summary.json"
fi

echo ""
echo "Last 8 log lines:"
tail -8 "$latest/soak.log" 2>/dev/null || echo "(no log yet)"
