#!/usr/bin/env bash
# Verify Sprint 2 MVP detection + event upload path
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

log() { printf '==> %s\n' "$*"; }

log "Running offline MVP self-test"
python3 "$ROOT/scripts/mvp-selftest.py"

ASSETS_DIR="${ASSETS_DIR:-./data/assets}"
EVENTS_FILE="$ASSETS_DIR/security-events.jsonl"

if [[ -f "$EVENTS_FILE" ]]; then
  log "Live security events present: $EVENTS_FILE"
  python3 - <<PY
import json
from pathlib import Path
lines = [l for l in Path("$EVENTS_FILE").read_text().splitlines() if l.strip()]
rules = set()
for line in lines[-20:]:
    rules.add(json.loads(line).get("rule_id"))
print("  recent rule_ids:", ", ".join(sorted(r for r in rules if r)))
PY
else
  log "No live security-events.jsonl yet (offline self-test validated detection path)"
fi

if docker inspect -f '{{.State.Status}}' sensel-edge-agent >/dev/null 2>&1; then
  log "edge-agent: $(docker inspect -f '{{.State.Status}}' sensel-edge-agent)"
fi

log "Sprint 2 MVP verification passed"
