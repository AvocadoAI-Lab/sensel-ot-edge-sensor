#!/usr/bin/env bash
# Verify attack detection coverage OT-001 ~ OT-018.
#   1. Always: deterministic offline self-test (no live capture needed).
#   2. If the live attack-lab is running: report which rules actually fired.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

log() { printf '==> %s\n' "$*"; }

run_selftest() {
  if python3 -c "import scapy" >/dev/null 2>&1; then
    log "Running offline attack-coverage self-test (host Python)"
    python3 "$ROOT/scripts/attacks-selftest.py"
    return
  fi
  if docker inspect -f '{{.State.Status}}' sensel-packet-sensor 2>/dev/null | grep -q running; then
    log "Running offline attack-coverage self-test (packet-sensor container)"
    docker run --rm -v "$ROOT:/repo:ro" -w /repo \
      --entrypoint python sensel-ot-edge-sensor-packet-sensor \
      scripts/attacks-selftest.py
    return
  fi
  echo "scapy not available on host and sensel-packet-sensor is not running" >&2
  echo "Install: pip3 install scapy   OR   start stack: make up-attack-lab" >&2
  exit 1
}

run_selftest

EVENTS_FILE="${ASSETS_DIR:-./data/assets}/security-events.jsonl"
if [[ -f "$EVENTS_FILE" ]] && command -v python3 >/dev/null 2>&1; then
  log "Live security events present: $EVENTS_FILE"
  python3 - "$EVENTS_FILE" <<'PY'
import json, sys
path = sys.argv[1]
fired = {}
with open(path, encoding="utf-8") as f:
    for line in f:
        line = line.strip()
        if not line:
            continue
        try:
            evt = json.loads(line)
        except json.JSONDecodeError:
            continue
        rid = evt.get("rule_id")
        if rid:
            fired[rid] = fired.get(rid, 0) + 1
print("  live rules fired:")
for rid in sorted(fired):
    print(f"    {rid}: {fired[rid]}")
PY
else
  log "No live event artifacts yet — bring up the lab and fire attacks:"
  log "  make up-attack-lab"
  log "  make attack-all      # OT-001~018 sweep"
  log "  make attack-arp      # real MITM ARP poisoning (isolated lab only!)"
fi

log "Attack detection verification passed"
