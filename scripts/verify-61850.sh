#!/usr/bin/env bash
# Verify IEC 61850 passive pipeline (S1-02b)
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

log() { printf '==> %s\n' "$*"; }

run_selftest() {
  if python3 -c "import scapy" >/dev/null 2>&1; then
    log "Running offline parser self-test (host Python)"
    python3 "$ROOT/scripts/61850-selftest.py"
    return
  fi

  if docker inspect -f '{{.State.Status}}' sensel-packet-sensor 2>/dev/null | grep -q running; then
    log "Running offline parser self-test (packet-sensor container)"
    docker run --rm \
      -v "$ROOT:/repo:ro" \
      -w /repo \
      --entrypoint python \
      sensel-ot-edge-sensor-packet-sensor \
      scripts/61850-selftest.py
    return
  fi

  echo "scapy not available on host and sensel-packet-sensor is not running" >&2
  echo "Install: pip3 install scapy   OR   start stack: make up-lab-61850" >&2
  exit 1
}

run_selftest

ASSETS_DIR="${ASSETS_DIR:-./data/assets}"
GOOSE_SUMMARY="$ASSETS_DIR/iec61850-goose-summary.json"
MMS_SUMMARY="$ASSETS_DIR/iec61850-mms-summary.json"
EVENTS_FILE="$ASSETS_DIR/security-events.jsonl"

if docker inspect -f '{{.State.Status}}' sensel-packet-sensor >/dev/null 2>&1; then
  log "packet-sensor container: $(docker inspect -f '{{.State.Status}}' sensel-packet-sensor)"
  if docker inspect -f '{{.State.Status}}' sensel-goose-publisher >/dev/null 2>&1; then
    log "goose-publisher: $(docker inspect -f '{{.State.Status}}' sensel-goose-publisher)"
  fi
  if docker inspect -f '{{.State.Status}}' sensel-mms-publisher >/dev/null 2>&1; then
    log "mms-publisher: $(docker inspect -f '{{.State.Status}}' sensel-mms-publisher)"
  fi
fi

if [[ -f "$GOOSE_SUMMARY" ]]; then
  log "Live GOOSE summary present: $GOOSE_SUMMARY"
  if command -v python3 >/dev/null 2>&1; then
    python3 - <<PY
import json, sys
with open("$GOOSE_SUMMARY") as f:
    s = json.load(f)
count = s.get("goose_message_count", 0)
print(f"  goose_message_count={count}")
if count < 1:
    print("WARN: expected goose_message_count >= 1 in live lab", file=sys.stderr)
PY
  fi
fi
if [[ -f "$MMS_SUMMARY" ]]; then
  log "Live MMS summary present: $MMS_SUMMARY"
  if command -v python3 >/dev/null 2>&1; then
    python3 - <<PY
import json, sys
with open("$MMS_SUMMARY") as f:
    s = json.load(f)
count = s.get("mms_write_count", 0)
print(f"  mms_write_count={count}")
if count < 1:
    print("WARN: expected mms_write_count >= 1 in live lab", file=sys.stderr)
PY
  fi
fi
if [[ -f "$EVENTS_FILE" ]]; then
  log "Live security events present: $EVENTS_FILE"
fi

if [[ ! -f "$GOOSE_SUMMARY" && ! -f "$MMS_SUMMARY" && ! -f "$EVENTS_FILE" ]]; then
  log "No live capture artifacts yet (offline self-test validated parser path)"
  log "Live lab: make up-lab-61850  (GOOSE + MMS publishers on eth0)"
fi

log "IEC 61850 verification passed"
