#!/usr/bin/env bash
# Snort NDR bridge E2E (v0.1): alert_json → SecurityEvent → schema → sighting.
#
# Self-contained: no running stack required. Exercises the packet-sensor Snort
# bridge and the edge-agent sighting builder against a sample Snort alert.
#
# Examples:
#   ./scripts/verify-snort-e2e.sh
#   ./scripts/verify-snort-e2e.sh --json
#
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

exec python3 "$ROOT/scripts/verify_snort_e2e.py" "$@"
