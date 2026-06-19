#!/usr/bin/env bash
# Suricata NDR bridge E2E (v0.1): eve.json → SecurityEvent → schema → sighting.
#
# Self-contained: no running stack required. Exercises the packet-sensor
# Suricata bridge and the edge-agent sighting builder against a sample EVE alert.
#
# Examples:
#   ./scripts/verify-suricata-e2e.sh
#   ./scripts/verify-suricata-e2e.sh --json
#
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

exec python3 "$ROOT/scripts/verify_suricata_e2e.py" "$@"
