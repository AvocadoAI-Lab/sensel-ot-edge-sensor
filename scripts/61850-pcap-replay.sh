#!/usr/bin/env bash
# Replay lab pcap into mirror interface (requires tcpreplay)
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
IFACE="${1:-${CAPTURE_INTERFACE:-eth0}}"
PCAP="${2:-$ROOT/lab/61850/pcap/goose_sample.pcap}"

if ! command -v tcpreplay >/dev/null 2>&1; then
  echo "tcpreplay not installed" >&2
  exit 1
fi
if [[ ! -f "$PCAP" ]]; then
  echo "pcap not found: $PCAP (generate with: python3 lab/61850/generate_sample_pcap.py)" >&2
  exit 1
fi

exec tcpreplay --intf1="$IFACE" "$PCAP"
