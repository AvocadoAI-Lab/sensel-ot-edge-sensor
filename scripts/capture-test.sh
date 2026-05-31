#!/usr/bin/env bash
# Quick mirror interface capture test (requires tcpdump on host)
set -euo pipefail

IFACE="${1:-eth1}"
COUNT="${2:-10}"

echo "==> Capture test on $IFACE ($COUNT packets)"
if ! command -v tcpdump &>/dev/null; then
  echo "Install tcpdump: sudo apt install tcpdump"
  exit 1
fi

sudo tcpdump -i "$IFACE" -c "$COUNT" -n 2>&1 || {
  echo "Failed — check interface name and promisc: sudo ip link set $IFACE promisc on"
  exit 1
}

echo "==> Capture test OK"
