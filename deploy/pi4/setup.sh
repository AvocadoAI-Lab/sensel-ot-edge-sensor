#!/usr/bin/env bash
# Raspberry Pi 4 preparation
set -euo pipefail

echo "==> Pi4 setup for SenseL OT Edge Sensor"

# Increase vm.min_free_kbytes if low memory (optional tuning)
# echo 8192 | sudo tee /proc/sys/vm/min_free_kbytes

MIRROR_IFACE="${MIRROR_IFACE:-eth1}"
if ip link show "$MIRROR_IFACE" &>/dev/null; then
  sudo ip link set "$MIRROR_IFACE" promisc on
fi

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

export DEPLOY_TARGET=pi4
./scripts/install.sh

echo "==> Start with: make up-pi4"
