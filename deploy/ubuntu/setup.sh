#!/usr/bin/env bash
# Ubuntu edge host preparation
set -euo pipefail

echo "==> Ubuntu setup for SenseL OT Edge Sensor"

# Docker group
if groups | grep -q docker; then
  echo "User already in docker group"
else
  echo "Add user to docker: sudo usermod -aG docker \$USER && newgrp docker"
fi

# Promiscuous on mirror NIC (override via MIRROR_IFACE env)
MIRROR_IFACE="${MIRROR_IFACE:-eth1}"
if ip link show "$MIRROR_IFACE" &>/dev/null; then
  sudo ip link set "$MIRROR_IFACE" promisc on
  echo "Promisc enabled on $MIRROR_IFACE"
else
  echo "Warning: $MIRROR_IFACE not found — set MIRROR_IFACE before re-run"
fi

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
"$SCRIPT_DIR/../../scripts/install.sh"
