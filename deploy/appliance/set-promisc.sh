#!/usr/bin/env bash
# Set promiscuous mode on the capture interface. Run by sensel-promisc.service
# on every boot. Reads CAPTURE_INTERFACE from the app .env; if unset/missing,
# uses the default-route interface.
set -euo pipefail

APP_DIR="${APP_DIR:-/home/sensel/sensel-ot-edge-sensor}"
ENV_FILE="${APP_DIR}/.env"

IFACE=""
if [[ -f "${ENV_FILE}" ]]; then
  IFACE="$(grep -E '^CAPTURE_INTERFACE=' "${ENV_FILE}" | tail -1 | cut -d= -f2- | tr -d '[:space:]')"
fi
if [[ -z "${IFACE}" ]]; then
  IFACE="$(ip route show default 2>/dev/null | awk '/default/ {print $5; exit}')"
fi
if [[ -z "${IFACE}" ]]; then
  echo "set-promisc: no capture interface resolved; skipping" >&2
  exit 0
fi

if ip link show "${IFACE}" >/dev/null 2>&1; then
  ip link set "${IFACE}" promisc on
  echo "set-promisc: promiscuous mode enabled on ${IFACE}"
else
  echo "set-promisc: interface ${IFACE} not found; skipping" >&2
fi
