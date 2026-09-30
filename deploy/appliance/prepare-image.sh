#!/usr/bin/env bash
# Sanitize the appliance right BEFORE exporting/distributing the VM image.
# Removes per-device identity + runtime state so every downloaded copy boots
# clean and re-provisions itself (see firstboot.sh). Keeps the .env template and
# pre-built Docker images.
#
#   sudo ./deploy/appliance/prepare-image.sh
#
# WARNING: do NOT run this on a live production sensor — it wipes runtime data,
# the machine-id and SSH host keys. Intended only for the image-builder box.
set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
  echo "Run as root (sudo)." >&2
  exit 1
fi

APP_DIR="${APP_DIR:-/home/sensel/sensel-ot-edge-sensor}"
GOLDEN_SENSOR_ID="ot-edge-golden"

echo "==> Stopping the stack (keeping images)"
( cd "${APP_DIR}" && sudo -u sensel docker compose \
    -f docker-compose.yml -f docker-compose.minimal-edgex.yml down ) || true

echo "==> Clearing runtime data (pcap / events / offsets / console config)"
rm -rf "${APP_DIR}/data/pcap/"* 2>/dev/null || true
rm -f  "${APP_DIR}/data/assets/"*.jsonl 2>/dev/null || true
rm -f  "${APP_DIR}/data/agent/"*.offset 2>/dev/null || true
rm -f  "${APP_DIR}/data/agent/platform.json" 2>/dev/null || true
rm -f  "${APP_DIR}/data/agent/capture.env" 2>/dev/null || true
rm -f  "${APP_DIR}/data/agent/mqtt-credentials.json" 2>/dev/null || true
rm -rf "${APP_DIR}/data/agent/tls/"* 2>/dev/null || true
rm -rf "${APP_DIR}/logs/"* 2>/dev/null || true

echo "==> Resetting SENSOR_ID to golden placeholder (firstboot will randomise)"
if [[ -f "${APP_DIR}/.env" ]] && grep -qE '^SENSOR_ID=' "${APP_DIR}/.env"; then
  sed -i -E "s|^SENSOR_ID=.*|SENSOR_ID=${GOLDEN_SENSOR_ID}|" "${APP_DIR}/.env"
fi

echo "==> Removing machine-id + SSH host keys (regenerated on first boot)"
truncate -s 0 /etc/machine-id || true
rm -f /var/lib/dbus/machine-id || true
rm -f /etc/ssh/ssh_host_*_key /etc/ssh/ssh_host_*_key.pub || true

echo "==> Clearing first-boot marker, shell history, apt cache"
rm -f /var/lib/sensel/firstboot.done || true
rm -f /root/.bash_history /home/sensel/.bash_history 2>/dev/null || true
apt-get clean 2>/dev/null || true
cloud-init clean --logs 2>/dev/null || true

echo "==> Image prepared. Power off now and export the VM:"
echo "    sudo poweroff"
