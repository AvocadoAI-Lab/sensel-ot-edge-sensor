#!/usr/bin/env bash
# SenseL appliance first-boot provisioning. Runs ONCE (guarded by a done-marker)
# on the first boot of a freshly cloned/downloaded image. Gives each deployed
# unit a distinct identity and advertises it on the LAN as sensel.local.
#
# Idempotent + self-disabling: writes /var/lib/sensel/firstboot.done at the end.
# Must run as root (systemd unit).
set -euo pipefail

MARKER="/var/lib/sensel/firstboot.done"
APP_DIR="${APP_DIR:-/home/sensel/sensel-ot-edge-sensor}"
ENV_FILE="${APP_DIR}/.env"
GOLDEN_SENSOR_ID="ot-edge-golden"

if [[ -f "${MARKER}" ]]; then
  echo "firstboot: already provisioned; skipping"
  exit 0
fi
mkdir -p /var/lib/sensel

echo "==> [1/4] Regenerating machine-id"
rm -f /etc/machine-id /var/lib/dbus/machine-id
systemd-machine-id-setup
ln -sf /etc/machine-id /var/lib/dbus/machine-id 2>/dev/null || true
MID="$(cat /etc/machine-id 2>/dev/null || echo unknown)"

echo "==> [2/4] Ensuring unique SSH host keys"
if ! ls /etc/ssh/ssh_host_*_key >/dev/null 2>&1; then
  ssh-keygen -A
  systemctl try-restart ssh sshd 2>/dev/null || true
  echo "    regenerated SSH host keys"
else
  echo "    host keys present; leaving as-is"
fi

echo "==> [3/4] Assigning unique SENSOR_ID"
if [[ -f "${ENV_FILE}" ]]; then
  CUR="$(grep -E '^SENSOR_ID=' "${ENV_FILE}" | tail -1 | cut -d= -f2- | tr -d '[:space:]')"
  if [[ -z "${CUR}" || "${CUR}" == "${GOLDEN_SENSOR_ID}" ]]; then
    NEW="ot-edge-${MID:0:8}"
    if grep -qE '^SENSOR_ID=' "${ENV_FILE}"; then
      sed -i -E "s|^SENSOR_ID=.*|SENSOR_ID=${NEW}|" "${ENV_FILE}"
    else
      printf '\nSENSOR_ID=%s\n' "${NEW}" >> "${ENV_FILE}"
    fi
    echo "    SENSOR_ID set to ${NEW}"
  else
    echo "    SENSOR_ID already customised (${CUR}); leaving as-is"
  fi
fi

echo "==> [4/4] Publishing mDNS name sensel.local + advertising Edge Console"
if [[ -x "${APP_DIR}/deploy/avahi/setup-mdns.sh" ]]; then
  MDNS_NAME=sensel "${APP_DIR}/deploy/avahi/setup-mdns.sh" || echo "    (mDNS setup non-fatal failure)"
fi

touch "${MARKER}"
echo "==> First-boot provisioning complete (machine-id=${MID:0:8})."
echo "    Console: http://sensel.local:8090  ·  https://sensel.local:8443"
