#!/usr/bin/env bash
# One-time appliance wiring — run while BUILDING the golden image (as a sudo-capable
# user). Installs the systemd units that make the VM self-start the SenseL stack,
# self-provision identity on first boot, and advertise sensel.local.
#
#   sudo ./deploy/appliance/install-appliance.sh
#
# After this + `prepare-image.sh`, the exported VM will, on first boot:
#   1) regenerate machine-id / SSH keys / SENSOR_ID  (sensel-firstboot.service)
#   2) set promisc on the capture NIC                (sensel-promisc.service)
#   3) advertise sensel.local + bring the stack up   (avahi + sensel-edge.service)
set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
  echo "Run as root (sudo)." >&2
  exit 1
fi

APP_DIR="${APP_DIR:-/home/sensel/sensel-ot-edge-sensor}"
UNIT_SRC="${APP_DIR}/deploy/appliance"
SYSTEMD_DIR="/etc/systemd/system"

echo "==> Ensuring Docker starts on boot"
systemctl enable docker >/dev/null 2>&1 || true

echo "==> Marking helper scripts executable"
chmod +x "${UNIT_SRC}/firstboot.sh" "${UNIT_SRC}/set-promisc.sh" \
  "${UNIT_SRC}/gen-banner.sh" "${UNIT_SRC}/prepare-image.sh" \
  "${UNIT_SRC}/build-image.sh" 2>/dev/null || true

echo "==> Installing systemd units"
for unit in sensel-edge.service sensel-firstboot.service sensel-promisc.service sensel-banner.service; do
  install -m 0644 "${UNIT_SRC}/${unit}" "${SYSTEMD_DIR}/${unit}"
  echo "    installed ${unit}"
done

systemctl daemon-reload
echo "==> Enabling units (start on boot)"
systemctl enable sensel-firstboot.service sensel-promisc.service sensel-banner.service sensel-edge.service

cat <<EOF

==> Appliance wiring installed.
    Pre-built images are expected in the local Docker cache (run a build once
    before exporting the image):
      cd ${APP_DIR}
      docker compose -f docker-compose.yml -f docker-compose.minimal-edgex.yml build

    Before exporting/distributing the VM, run:
      sudo ${UNIT_SRC}/prepare-image.sh
EOF
