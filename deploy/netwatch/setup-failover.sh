#!/usr/bin/env bash
# Install the SenseL offline-failover watchdog as a systemd timer on the
# appliance host (it needs host nmcli + NetworkManager, so it runs on the host
# rather than in a container). Idempotent; safe to re-run on every deploy.
#
#   sudo WIFI_PRIORITY_FILE=/home/edgex/sensel-ot-edge-sensor/data/agent/wifi-priority.json \
#        ./deploy/netwatch/setup-failover.sh
set -euo pipefail

SRC_DIR="$(cd "$(dirname "$0")" && pwd)"
WIFI_PRIORITY_FILE="${WIFI_PRIORITY_FILE:-/home/edgex/sensel-ot-edge-sensor/data/agent/wifi-priority.json}"
INTERVAL_SEC="${NETWATCH_INTERVAL_SEC:-30}"
FAIL_THRESHOLD="${NETWATCH_FAIL_THRESHOLD:-2}"
BIN="/usr/local/sbin/sensel-net-failover.sh"
UNIT="/etc/systemd/system/sensel-net-failover.service"
TIMER="/etc/systemd/system/sensel-net-failover.timer"

echo "==> Installing failover script -> ${BIN}"
install -m 0755 "${SRC_DIR}/net-failover.sh" "${BIN}"

echo "==> Writing systemd service (priority file: ${WIFI_PRIORITY_FILE})"
cat > "${UNIT}" <<EOF
[Unit]
Description=SenseL offline failover to pinned Wi-Fi
After=NetworkManager.service
Wants=NetworkManager.service

[Service]
Type=oneshot
Environment=WIFI_PRIORITY_FILE=${WIFI_PRIORITY_FILE}
Environment=NETWATCH_FAIL_THRESHOLD=${FAIL_THRESHOLD}
ExecStart=${BIN}
EOF

cat > "${TIMER}" <<EOF
[Unit]
Description=Run SenseL offline failover check every ${INTERVAL_SEC}s

[Timer]
OnBootSec=60
OnUnitActiveSec=${INTERVAL_SEC}
AccuracySec=5s
Unit=sensel-net-failover.service

[Install]
WantedBy=timers.target
EOF

echo "==> Enabling timer"
systemctl daemon-reload
systemctl enable --now sensel-net-failover.timer

echo "==> Done. Check: systemctl status sensel-net-failover.timer ; journalctl -u sensel-net-failover.service -n 20"
