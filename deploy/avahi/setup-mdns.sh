#!/usr/bin/env bash
# Publish a branded mDNS / Bonjour name for the appliance and advertise the Edge
# Console over DNS-SD, so operators can reach the box by name without knowing
# its DHCP IP — e.g. http://sensel.local:8090 — the moment it is plugged into a
# switch on the same L2 segment.
#
# The appliance host already runs avahi-daemon (Debian/Pi OS), so we configure
# THAT daemon rather than a container (a second mDNS responder would clash on
# UDP 5353). Run as root on the appliance:
#
#   sudo MDNS_NAME=sensel ./deploy/avahi/setup-mdns.sh
#
# Idempotent: safe to re-run on every deploy.
set -euo pipefail

MDNS_NAME="${MDNS_NAME:-sensel}"
CONSOLE_PORT="${CONSOLE_PORT:-8090}"
CONSOLE_HTTPS_PORT="${CONSOLE_HTTPS_PORT:-8443}"
CONF="/etc/avahi/avahi-daemon.conf"
SVC_DIR="/etc/avahi/services"
SVC="${SVC_DIR}/sensel-console.service"

if [[ "${MDNS_NAME}" =~ [^A-Za-z0-9-] ]]; then
  echo "MDNS_NAME must be a single DNS label (A-Z a-z 0-9 -): '${MDNS_NAME}'" >&2
  exit 1
fi

if ! command -v avahi-daemon >/dev/null 2>&1; then
  echo "==> Installing avahi-daemon"
  apt-get update -qq
  apt-get install -y --no-install-recommends avahi-daemon
fi

echo "==> Setting advertised mDNS name to '${MDNS_NAME}.local'"
cp -n "${CONF}" "${CONF}.bak" 2>/dev/null || true
# host-name (the .local label avahi publishes, independent of the system hostname)
if grep -qE '^[[:space:]]*#?[[:space:]]*host-name=' "${CONF}"; then
  sed -i -E "s|^[[:space:]]*#?[[:space:]]*host-name=.*|host-name=${MDNS_NAME}|" "${CONF}"
else
  sed -i "/^\[server\]/a host-name=${MDNS_NAME}" "${CONF}"
fi
# domain-name
if grep -qE '^[[:space:]]*#?[[:space:]]*domain-name=' "${CONF}"; then
  sed -i -E "s|^[[:space:]]*#?[[:space:]]*domain-name=.*|domain-name=local|" "${CONF}"
else
  sed -i "/^\[server\]/a domain-name=local" "${CONF}"
fi

echo "==> Advertising Edge Console (_http._tcp:${CONSOLE_PORT}, _https._tcp:${CONSOLE_HTTPS_PORT}) for DNS-SD browsers"
mkdir -p "${SVC_DIR}"
cat > "${SVC}" <<EOF
<?xml version="1.0" standalone='no'?>
<!DOCTYPE service-group SYSTEM "avahi-service.dtd">
<service-group>
  <name replace-wildcards="yes">SenseL Edge Console</name>
  <service>
    <type>_https._tcp</type>
    <port>${CONSOLE_HTTPS_PORT}</port>
    <txt-record>path=/</txt-record>
  </service>
  <service>
    <type>_http._tcp</type>
    <port>${CONSOLE_PORT}</port>
    <txt-record>path=/</txt-record>
  </service>
</service-group>
EOF

echo "==> Restarting avahi-daemon"
systemctl enable avahi-daemon >/dev/null 2>&1 || true
systemctl restart avahi-daemon
sleep 1

echo "==> Done."
echo "    HTTPS: https://${MDNS_NAME}.local:${CONSOLE_HTTPS_PORT}  (self-signed)"
echo "    HTTP : http://${MDNS_NAME}.local:${CONSOLE_PORT}"
