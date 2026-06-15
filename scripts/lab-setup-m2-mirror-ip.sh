#!/usr/bin/env bash
# Lab M2 實機：在 108 (agent 003) 加上 mirror 次要 IP，觸發 syscollector 更新。
#
# 用途：讓 topology mirror 資產 192.168.10.88 可透過 M2_syscollector_netaddr match agent 003。
#
# Usage:
#   SSHPASS=avocado@@ ./scripts/lab-setup-m2-mirror-ip.sh
#   M2_MIRROR_OT_IP=192.168.10.88 M2_LAB_SSH_HOST=192.168.1.108 ./scripts/lab-setup-m2-mirror-ip.sh
#   M2_PERSIST_NETPLAN=1 SSHPASS=avocado@@ ./scripts/lab-setup-m2-mirror-ip.sh
#
set -euo pipefail

HOST="${M2_LAB_SSH_HOST:-192.168.1.108}"
USER="${M2_LAB_SSH_USER:-ubuntu}"
PASS="${SSHPASS:-avocado@@}"
IFACE="${M2_LAB_NET_IFACE:-ens33}"
MIRROR_IP="${M2_MIRROR_OT_IP:-192.168.10.88}"
PREFIX="${M2_MIRROR_PREFIX:-24}"

echo "==> Lab M2 setup: add ${MIRROR_IP}/${PREFIX} on ${USER}@${HOST}:${IFACE}"

NETPLAN_BODY=$(cat <<YAML
network:
  version: 2
  ethernets:
    ${IFACE}:
      addresses:
        - ${MIRROR_IP}/${PREFIX}
YAML
)

sshpass -p "$PASS" ssh -o StrictHostKeyChecking=accept-new "${USER}@${HOST}" bash -s <<EOF
set -euo pipefail
IFACE='${IFACE}'
MIRROR_IP='${MIRROR_IP}'
PREFIX='${PREFIX}'
SUDO_PASS='${PASS}'
PERSIST_NETPLAN='${M2_PERSIST_NETPLAN:-0}'
DROPIN='/etc/netplan/99-sensel-m2-mirror.yaml'

sudo_cmd() { echo "\$SUDO_PASS" | sudo -S "\$@"; }

if ip -4 addr show dev "\$IFACE" | grep -q "inet \${MIRROR_IP}/"; then
  echo "OK  alias \${MIRROR_IP} already on \$IFACE"
else
  sudo_cmd ip addr add "\${MIRROR_IP}/\${PREFIX}" dev "\$IFACE" 2>/dev/null || true
  echo "OK  added \${MIRROR_IP}/\${PREFIX} on \$IFACE"
fi
ip -4 addr show dev "\$IFACE" | grep 'inet ' || true

if [ "\$PERSIST_NETPLAN" = "1" ]; then
  if [ -s "\$DROPIN" ] && grep -q "\${MIRROR_IP}/\${PREFIX}" "\$DROPIN" 2>/dev/null; then
    echo "OK  netplan drop-in already has \${MIRROR_IP}/\${PREFIX}"
  else
    tmp_dropin="\$(mktemp)"
    cat > "\$tmp_dropin" <<'NETPLAN'
${NETPLAN_BODY}
NETPLAN
    sudo_cmd cp "\$tmp_dropin" "\$DROPIN"
    rm -f "\$tmp_dropin"
    sudo_cmd chmod 600 "\$DROPIN"
    if command -v netplan >/dev/null 2>&1; then
      sudo_cmd netplan apply
      echo "OK  netplan apply (\$DROPIN)"
    else
      echo "WARN netplan not found — drop-in written but not applied"
    fi
  fi
  if [ ! -s "\$DROPIN" ]; then
    echo "FAIL netplan drop-in empty" >&2
    exit 1
  fi
fi

if command -v systemctl >/dev/null 2>&1 && systemctl is-active wazuh-agent >/dev/null 2>&1; then
  sudo_cmd systemctl restart wazuh-agent
  echo "OK  restarted wazuh-agent"
elif [ -x /var/ossec/bin/wazuh-control ]; then
  sudo_cmd /var/ossec/bin/wazuh-control restart
  echo "OK  restarted wazuh-control"
else
  echo "WARN wazuh-agent service not found — wait for next syscollector scan"
fi

if command -v docker >/dev/null 2>&1; then
  if docker ps --format '{{.Names}}' | grep -q sensel-control-plane-api; then
    docker restart sensel-control-plane-api
    echo "OK  restarted sensel-control-plane-api (clear M2 cache)"
  fi
fi
EOF

echo "==> Wait 15s for agent syscollector + API health"
sleep 15
if curl -sf "http://${HOST}:8081/api/health" >/dev/null; then
  echo "OK  CP health"
else
  echo "WARN CP health not ready yet"
fi

echo "==> Next: ./scripts/verify-topology-m2-ingest-lab.sh --expect-agent-id 003"
