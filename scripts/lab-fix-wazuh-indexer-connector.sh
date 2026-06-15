#!/usr/bin/env bash
# Fix Wazuh manager → indexer connector for vulnerability states indexing.
#
# Patches ossec.conf inside the manager container:
#   - indexer host: 0.0.0.0 → wazuh.indexer
#   - SSL cert paths: /etc/filebeat/certs/* → /etc/ssl/* (docker-compose mounts)
#
# Usage:
#   SSHPASS=avocado@@ ./scripts/lab-fix-wazuh-indexer-connector.sh
#
set -euo pipefail

HOST="${M2_LAB_SSH_HOST:-192.168.1.108}"
USER="${M2_LAB_SSH_USER:-ubuntu}"
PASS="${SSHPASS:-avocado@@}"
INDEXER_HOST="${WAZUH_INDEXER_DOCKER_HOST:-wazuh.indexer}"

echo "==> Lab fix: Wazuh manager indexer connector on ${USER}@${HOST}"

sshpass -p "$PASS" ssh -o StrictHostKeyChecking=accept-new "${USER}@${HOST}" bash -s <<EOF
set -euo pipefail
SUDO_PASS='${PASS}'
INDEXER_HOST='${INDEXER_HOST}'
sudo_cmd() { echo "\$SUDO_PASS" | sudo -S "\$@"; }

changed=0
patch_conf() {
  local expr="\$1"
  local label="\$2"
  if docker exec wazuh-manager grep -qE "\$expr" /var/ossec/etc/ossec.conf 2>/dev/null; then
    return 0
  fi
  sudo_cmd docker exec wazuh-manager sed -i "\$expr" /var/ossec/etc/ossec.conf
  echo "OK  patched \$label"
  changed=1
}

# Host
if ! docker exec wazuh-manager grep -q "<host>https://\${INDEXER_HOST}:9200</host>" /var/ossec/etc/ossec.conf; then
  sudo_cmd docker exec wazuh-manager sed -i 's#<host>https://0.0.0.0:9200</host>#<host>https://${INDEXER_HOST}:9200</host>#' /var/ossec/etc/ossec.conf
  echo "OK  patched indexer host → \${INDEXER_HOST}"
  changed=1
else
  echo "OK  indexer host already \${INDEXER_HOST}"
fi

# SSL paths (compose mounts under /etc/ssl)
if docker exec wazuh-manager grep -q '/etc/filebeat/certs/root-ca.pem' /var/ossec/etc/ossec.conf 2>/dev/null; then
  sudo_cmd docker exec wazuh-manager sed -i 's#/etc/filebeat/certs/root-ca.pem#/etc/ssl/root-ca.pem#' /var/ossec/etc/ossec.conf
  echo "OK  patched ssl ca path"
  changed=1
fi
if docker exec wazuh-manager grep -q '/etc/filebeat/certs/filebeat.pem' /var/ossec/etc/ossec.conf 2>/dev/null; then
  sudo_cmd docker exec wazuh-manager sed -i 's#/etc/filebeat/certs/filebeat.pem#/etc/ssl/filebeat.pem#' /var/ossec/etc/ossec.conf
  echo "OK  patched ssl cert path"
  changed=1
fi
if docker exec wazuh-manager grep -q '/etc/filebeat/certs/filebeat-key.pem' /var/ossec/etc/ossec.conf 2>/dev/null; then
  sudo_cmd docker exec wazuh-manager sed -i 's#/etc/filebeat/certs/filebeat-key.pem#/etc/ssl/filebeat.key#' /var/ossec/etc/ossec.conf
  echo "OK  patched ssl key path"
  changed=1
fi

if docker exec wazuh-manager test -f /etc/ssl/filebeat.pem && docker exec wazuh-manager test -f /etc/ssl/filebeat.key; then
  echo "OK  /etc/ssl certs present in manager container"
else
  echo "WARN /etc/ssl certs missing — check docker-compose.wazuh.yml mounts" >&2
fi

if [ "\$changed" = "1" ]; then
  sudo_cmd docker restart wazuh-manager
  echo "OK  restarted wazuh-manager (wait ~45s for indexer-connector)"
else
  echo "OK  ossec.conf already patched"
fi
EOF

echo "==> Waiting 45s for indexer-connector ..."
sleep 45

sshpass -p "$PASS" ssh -o StrictHostKeyChecking=accept-new "${USER}@${HOST}" bash -s <<'REMOTE'
set -euo pipefail
echo "==> indexer-connector log tail"
docker exec wazuh-manager tail -30 /var/ossec/logs/ossec.log 2>/dev/null | grep -iE "indexer-connector|vulnerability-scanner" | tail -12 || true
echo "==> vuln indices"
docker exec wazuh-indexer curl -sk -u admin:admin "https://localhost:9200/_cat/indices/wazuh-states-vulnerabilities*?v" 2>/dev/null || true
REMOTE

echo "==> Done."
