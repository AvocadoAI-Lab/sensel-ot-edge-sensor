#!/usr/bin/env bash
# Lab helper: publish OT detection policy via Portal API (MQTT path B).
#
# Usage:
#   PORTAL_URL=http://192.168.1.108:8081 WORKSPACE_ID=6 ./scripts/publish-ot-detection-policy-mqtt.sh
set -euo pipefail

PORTAL_URL="${PORTAL_URL:-http://192.168.1.108:8081}"
WORKSPACE_ID="${WORKSPACE_ID:-6}"
SITE_ID="${SITE_ID:-factory-lab-001}"
TOKEN="${PORTAL_TOKEN:-}"

if [[ -z "$TOKEN" ]]; then
  echo "Set PORTAL_TOKEN (Bearer JWT) or login via Portal first" >&2
  exit 1
fi

auth=(-H "Authorization: Bearer ${TOKEN}" -H "Content-Type: application/json")

echo "==> PUT detection-policy draft (workspace=${WORKSPACE_ID} site=${SITE_ID})"
curl -fsS "${auth[@]}" -X PUT \
  "${PORTAL_URL}/api/v1/smb/workspaces/${WORKSPACE_ID}/ot-security/detection-policy" \
  -d "$(cat <<EOF
{
  "site_id": "${SITE_ID}",
  "rules_enabled": ["OT-011","OT-014","OT-016","OT-018","OT-019"],
  "baseline": {
    "policy_version": "lab-mqtt",
    "iec61850": {
      "mms_ieds": [{
        "asset_id": "ied-lab-01",
        "ied_ip": "192.168.10.50",
        "allowed_mms_clients": ["192.168.10.88", "192.168.10.10", "192.168.10.11"]
      }]
    }
  }
}
EOF
)"

echo ""
echo "==> POST publish (MQTT)"
curl -fsS "${auth[@]}" -X POST \
  "${PORTAL_URL}/api/v1/smb/workspaces/${WORKSPACE_ID}/ot-security/detection-policy/publish?site_id=${SITE_ID}"
echo ""
echo "==> OK"
