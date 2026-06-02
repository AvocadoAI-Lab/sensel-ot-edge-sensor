#!/usr/bin/env bash
# Seed approved lab IoC on 108 for Track B correlate + feed (B-S4 prep).
#
# Creates workforce IoC draft with taiwan-supply-chain tag so SMB feed on-demand
# includes the test IP. Default IP: 203.0.113.99 (RFC5737 TEST-NET-3).
#
# Usage:
#   export SSHPASS='avocado@@'
#   ./scripts/seed-track-b-lab-ioc.sh
#   TRACK_B_TEST_IOC_IP=192.168.10.88 ./scripts/seed-track-b-lab-ioc.sh
#
set -euo pipefail

SENSEL_HOST="${SENSEL_HOST:-192.168.1.108}"
SENSEL_USER="${SENSEL_USER:-ubuntu}"
SENSEL_REMOTE_DIR="${SENSEL_REMOTE_DIR:-/home/ubuntu/guacamole-ai}"
TEST_IP="${TRACK_B_TEST_IOC_IP:-203.0.113.99}"
TENANT="${POLICY_SYNC_TENANT_ID:-sensel-platform}"
API_KEY="${SMB_INTEL_API_KEY:-}"

if [[ -z "${SSHPASS:-}" ]]; then
  echo "Set SSHPASS for 108 SSH (lab: export SSHPASS='avocado@@')" >&2
  exit 2
fi

SSH=(sshpass -e ssh -o StrictHostKeyChecking=no "${SENSEL_USER}@${SENSEL_HOST}")

echo "==> Seeding approved IoC ${TEST_IP} on ${SENSEL_HOST}"
"${SSH[@]}" "TRACK_B_TEST_IOC_IP=${TEST_IP} POLICY_SYNC_TENANT_ID=${TENANT}" bash -s <<REMOTE
set -euo pipefail
cd "${SENSEL_REMOTE_DIR}"
docker compose exec -T \
  -e TRACK_B_TEST_IOC_IP="${TEST_IP}" \
  -e POLICY_SYNC_TENANT_ID="${TENANT}" \
  api python3 <<'PY'
import os
from datetime import datetime

from sensel_control_plane.models.workforce import DraftStatus, IoCDraft, IoCType, TlpLevel
from sensel_control_plane.repository.workforce_repository import WorkforceRepository

test_ip = os.environ.get("TRACK_B_TEST_IOC_IP", "203.0.113.99")
repo = WorkforceRepository()
existing = repo.get_ioc_by_type_and_value(ioc_type=IoCType.IP, value=test_ip)
if existing and existing.id:
    print(f"exists id={existing.id} value={existing.value} status={existing.status}")
else:
    now = datetime.utcnow()
    draft = IoCDraft(
        type=IoCType.IP,
        value=test_ip,
        severity=85,
        confidence=90,
        tlp=TlpLevel.AMBER,
        source="track-b-lab-seed",
        tags=["taiwan-supply-chain", "track-b-lab"],
        status=DraftStatus.APPROVED,
        first_seen=now,
        last_seen=now,
    )
    created = repo.insert_ioc_draft(draft)
    print(f"created id={created.id} value={created.value}")

from sensel_control_plane.channels.feed_store import get_feed_store
from sensel_control_plane.channels.smb_intel_blacklist import build_and_store_smb_intel_blacklist

tenant = os.environ.get("POLICY_SYNC_TENANT_ID", "sensel-platform")
artifact = build_and_store_smb_intel_blacklist(tenant, get_feed_store())
print(f"feed rebuilt version={artifact.version} items={len(artifact.items)}")
PY
echo "==> Restart API to reload in-memory feed store"
docker compose restart api
sleep 8
REMOTE

if [[ -n "$API_KEY" ]]; then
  echo "==> Refresh feed artifact for tenant ${TENANT}"
  curl -sf -H "X-API-Key: ${API_KEY}" \
    "http://${SENSEL_HOST}:8081/api/v1/feed/${TENANT}/blacklist.json" \
    | python3 -c "import json,sys; d=json.load(sys.stdin); ips=[i.get('value') for i in d.get('items',[]) if str(i.get('ioc_type','')).lower() in ('ip','ipv4')]; print('feed ipv4 items:', len(ips)); print('test ip present:', '${TEST_IP}' in ips)"
else
  echo "Tip: set SMB_INTEL_API_KEY to verify feed includes ${TEST_IP}"
fi

echo "==> Seed complete."
echo "    Pi: wait POLICY_SYNC_INTERVAL_SEC or restart sensel-edge-agent"
echo "    Verify: ./scripts/verify-track-b-e2e.sh [--expect-correlate --probe-ip ${TEST_IP}]"
