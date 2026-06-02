#!/usr/bin/env bash
# Track B Lab E2E (B-S4): feed → Pi cache → OT-019 → sighting → optional correlate.
#
# Required:
#   SMB_INTEL_API_KEY          Portal 情資 API Key
#
# Optional:
#   SENSEL_API_URL             default http://192.168.1.108:8081
#   POLICY_SYNC_TENANT_ID      default sensel-platform
#   TRACK_B_TEST_IOC_IP        default 203.0.113.99
#   PI_TARGET                  default edgex@192.168.1.123
#   SSHPASS                    Pi SSH password (lab: edgex)
#
# Examples:
#   export SMB_INTEL_API_KEY='...'
#   ./scripts/verify-track-b-e2e.sh
#   ./scripts/seed-track-b-lab-ioc.sh && ./scripts/verify-track-b-e2e.sh --expect-correlate
#
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

if [[ -z "${SMB_INTEL_API_KEY:-}" ]]; then
  echo "Set SMB_INTEL_API_KEY (Portal 情資 API Key)" >&2
  exit 2
fi

exec python3 "$ROOT/scripts/verify_track_b_e2e.py" "$@"
