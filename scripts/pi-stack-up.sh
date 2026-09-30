#!/usr/bin/env bash
# Start Pi lab stack with upstream wait, reliability overlay, and EdgeX 61850 profile.
#
# Usage (on Pi):
#   cd ~/sensel-ot-edge-sensor
#   ./scripts/pi-stack-up.sh
#   DEPLOY_PROFILE=production ./scripts/pi-stack-up.sh
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

PROFILE="${DEPLOY_PROFILE:-lab}"
COMPOSE_FILES="-f docker-compose.yml -f docker-compose.pi4.yml -f docker-compose.lab-61850.yml -f docker-compose.pi-reliability.yml"
if [[ "$PROFILE" == "production" ]]; then
  COMPOSE_FILES="${COMPOSE_FILES} -f docker-compose.pi-production.yml"
else
  COMPOSE_FILES="${COMPOSE_FILES} -f docker-compose.pi-lab.yml"
fi

chmod +x scripts/*.sh 2>/dev/null || true
./scripts/seed-pi-env.sh
./scripts/wait-for-upstream.sh

echo "==> docker compose up (${PROFILE})"
# shellcheck disable=SC2086
docker compose ${COMPOSE_FILES} up -d --build

if [[ -x ./scripts/apply-lab-61850-edgex.sh ]]; then
  ./scripts/apply-lab-61850-edgex.sh
fi

if [[ -x ./scripts/verify-pi-stack-health.sh ]]; then
  ./scripts/verify-pi-stack-health.sh ${COMPOSE_FILES}
fi
