<<<<<<< Updated upstream
#!/usr/bin/env bash
# Basic stack health check (local or Pi)
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

COMPOSE_FILES=(
  -f docker-compose.yml
  -f docker-compose.pi4.yml
  -f docker-compose.lab-61850.yml
  -f docker-compose.pi-lab.yml
  -f docker-compose.pi-reliability.yml
)

echo "==> Docker services"
# shellcheck disable=SC2086
docker compose "${COMPOSE_FILES[@]}" ps 2>/dev/null || docker compose ps 2>/dev/null || echo "Compose stack not running"

echo ""
if [[ -x ./scripts/verify-pi-stack-health.sh ]]; then
  ./scripts/verify-pi-stack-health.sh "${COMPOSE_FILES[@]}" || true
fi

echo ""
echo "==> EdgeX Core (61850 lab)"
for c in edgex-core-data edgex-core-metadata edgex-device-mqtt edgex-mqtt-broker; do
  if docker inspect -f '{{.State.Status}}' "$c" >/dev/null 2>&1; then
    echo "  $c: $(docker inspect -f '{{.State.Status}}' "$c")"
  else
    echo "  $c: not found"
  fi
done

echo ""
echo "==> Config"
[[ -f .env ]] && echo "  .env: OK" || echo "  .env: MISSING (run ./scripts/seed-pi-env.sh)"
[[ -f config/sensor.yaml ]] && echo "  sensor.yaml: OK" || echo "  sensor.yaml: using example only"

echo ""
echo "Done."
=======
#!/usr/bin/env bash
# Basic stack health check (local or Pi)
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

COMPOSE_FILES=(
  -f docker-compose.yml
  -f docker-compose.pi4.yml
  -f docker-compose.lab-61850.yml
  -f docker-compose.pi-lab.yml
  -f docker-compose.pi-reliability.yml
)

echo "==> Docker services"
# shellcheck disable=SC2086
docker compose "${COMPOSE_FILES[@]}" ps 2>/dev/null || docker compose ps 2>/dev/null || echo "Compose stack not running"

echo ""
if [[ -x ./scripts/verify-pi-stack-health.sh ]]; then
  ./scripts/verify-pi-stack-health.sh "${COMPOSE_FILES[@]}" || true
fi

echo ""
echo "==> EdgeX Core (61850 lab)"
for c in edgex-core-data edgex-core-metadata edgex-device-mqtt edgex-mqtt-broker; do
  if docker inspect -f '{{.State.Status}}' "$c" >/dev/null 2>&1; then
    echo "  $c: $(docker inspect -f '{{.State.Status}}' "$c")"
  else
    echo "  $c: not found"
  fi
done

echo ""
echo "==> Config"
[[ -f .env ]] && echo "  .env: OK" || echo "  .env: MISSING (run ./scripts/seed-pi-env.sh)"
[[ -f config/sensor.yaml ]] && echo "  sensor.yaml: OK" || echo "  sensor.yaml: using example only"

echo ""
echo "Done."
>>>>>>> Stashed changes
