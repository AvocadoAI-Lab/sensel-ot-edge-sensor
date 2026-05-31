#!/usr/bin/env bash
# Basic stack health check
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

echo "==> Docker services"
docker compose ps 2>/dev/null || echo "Compose stack not running"

echo ""
echo "==> Container health"
for c in sensel-edge-agent sensel-packet-sensor sensel-local-mqtt; do
  if docker inspect -f '{{.State.Status}}' "$c" 2>/dev/null; then
    echo "  $c: $(docker inspect -f '{{.State.Status}}' "$c" 2>/dev/null)"
  else
    echo "  $c: not found"
  fi
done

echo ""
echo "==> EdgeX Core services"
for c in edgex-core-data edgex-core-metadata edgex-device-modbus edgex-device-mqtt edgex-mqtt-broker edgex-modbus-simulator; do
  if docker inspect -f '{{.State.Status}}' "$c" 2>/dev/null; then
    echo "  $c: $(docker inspect -f '{{.State.Status}}' "$c" 2>/dev/null)"
  else
    echo "  $c: not found"
  fi
done

echo ""
echo "==> Config"
[[ -f .env ]] && echo "  .env: OK" || echo "  .env: MISSING (cp .env.example .env)"
[[ -f config/sensor.yaml ]] && echo "  sensor.yaml: OK" || echo "  sensor.yaml: using example only"

echo ""
echo "Done."
