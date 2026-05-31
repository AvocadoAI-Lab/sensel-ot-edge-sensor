#!/usr/bin/env bash
# SenseL OT Edge Sensor — Ubuntu install helper
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

echo "==> SenseL OT Edge Sensor install"

if ! command -v docker &>/dev/null; then
  echo "Docker not found. Install: https://docs.docker.com/engine/install/ubuntu/"
  exit 1
fi

[[ -f .env ]] || { cp .env.example .env; echo "Created .env — please edit before production"; }
[[ -f config/sensor.yaml ]] || cp config/sensor.yaml.example config/sensor.yaml
[[ -f config/policy/baseline.json ]] || cp config/policy/baseline.example.json config/policy/baseline.json

mkdir -p data/pcap data/assets data/agent logs

echo "==> Ready. Next: edit .env && docker compose up -d"
