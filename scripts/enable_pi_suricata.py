"""Enable Suricata on Pi 4 native stack (one-shot deploy + start)."""
from __future__ import annotations

import os
import sys
from pathlib import Path

import paramiko

PI_HOST = "192.168.50.90"
PI_USER = "fju"
PI_PASS = "0000"
PI_ROOT = "/home/fju/sensel-ot-edge-sensor"
REPO = Path(__file__).resolve().parents[1]

UPLOADS = [
    (REPO / "deploy/pi4/start-suricata.sh", f"{PI_ROOT}/deploy/pi4/start-suricata.sh"),
    (REPO / "deploy/pi4/start-native-edgemed.sh", f"{PI_ROOT}/deploy/pi4/start-native-edgemed.sh"),
    (REPO / "deploy/pi4/start-edge-agent.sh", f"{PI_ROOT}/deploy/pi4/start-edge-agent.sh"),
    (REPO / "config/sensor.pi-edgemed.yaml", f"{PI_ROOT}/config/sensor.pi-edgemed.yaml"),
    (REPO / "config/suricata/suricata.yaml", f"{PI_ROOT}/config/suricata/suricata.yaml"),
    (REPO / "config/suricata/rules/local.rules", f"{PI_ROOT}/config/suricata/rules/local.rules"),
    (REPO / "config/suricata/rules/it-ndr-seed.rules", f"{PI_ROOT}/config/suricata/rules/it-ndr-seed.rules"),
]

REMOTE_ENABLE = rf"""set -euo pipefail
ROOT="{PI_ROOT}"
export PW='{PI_PASS}'
chmod +x "$ROOT/deploy/pi4/start-suricata.sh" "$ROOT/deploy/pi4/start-native-edgemed.sh" "$ROOT/deploy/pi4/start-edge-agent.sh"
mkdir -p "$ROOT/data/suricata" "$ROOT/config/suricata/rules" "$ROOT/data/assets"

echo '==> Docker version'
sudo docker --version || exit 1

echo '==> Start Suricata container'
bash "$ROOT/deploy/pi4/start-suricata.sh"

echo '==> Restart packet-sensor with Suricata bridge'
pkill -f 'packet-sensor/.venv/bin/python -m src.main' 2>/dev/null || true
sudo pkill -f 'python -m src.main' 2>/dev/null || true
sleep 2

PS_DIR="$ROOT/services/packet-sensor"
cd "$PS_DIR"
source .venv/bin/activate
export SENSOR_CONFIG_PATH="$ROOT/config/sensor.pi-edgemed.yaml"
export PYTHONPATH="$PS_DIR"
export CAPTURE_INTERFACE=eth0
export INFERENCE_BACKEND=edgemed
export EDGEMED_BASE_URL=http://127.0.0.1:8000
export EDGEMED_INVESTIGATE_ENABLED=true
export MODEL_INFERENCE_ENABLED=true
export SURICATA_SOURCE_ENABLED=true
export SURICATA_EVE_JSON_PATH="$ROOT/data/suricata/eve.json"
export SURICATA_SOURCE_POLL_SEC=2

sudo -E env \
  SENSOR_CONFIG_PATH="$SENSOR_CONFIG_PATH" \
  PYTHONPATH="$PYTHONPATH" \
  CAPTURE_INTERFACE="$CAPTURE_INTERFACE" \
  INFERENCE_BACKEND="$INFERENCE_BACKEND" \
  EDGEMED_BASE_URL="$EDGEMED_BASE_URL" \
  EDGEMED_INVESTIGATE_ENABLED="$EDGEMED_INVESTIGATE_ENABLED" \
  MODEL_INFERENCE_ENABLED="$MODEL_INFERENCE_ENABLED" \
  SURICATA_SOURCE_ENABLED="$SURICATA_SOURCE_ENABLED" \
  SURICATA_EVE_JSON_PATH="$SURICATA_EVE_JSON_PATH" \
  SURICATA_SOURCE_POLL_SEC="$SURICATA_SOURCE_POLL_SEC" \
  "$PS_DIR/.venv/bin/python" -m src.main >/tmp/packet-sensor.log 2>&1 &
echo $! > /tmp/packet-sensor.pid
sleep 4

echo '==> Restart edge-agent with Suricata health'
bash "$ROOT/deploy/pi4/start-edge-agent.sh"

echo '==> Verification'
sudo docker logs sensel-suricata 2>&1 | grep -E 'Engine started|rules successfully loaded' | tail -3 || true
grep -i suricata /tmp/packet-sensor.log | tail -5 || true
ls -la "$ROOT/data/suricata/" | head -10 || true
tail -1 "$ROOT/data/assets/suricata-events.jsonl" 2>/dev/null || echo '(no suricata-events yet — need OT traffic)'

echo '==> Resource snapshot'
free -h
sudo docker stats --no-stream sensel-suricata 2>/dev/null || true
ps -eo pid,comm,%cpu,rss,args --sort=-rss | grep -E 'llama-server|uvicorn|src.main|suricata' | grep -v grep || true
if [[ -f "$ROOT/data/agent/agent-runtime.json" ]]; then
  python3 -c "import json; d=json.load(open('$ROOT/data/agent/agent-runtime.json')); print([e for e in d.get('engines',[]) if e.get('name')=='suricata'])"
fi
"""


def main() -> int:
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(
        PI_HOST,
        username=PI_USER,
        password=PI_PASS,
        timeout=20,
        look_for_keys=False,
        allow_agent=False,
    )
    sftp = client.open_sftp()

    for local, remote in UPLOADS:
        if not local.is_file():
            print(f"MISSING local: {local}", file=sys.stderr)
            return 1
        remote_dir = os.path.dirname(remote)
        try:
            sftp.stat(remote_dir)
        except OSError:
            # mkdir -p via ssh
            client.exec_command(f"mkdir -p {remote_dir}")
        print(f"upload {local.name} -> {remote}")
        sftp.put(str(local), remote)

    sftp.close()
    _, stdout, stderr = client.exec_command(REMOTE_ENABLE, timeout=600)
    out = stdout.read().decode("utf-8", errors="replace")
    err = stderr.read().decode("utf-8", errors="replace")
    client.close()
    if err.strip():
        print("STDERR:", err)
    print(out)
    return 0 if "Start Suricata" in out or "Suricata engine" in out or "sensel-suricata" in out else 1


if __name__ == "__main__":
    raise SystemExit(main())
