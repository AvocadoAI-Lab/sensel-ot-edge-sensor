"""Inject Suricata lab traffic on Pi and verify E2E bridge."""
from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path

import paramiko

PI_HOST = "192.168.50.90"
PI_USER = "fju"
PI_PASS = "0000"
PI_ROOT = "/home/fju/sensel-ot-edge-sensor"
REPO = Path(__file__).resolve().parents[1]
TARGET = os.environ.get("SURICATA_LAB_TARGET", "192.168.50.134")


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

    local_script = REPO / "deploy/pi4/inject-suricata-lab-traffic.sh"
    remote_script = f"{PI_ROOT}/deploy/pi4/inject-suricata-lab-traffic.sh"
    sftp = client.open_sftp()
    sftp.put(str(local_script), remote_script)
    sftp.close()

    remote = f"""
set -e
chmod +x {remote_script}
export SURICATA_LAB_TARGET={TARGET}

# ensure services up
echo 0000 | sudo -S docker ps --filter name=sensel-suricata --format '{{{{.Names}}}}' | grep -q sensel-suricata || bash {PI_ROOT}/deploy/pi4/start-suricata.sh

# inject
bash {remote_script}

sleep 6

# Ensure packet-sensor bridge is running; backfill eve.json if needed
PS_DIR="{PI_ROOT}/services/packet-sensor"
if ! pgrep -f 'packet-sensor/.venv/bin/python -m src.main' >/dev/null; then
  cd "$PS_DIR" && . .venv/bin/activate
  export SENSOR_CONFIG_PATH="{PI_ROOT}/config/sensor.pi-edgemed.yaml"
  export PYTHONPATH="$PS_DIR"
  export CAPTURE_INTERFACE=eth0
  export INFERENCE_BACKEND=edgemed
  export EDGEMED_BASE_URL=http://127.0.0.1:8000
  export EDGEMED_INVESTIGATE_ENABLED=true
  export MODEL_INFERENCE_ENABLED=true
  export SURICATA_SOURCE_ENABLED=true
  export SURICATA_EVE_JSON_PATH="{PI_ROOT}/data/suricata/eve.json"
  export SURICATA_SOURCE_POLL_SEC=2
  echo 0000 | sudo -S -E env SENSOR_CONFIG_PATH="$SENSOR_CONFIG_PATH" PYTHONPATH="$PYTHONPATH" CAPTURE_INTERFACE="$CAPTURE_INTERFACE" INFERENCE_BACKEND="$INFERENCE_BACKEND" EDGEMED_BASE_URL="$EDGEMED_BASE_URL" EDGEMED_INVESTIGATE_ENABLED="$EDGEMED_INVESTIGATE_ENABLED" MODEL_INFERENCE_ENABLED="$MODEL_INFERENCE_ENABLED" SURICATA_SOURCE_ENABLED="$SURICATA_SOURCE_ENABLED" SURICATA_EVE_JSON_PATH="$SURICATA_EVE_JSON_PATH" SURICATA_SOURCE_POLL_SEC="$SURICATA_SOURCE_POLL_SEC" "$PS_DIR/.venv/bin/python" -m src.main >> /tmp/ps-new.log 2>&1 &
  sleep 4
fi

cd "$PS_DIR" && . .venv/bin/activate && export PYTHONPATH="$PS_DIR"
python3 - <<'PY'
from pathlib import Path
from src.detection.external_engine.suricata_source import SuricataEveSource
ROOT = Path("{PI_ROOT}")
src = SuricataEveSource(
    eve_json_path=str(ROOT / "data/suricata/eve.json"),
    output_dir=str(ROOT / "data/assets"),
    offset_path=str(ROOT / "data/assets/.suricata-source.offset"),
    site_id="factory-lab-pi",
    sensor_id="ot-edge-pi4",
)
print("bridge_backfill", src.poll_once())
PY

SURICATA_SOURCE_ENABLED=true SURICATA_RULES_PATH={PI_ROOT}/config/suricata/rules/local.rules SURICATA_RULE_VERSION=pi-lab-v0.1 bash {PI_ROOT}/deploy/pi4/start-edge-agent.sh
sleep 6

python3 - <<'PY'
import json, os, subprocess, time
ROOT = "{PI_ROOT}"

def sh(cmd):
    return subprocess.check_output(cmd, shell=True, text=True, errors='replace').strip()

out = {{}}
eve = ROOT + "/data/suricata/eve.json"
events = ROOT + "/data/assets/suricata-events.jsonl"
out["eve_bytes"] = os.path.getsize(eve) if os.path.isfile(eve) else 0
out["eve_alert_lines"] = 0
if out["eve_bytes"] > 0:
    out["eve_alert_lines"] = sum(
        1 for line in open(eve, encoding="utf-8", errors="replace")
        if '"event_type": "alert"' in line or '"event_type":"alert"' in line
    )
    out["eve_tail"] = open(eve, encoding="utf-8", errors="replace").read().splitlines()[-1][:240]
out["events_lines"] = int(sh(f"wc -l < {{events}} 2>/dev/null || echo 0"))
if out["events_lines"] > 0:
    out["events_tail"] = sh(f"tail -1 {{events}}")[:400]
rt = ROOT + "/data/agent/agent-runtime.json"
if os.path.isfile(rt):
    d = json.load(open(rt, encoding="utf-8"))
    out["suricata_engine"] = [e for e in d.get("engines", []) if e.get("name") == "suricata"]
out["suricata_log"] = sh("echo 0000 | sudo -S docker logs sensel-suricata 2>&1 | grep -i alert | tail -3 || true")
print(json.dumps(out, ensure_ascii=False, indent=2))
PY
"""

    _, stdout, stderr = client.exec_command(remote, timeout=180)
    out = stdout.read().decode("utf-8", errors="replace")
    err = stderr.read().decode("utf-8", errors="replace")
    client.close()

    if err.strip():
        print("STDERR:", err, file=sys.stderr)
    print(out)

    try:
        # last JSON block in output
        block = out[out.rfind("{") :]
        data = json.loads(block)
    except (json.JSONDecodeError, ValueError):
        return 1

    ok = data.get("eve_alert_lines", 0) > 0 or data.get("events_lines", 0) > 0
    engine = (data.get("suricata_engine") or [{}])[0]
    if engine.get("configured") and engine.get("status") in ("running", "stale"):
        ok = True
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
