#!/usr/bin/env python3
"""Push Pi-lab config updates and restart packet-sensor."""
import sys
import time
from pathlib import Path
import paramiko

HOST, USER, PW = "192.168.50.90", "fju", "0000"
ROOT = Path(__file__).resolve().parents[1]
REMOTE = "/home/fju/sensel-ot-edge-sensor"
FILES = [
    (ROOT / "config/sensor.pi-edgemed.yaml", f"{REMOTE}/config/sensor.pi-edgemed.yaml"),
    (ROOT / "config/model/feature-contract.ot-window-pi-lab-v1.json", f"{REMOTE}/config/model/feature-contract.ot-window-pi-lab-v1.json"),
    (ROOT / "config/model/edgemed-feature-mapping.ot-window-pi-lab-v1.json", f"{REMOTE}/config/model/edgemed-feature-mapping.ot-window-pi-lab-v1.json"),
]

c = paramiko.SSHClient()
c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
c.connect(HOST, username=USER, password=PW, timeout=20, look_for_keys=False, allow_agent=False)
sftp = c.open_sftp()
for local, remote in FILES:
    sftp.put(str(local), remote)
sftp.close()

script = f"""#!/bin/bash
set -e
pkill -f 'python -m src.main' || true
sleep 1
echo '{PW}' | sudo -S bash {REMOTE}/deploy/pi4/start-native-edgemed.sh
"""
remote = "/tmp/restart_ps.sh"
sftp = c.open_sftp()
with sftp.file(remote, "w") as f:
    f.write(script)
sftp.chmod(remote, 0o755)
sftp.close()
_, o, e = c.exec_command(f"bash {remote}", timeout=120)
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
print(o.read().decode("utf-8", "replace"))
print(e.read().decode("utf-8", "replace"))
c.close()

time.sleep(70)
c = paramiko.SSHClient()
c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
c.connect(HOST, username=USER, password=PW, timeout=20, look_for_keys=False, allow_agent=False)
_, o, _ = c.exec_command(
    "cat /home/fju/sensel-ot-edge-sensor/data/assets/model-runtime.json 2>/dev/null; "
    "echo ---; tail -n 2 /home/fju/sensel-ot-edge-sensor/data/assets/trust-episodes.jsonl 2>/dev/null; "
    "echo ---; tail -n 20 /tmp/packet-sensor.log",
    timeout=30,
)
print(o.read().decode("utf-8", "replace"))
c.close()
