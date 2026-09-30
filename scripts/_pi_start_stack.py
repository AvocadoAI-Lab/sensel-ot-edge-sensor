#!/usr/bin/env python3
import sys
import time
import httpx
import paramiko

HOST, USER, PW = "192.168.50.90", "fju", "0000"
REMOTE_ROOT = "/home/fju/sensel-ot-edge-sensor"

c = paramiko.SSHClient()
c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
c.connect(HOST, username=USER, password=PW, timeout=20, look_for_keys=False, allow_agent=False)
remote = "/tmp/sensel_start.sh"
script = f"""#!/bin/bash
set -e
echo '{PW}' | sudo -S bash {REMOTE_ROOT}/deploy/pi4/start-native-edgemed.sh
"""
sftp = c.open_sftp()
with sftp.file(remote, "w") as f:
    f.write(script)
sftp.chmod(remote, 0o755)
sftp.close()
_, o, e = c.exec_command(f"bash {remote}", timeout=120)
out = o.read().decode("utf-8", "replace")
err = e.read().decode("utf-8", "replace")
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
print(out)
if err.strip():
    print(err)
c.close()

for i in range(25):
    try:
        r = httpx.get(f"http://{HOST}:8000/health", timeout=8)
        print(f"health {i}: {r.status_code} {r.text[:200]}")
        if r.status_code == 200:
            break
    except Exception as exc:
        print(f"health {i}: {exc}")
    time.sleep(3)

c = paramiko.SSHClient()
c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
c.connect(HOST, username=USER, password=PW, timeout=20, look_for_keys=False, allow_agent=False)
_, o, _ = c.exec_command(
    "pgrep -af uvicorn; pgrep -af 'python -m src.main'; "
    "tail -n 25 /tmp/packet-sensor.log 2>/dev/null; "
    "tail -n 15 /tmp/edgemed-uvicorn.log 2>/dev/null",
    timeout=30,
)
print(o.read().decode("utf-8", "replace"))
c.close()
