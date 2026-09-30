#!/usr/bin/env python3
"""Deploy llama-server + API with EDGEMED_LLAMA_SERVER backend."""

from __future__ import annotations

import time
from pathlib import Path

import httpx
import paramiko

HOST, USER, PW = "192.168.50.90", "fju", "0000"
REMOTE = "/home/fju/sensel-ot-edge-sensor/services/edgemed"
ROOT = Path(__file__).resolve().parents[1]
FILES = [
    ("app/slm.py", f"{REMOTE}/app/slm.py"),
    ("app/main.py", f"{REMOTE}/app/main.py"),
    ("app/events.py", f"{REMOTE}/app/events.py"),
    ("config/slm.yaml", f"{REMOTE}/config/slm.yaml"),
]


def connect() -> paramiko.SSHClient:
    c = paramiko.SSHClient()
    c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    for i in range(8):
        try:
            c.connect(
                HOST,
                username=USER,
                password=PW,
                timeout=20,
                look_for_keys=False,
                allow_agent=False,
                banner_timeout=40,
            )
            t = c.get_transport()
            if t:
                t.set_keepalive(20)
            return c
        except Exception as exc:
            print(f"ssh try {i}: {exc}", flush=True)
            time.sleep(3)
    raise RuntimeError("SSH failed")


def main() -> int:
    c = connect()
    sftp = c.open_sftp()
    for local, remote in FILES:
        print(f"upload {local}", flush=True)
        sftp.put(str(ROOT / local), remote)
    sftp.close()

    script = f"""#!/bin/bash
set -e
pkill -f 'uvicorn app.main:app' || true
pkill -f 'llama-server' || true
sleep 2
export LD_LIBRARY_PATH=/home/fju/edgemed-slm/llama-b10276:${{LD_LIBRARY_PATH:-}}
cd /home/fju/edgemed-slm/llama-b10276
nohup ./llama-server \\
  -m /home/fju/edgemed-slm/models/SmolLM2-360M-Instruct-Q4_K_M.gguf \\
  --host 127.0.0.1 --port 8081 \\
  -c 2048 -n 160 -t 2 -ngl 0 \\
  >/tmp/llama-server.log 2>&1 &
echo $! > /tmp/llama-server.pid
# wait for server
for i in $(seq 1 60); do
  if curl -s http://127.0.0.1:8081/health >/dev/null 2>&1 || curl -s http://127.0.0.1:8081/ >/dev/null 2>&1; then
    echo LLAMA_SERVER_UP
    break
  fi
  sleep 2
done
cd {REMOTE}
source .venv/bin/activate
export OMP_NUM_THREADS=1 OPENBLAS_NUM_THREADS=1
export EDGEMED_LLAMA_SERVER=http://127.0.0.1:8081
nohup uvicorn app.main:app --host 0.0.0.0 --port 8000 >/tmp/edgemed-uvicorn.log 2>&1 &
echo $! > /tmp/edgemed-uvicorn.pid
echo STARTED
"""
    sftp = c.open_sftp()
    with sftp.file("/tmp/start_edgemed_llama_stack.sh", "w") as f:
        f.write(script)
    sftp.chmod("/tmp/start_edgemed_llama_stack.sh", 0o755)
    sftp.close()
    _, o, e = c.exec_command("bash /tmp/start_edgemed_llama_stack.sh", timeout=180)
    print(o.read().decode("utf-8", "replace"), flush=True)
    err = e.read().decode("utf-8", "replace")
    if err.strip():
        print("ERR", err[-500:], flush=True)
    # show llama log tail
    _, o2, _ = c.exec_command("tail -n 30 /tmp/llama-server.log || true", timeout=20)
    print("LLAMA_LOG", o2.read().decode("utf-8", "replace")[-1500:], flush=True)
    c.close()

    for i in range(50):
        time.sleep(3)
        try:
            r = httpx.get(f"http://{HOST}:8000/health", timeout=8)
            print(f"health {i}: {r.text[:320]}", flush=True)
            body = r.json()
            slm = (body.get("components") or {}).get("slm") or {}
            if slm.get("runtime_loaded") and "llama" in str(slm.get("backend")):
                print("STACK_OK", flush=True)
                return 0
        except Exception as exc:
            print(f"health {i}: {exc}", flush=True)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
