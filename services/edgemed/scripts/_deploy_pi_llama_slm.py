#!/usr/bin/env python3
"""Deploy SLM llama.cpp wiring to Pi and restart API with env."""

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
    ("config/slm.yaml", f"{REMOTE}/config/slm.yaml"),
]


def connect() -> paramiko.SSHClient:
    c = paramiko.SSHClient()
    c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
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


def main() -> int:
    c = connect()
    sftp = c.open_sftp()
    for local, remote in FILES:
        src = ROOT / local
        print(f"upload {src} -> {remote}", flush=True)
        sftp.put(str(src), remote)
    sftp.close()

    start = f"""#!/bin/bash
pkill -f 'uvicorn app.main:app' || true
sleep 1
cd {REMOTE}
source .venv/bin/activate
export OMP_NUM_THREADS=1 OPENBLAS_NUM_THREADS=1
export EDGEMED_LLAMA_BIN=/home/fju/edgemed-slm/llama-b10276/llama-completion
export EDGEMED_LLAMA_MODEL=/home/fju/edgemed-slm/models/SmolLM2-360M-Instruct-Q4_K_M.gguf
export EDGEMED_LLAMA_THREADS=2
export LD_LIBRARY_PATH=/home/fju/edgemed-slm/llama-b10276:${{LD_LIBRARY_PATH:-}}
# clear stale unittest markers so V2 retest is fresh
rm -f /tmp/edgemed_v2_*.done /tmp/edgemed_v2_*.log
nohup uvicorn app.main:app --host 0.0.0.0 --port 8000 >/tmp/edgemed-uvicorn.log 2>&1 &
echo $! > /tmp/edgemed-uvicorn.pid
cat /tmp/edgemed-uvicorn.pid
"""
    sftp = c.open_sftp()
    with sftp.file("/tmp/start_edgemed_api.sh", "w") as f:
        f.write(start)
    sftp.chmod("/tmp/start_edgemed_api.sh", 0o755)
    sftp.close()
    _, o, e = c.exec_command("bash /tmp/start_edgemed_api.sh", timeout=30)
    print(o.read().decode("utf-8", "replace"), flush=True)
    err = e.read().decode("utf-8", "replace")
    if err.strip():
        print("ERR", err, flush=True)
    c.close()

    for i in range(40):
        time.sleep(3)
        try:
            r = httpx.get(f"http://{HOST}:8000/health", timeout=8)
            print(f"health {i}: {r.status_code} {r.text[:350]}", flush=True)
            if r.status_code == 200:
                body = r.json()
                slm = (body.get("components") or {}).get("slm") or {}
                if slm.get("runtime_loaded") and slm.get("backend") == "llama_cpp":
                    print("PI_SLM_LLAMA_OK", flush=True)
                    return 0
                if i >= 5 and body.get("status"):
                    print("PI_API_UP_BUT_SLM_NOT_LLAMA", flush=True)
                    return 2
        except Exception as exc:
            print(f"health {i}: {exc}", flush=True)
    print("PI_API_FAIL", flush=True)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
