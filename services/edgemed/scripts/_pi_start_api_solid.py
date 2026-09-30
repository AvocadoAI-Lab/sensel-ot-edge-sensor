#!/usr/bin/env python3
"""Reliably start Pi uvicorn via remote shell script."""

from __future__ import annotations

import time

import httpx
import paramiko

HOST, USER, PW = "192.168.50.90", "fju", "0000"
REMOTE = "/home/fju/sensel-ot-edge-sensor/services/edgemed"
SCRIPT = "/tmp/start_edgemed_api.sh"


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
    body = f"""#!/bin/bash
set -e
pkill -f 'uvicorn app.main:app' || true
sleep 1
cd {REMOTE}
source .venv/bin/activate
export OMP_NUM_THREADS=1 OPENBLAS_NUM_THREADS=1
nohup uvicorn app.main:app --host 0.0.0.0 --port 8000 >/tmp/edgemed-uvicorn.log 2>&1 &
echo $! > /tmp/edgemed-uvicorn.pid
sleep 1
cat /tmp/edgemed-uvicorn.pid
pgrep -af 'uvicorn app.main' || true
"""
    c = connect()
    sftp = c.open_sftp()
    with sftp.file(SCRIPT, "w") as f:
        f.write(body)
    sftp.chmod(SCRIPT, 0o755)
    sftp.close()

    _, stdout, stderr = c.exec_command(f"bash {SCRIPT}", timeout=30)
    print(stdout.read().decode("utf-8", "replace"), flush=True)
    err = stderr.read().decode("utf-8", "replace")
    if err.strip():
        print("ERR", err, flush=True)
    c.close()

    for i in range(50):
        time.sleep(3)
        try:
            r = httpx.get(f"http://{HOST}:8000/health", timeout=8)
            print(f"health {i}: {r.status_code} {r.text[:260]}", flush=True)
            if r.status_code == 200:
                print("PI_API_OK", flush=True)
                return 0
        except Exception as exc:
            print(f"health {i}: {exc}", flush=True)
            if i in (5, 15, 30):
                c2 = connect()
                _, o, _ = c2.exec_command(
                    "pgrep -af uvicorn || true; tail -n 40 /tmp/edgemed-uvicorn.log || true",
                    timeout=20,
                )
                print(o.read().decode("utf-8", "replace")[-1200:], flush=True)
                c2.close()
    print("PI_API_FAIL", flush=True)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
