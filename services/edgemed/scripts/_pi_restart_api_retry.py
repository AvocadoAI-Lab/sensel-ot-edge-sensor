#!/usr/bin/env python3
"""Retry SSH and start Pi API."""

from __future__ import annotations

import time

import httpx
import paramiko

HOST, USER, PW = "192.168.50.90", "fju", "0000"
REMOTE = "/home/fju/sensel-ot-edge-sensor/services/edgemed"


def main() -> int:
    client = None
    for i in range(12):
        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(
                HOST,
                username=USER,
                password=PW,
                timeout=15,
                look_for_keys=False,
                allow_agent=False,
                banner_timeout=40,
            )
            print(f"SSH_OK try={i}", flush=True)
            break
        except Exception as exc:
            print(f"ssh try {i}: {exc}", flush=True)
            time.sleep(3)
            client = None
    if client is None:
        print("SSH_FAIL — 請確認 Pi 已接上網路且 IP 仍是 192.168.50.90", flush=True)
        return 2

    cmd = (
        "pkill -f 'uvicorn app.main:app' || true; sleep 1; "
        f"cd {REMOTE} && source .venv/bin/activate && "
        "nohup env OMP_NUM_THREADS=1 OPENBLAS_NUM_THREADS=1 "
        "uvicorn app.main:app --host 0.0.0.0 --port 8000 "
        ">/tmp/edgemed-uvicorn.log 2>&1 & echo PID:$!; sleep 2; "
        "pgrep -af uvicorn || true; hostname -I; uptime"
    )
    _, stdout, _ = client.exec_command(cmd, timeout=60)
    print(stdout.read().decode("utf-8", "replace"), flush=True)
    client.close()

    for i in range(40):
        time.sleep(3)
        try:
            r = httpx.get(f"http://{HOST}:8000/health", timeout=8)
            print(f"health {i}: {r.status_code} {r.text[:280]}", flush=True)
            if r.status_code == 200:
                print("PI_API_OK", flush=True)
                return 0
        except Exception as exc:
            print(f"health {i}: {exc}", flush=True)
    print("PI_API_FAIL", flush=True)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
