#!/usr/bin/env python3
"""Restart EdgeMed API on Raspberry Pi (post-reboot helper)."""

from __future__ import annotations

import time

import paramiko

HOST, USER, PW = "192.168.50.90", "fju", "0000"
REMOTE = "/home/fju/sensel-ot-edge-sensor/services/edgemed"


def connect() -> paramiko.SSHClient:
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(
        HOST,
        username=USER,
        password=PW,
        timeout=25,
        look_for_keys=False,
        allow_agent=False,
        banner_timeout=60,
    )
    t = client.get_transport()
    if t:
        t.set_keepalive(20)
    return client


def run(client: paramiko.SSHClient, cmd: str, timeout: int = 120) -> tuple[int, str]:
    print(">>>", cmd[:160], flush=True)
    _, stdout, stderr = client.exec_command(cmd, timeout=timeout, get_pty=True)
    out = stdout.read().decode("utf-8", "replace")
    err = stderr.read().decode("utf-8", "replace")
    code = stdout.channel.recv_exit_status()
    text = out + (("\n" + err) if err.strip() else "")
    print(text[-800:], flush=True)
    return code, text


def main() -> int:
    client = connect()
    run(client, "pkill -f 'uvicorn app.main:app' || true", timeout=20)
    time.sleep(1)
    run(
        client,
        f"cd {REMOTE} && source .venv/bin/activate && "
        "python -c \"import torch; print('torch', torch.__version__)\"",
        timeout=60,
    )
    run(client, "rm -f /tmp/edgemed-uvicorn.log")
    run(
        client,
        f"cd {REMOTE} && source .venv/bin/activate && "
        "nohup env OMP_NUM_THREADS=1 OPENBLAS_NUM_THREADS=1 "
        "uvicorn app.main:app --host 0.0.0.0 --port 8000 "
        ">/tmp/edgemed-uvicorn.log 2>&1 & echo $! > /tmp/edgemed-uvicorn.pid; "
        "cat /tmp/edgemed-uvicorn.pid",
        timeout=30,
    )
    client.close()

    import httpx

    for i in range(40):
        time.sleep(3)
        try:
            r = httpx.get(f"http://{HOST}:8000/health", timeout=8)
            print(f"health {i}: {r.status_code} {r.text[:300]}", flush=True)
            if r.status_code == 200:
                print("PI_API_OK", flush=True)
                return 0
        except Exception as exc:
            print(f"health {i}: {exc}", flush=True)
    print("PI_API_FAIL", flush=True)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
