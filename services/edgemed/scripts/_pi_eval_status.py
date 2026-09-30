#!/usr/bin/env python3
"""Check Pi eval log after reboot (no PowerShell-pipe quoting)."""

from __future__ import annotations

import time

import paramiko

HOST, USER, PW = "192.168.50.90", "fju", "0000"


def main() -> int:
    c = paramiko.SSHClient()
    c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    last = None
    for i in range(12):
        try:
            c.connect(
                HOST,
                username=USER,
                password=PW,
                timeout=25,
                look_for_keys=False,
                allow_agent=False,
                banner_timeout=40,
            )
            break
        except Exception as exc:
            last = exc
            print("retry", i, exc, flush=True)
            time.sleep(5)
    else:
        raise SystemExit(f"ssh fail {last}")

    cmds = [
        "uptime; free -m",
        "ls -la /home/fju/sensel-ot-edge-sensor/services/edgemed/artifacts/eval/full_eval_stream* 2>/dev/null || true",
        "wc -l /home/fju/sensel-ot-edge-sensor/services/edgemed/artifacts/eval/full_eval_stream.log 2>/dev/null || true",
        "tail -n 80 /home/fju/sensel-ot-edge-sensor/services/edgemed/artifacts/eval/full_eval_stream.log 2>/dev/null || true",
        "cat /home/fju/sensel-ot-edge-sensor/services/edgemed/artifacts/eval/full_eval_stream.done 2>/dev/null || true",
        "ps -eo pid,cmd | grep -E 'uvicorn|llama|edgemed' | grep -v grep || true",
    ]
    for cmd in cmds:
        print(">>>", cmd, flush=True)
        _, o, e = c.exec_command(cmd, timeout=60)
        print(o.read().decode("utf-8", "replace"), flush=True)
        err = e.read().decode("utf-8", "replace")
        if err.strip():
            print("ERR", err[-400:], flush=True)
    c.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
