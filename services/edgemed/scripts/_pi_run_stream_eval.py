#!/usr/bin/env python3
"""Upload streaming full-test eval to Pi, run via remote helper script, poll, download."""

from __future__ import annotations

import time
from pathlib import Path

import paramiko

HOST, USER, PW = "192.168.50.90", "fju", "0000"
ROOT = Path(__file__).resolve().parents[1]
REMOTE_ROOT = "/home/fju/sensel-ot-edge-sensor/services/edgemed"
TEST_DIR = "/home/fju/dataset/WiFI_and_MQTTattacksCSVtest"
OUT_REMOTE = f"{REMOTE_ROOT}/artifacts/eval/official_test_full_pi.json"
OUT_LOCAL = ROOT / "artifacts" / "eval" / "official_test_full_pi.json"
REMOTE_HELPER = f"{REMOTE_ROOT}/scripts/_run_stream_eval_bg.sh"
LOG_PATH = f"{REMOTE_ROOT}/artifacts/eval/full_eval_stream.log"
DONE_PATH = f"{REMOTE_ROOT}/artifacts/eval/full_eval_stream.done"
PID_PATH = f"{REMOTE_ROOT}/artifacts/eval/full_eval_stream.pid"

REMOTE_HELPER_BODY = f"""#!/bin/bash
set -e
cd {REMOTE_ROOT}
source .venv/bin/activate
mkdir -p artifacts/eval
rm -f {LOG_PATH} {DONE_PATH} {PID_PATH}
export OMP_NUM_THREADS=1
export OPENBLAS_NUM_THREADS=1
export MKL_NUM_THREADS=1
export NUMEXPR_NUM_THREADS=1
export XGBOOST_NUM_THREAD=1
echo $$ > {PID_PATH}
python -u scripts/eval_official_test_full_stream.py \\
  --test-dir {TEST_DIR} \\
  --chunk-size 3000 \\
  --skip-if \\
  --output artifacts/eval/official_test_full_pi.json \\
  >{LOG_PATH} 2>&1
echo EXIT:$? > {DONE_PATH}
"""


def connect() -> paramiko.SSHClient:
    last = None
    for i in range(20):
        try:
            c = paramiko.SSHClient()
            c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            c.connect(
                HOST,
                username=USER,
                password=PW,
                timeout=25,
                look_for_keys=False,
                allow_agent=False,
                banner_timeout=40,
            )
            t = c.get_transport()
            if t:
                t.set_keepalive(15)
            print(f"SSH_OK try={i}", flush=True)
            return c
        except Exception as exc:
            last = exc
            print(f"ssh try {i}: {exc}", flush=True)
            time.sleep(5)
    raise RuntimeError(f"SSH failed: {last}")


def run(c: paramiko.SSHClient, cmd: str, timeout: int = 120) -> str:
    print(">>>", cmd[:180], flush=True)
    _, o, e = c.exec_command(cmd, timeout=timeout)
    chan = o.channel
    deadline = time.time() + timeout
    chunks: list[bytes] = []
    while True:
        if chan.recv_ready():
            chunks.append(chan.recv(65536))
        if chan.recv_stderr_ready():
            err = chan.recv_stderr(65536).decode("utf-8", "replace")
            if err.strip():
                print("ERR", err[-500:], flush=True)
        if chan.exit_status_ready() and not chan.recv_ready():
            break
        if time.time() > deadline:
            print("CMD_TIMEOUT", flush=True)
            break
        time.sleep(0.2)
    out = b"".join(chunks).decode("utf-8", "replace")
    if out.strip():
        print(out[-1800:], flush=True)
    return out


def wait_settled(min_minutes: int = 3) -> None:
    for _ in range(40):
        try:
            c = connect()
            boot = run(c, "awk '{{print int($1/60)}}' /proc/uptime; uptime; free -m | head -n 2", timeout=40)
            c.close()
            mins = int(boot.strip().splitlines()[0].strip())
            print(f"pi_uptime_min={mins}", flush=True)
            if mins >= min_minutes:
                return
            print("waiting for pi to settle...", flush=True)
        except Exception as exc:
            print("settle wait", exc, flush=True)
        time.sleep(20)
    print("PI_NOT_SETTLED_CONTINUING", flush=True)


def main() -> int:
    wait_settled(3)
    c = connect()
    status = run(
        c,
        f"ls '{TEST_DIR}' 2>/dev/null | wc -l; du -sh '{TEST_DIR}' 2>/dev/null; free -m | head -n 3; uptime",
        timeout=60,
    )
    if status.strip().startswith("0"):
        print("DATASET_MISSING", flush=True)
        c.close()
        return 3

    sftp = c.open_sftp()
    for rel in (
        "scripts/eval_official_test_full_stream.py",
        "artifacts/classifiers/xgboost_binary.joblib",
        "artifacts/classifiers/xgboost_category.joblib",
    ):
        local = ROOT / rel
        remote = f"{REMOTE_ROOT}/{rel}"
        run(c, f"mkdir -p $(dirname {remote})", timeout=30)
        print("put", rel, local.stat().st_size, flush=True)
        sftp.put(str(local), remote)

    with sftp.file(REMOTE_HELPER, "w") as fh:
        fh.write(REMOTE_HELPER_BODY)
    sftp.close()
    run(c, f"chmod +x {REMOTE_HELPER}", timeout=30)

    run(
        c,
        f"if [ -f {PID_PATH} ]; then kill $(cat {PID_PATH}) 2>/dev/null || true; fi; "
        "pkill -f 'python -u scripts/eval_official_test_full_stream.py' || true; "
        "pkill -f 'uvicorn app.main:app' || true; "
        "pkill -f llama-server || true; "
        f"rm -f {LOG_PATH} {DONE_PATH} {PID_PATH}; sleep 2; free -m | head -n 3; uptime",
        timeout=60,
    )

    run(
        c,
        f"nohup {REMOTE_HELPER} >/dev/null 2>&1 & echo LAUNCHED; sleep 3; "
        f"test -f {LOG_PATH} && echo LOG_OK || echo LOG_MISSING; "
        f"test -f {PID_PATH} && echo PID:$(cat {PID_PATH}) || echo NO_PID; "
        "ps -eo pid,cmd | grep '[e]val_official_test_full_stream' || echo NO_PYTHON_YET",
        timeout=30,
    )
    c.close()

    last_lines = 0
    stall = 0
    for i in range(480):
        time.sleep(20)
        try:
            c2 = connect()
            text = run(
                c2,
                f"echo MARK_START; "
                f"if [ -f {DONE_PATH} ]; then echo STATUS_FINISHED; cat {DONE_PATH}; "
                f"else echo STATUS_RUNNING; fi; "
                f"wc -l {LOG_PATH} 2>/dev/null || echo 0 {LOG_PATH}; "
                f"tail -n 10 {LOG_PATH} 2>/dev/null || true; "
                f"if [ -f {PID_PATH} ]; then PID=$(cat {PID_PATH}); "
                f"if kill -0 $PID 2>/dev/null; then echo PROC_ALIVE:$PID; else echo PROC_DEAD:$PID; fi; "
                f"else echo PROC_NOPID; fi; "
                "free -m | head -n 3; uptime; echo MARK_END",
                timeout=90,
            )
            c2.close()
        except Exception as exc:
            print("poll err", exc, flush=True)
            continue

        if "STATUS_FINISHED" in text:
            if "FULL_EVAL_DONE" in text:
                c3 = connect()
                sftp = c3.open_sftp()
                OUT_LOCAL.parent.mkdir(parents=True, exist_ok=True)
                sftp.get(OUT_REMOTE, str(OUT_LOCAL))
                sftp.close()
                c3.close()
                print("PI_EVAL_OK", OUT_LOCAL, flush=True)
                return 0
            print("PI_EVAL_FAIL", flush=True)
            return 1

        try:
            for line in text.splitlines():
                if LOG_PATH in line and line.strip()[0].isdigit():
                    n = int(line.strip().split()[0])
                    if n > last_lines:
                        last_lines = n
                        stall = 0
                    else:
                        stall += 1
                    break
        except Exception:
            pass

        if "PROC_DEAD" in text or "PROC_NOPID" in text:
            if "up 0 min" in text or "up 1 min" in text:
                print("PI_REBOOTED_DURING_EVAL", flush=True)
                return 6
            if i >= 2:
                print("PROCESS_DIED_EARLY", flush=True)
                return 4

        if stall >= 30:
            print("STALLED", flush=True)
            return 5

        print(f"poll {i} lines={last_lines} stall={stall}", flush=True)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
