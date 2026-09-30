#!/usr/bin/env python3
"""Re-upload full CIC test tgz to Pi with size verify, extract, run eval."""

from __future__ import annotations

import os
import time
from pathlib import Path

import paramiko

HOST, USER, PW = "192.168.50.90", "fju", "0000"
ROOT = Path(__file__).resolve().parents[1]
LOCAL_TGZ = Path(os.environ.get("TEMP", ".")) / "ciciomt_test_full.tgz"


def connect() -> paramiko.SSHClient:
    last = None
    for i in range(10):
        try:
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
                t.set_keepalive(15)
            print(f"SSH_OK try={i}", flush=True)
            return c
        except Exception as exc:
            last = exc
            print(f"ssh try {i}: {exc}", flush=True)
            time.sleep(3)
    raise RuntimeError(f"SSH failed: {last}")


def run(c: paramiko.SSHClient, cmd: str, timeout: int = 300) -> str:
    print(">>>", cmd[:140], flush=True)
    _, o, e = c.exec_command(cmd, timeout=timeout)
    # avoid hanging forever: poll
    chan = o.channel
    deadline = time.time() + timeout
    chunks = []
    while True:
        if chan.recv_ready():
            chunks.append(chan.recv(65536))
        if chan.recv_stderr_ready():
            err = chan.recv_stderr(65536).decode("utf-8", "replace")
            if err.strip():
                print("ERR", err[-400:], flush=True)
        if chan.exit_status_ready() and not chan.recv_ready():
            break
        if time.time() > deadline:
            print("CMD_TIMEOUT", flush=True)
            break
        time.sleep(0.2)
    out = b"".join(chunks).decode("utf-8", "replace")
    print(out[-1200:], flush=True)
    return out


def main() -> int:
    assert LOCAL_TGZ.exists(), LOCAL_TGZ
    local_size = LOCAL_TGZ.stat().st_size
    print("local_tgz", local_size, flush=True)

    c = connect()
    run(c, "rm -rf /home/fju/dataset/WiFI_and_MQTTattacksCSVtest /home/fju/ciciomt_test_full.tgz")
    sftp = c.open_sftp()
    print("uploading tgz...", flush=True)
    t0 = time.time()
    sftp.put(str(LOCAL_TGZ), "/home/fju/ciciomt_test_full.tgz")
    print("upload_sec", round(time.time() - t0, 1), flush=True)
    remote_size = sftp.stat("/home/fju/ciciomt_test_full.tgz").st_size
    print("remote_size", remote_size, flush=True)
    if remote_size != local_size:
        raise SystemExit(f"size mismatch {remote_size} != {local_size}")

    for rel in (
        "scripts/eval_official_test_full.py",
        "artifacts/classifiers/xgboost_binary.joblib",
        "artifacts/classifiers/xgboost_category.joblib",
        "artifacts/detector.joblib",
    ):
        local = ROOT / rel
        remote = f"/home/fju/sensel-ot-edge-sensor/services/edgemed/{rel}"
        run(c, f"mkdir -p {str(Path(remote).parent).replace(chr(92), '/')}")
        print("put", rel, flush=True)
        sftp.put(str(local), remote)
    sftp.close()

    run(
        c,
        "mkdir -p /home/fju/dataset && "
        "tar -xzf /home/fju/ciciomt_test_full.tgz -C /home/fju/dataset && "
        "ls /home/fju/dataset/WiFI_and_MQTTattacksCSVtest | wc -l && "
        "du -sh /home/fju/dataset/WiFI_and_MQTTattacksCSVtest",
        timeout=180,
    )

    run(
        c,
        "rm -f /tmp/edgemed_full_eval.log /tmp/edgemed_full_eval.done; "
        "nohup bash -lc 'cd /home/fju/sensel-ot-edge-sensor/services/edgemed && source .venv/bin/activate && "
        "python -u scripts/eval_official_test_full.py "
        "--test-dir /home/fju/dataset/WiFI_and_MQTTattacksCSVtest "
        "--output artifacts/eval/official_test_full_pi.json "
        ">/tmp/edgemed_full_eval.log 2>&1; "
        "echo EXIT:$? >/tmp/edgemed_full_eval.done' >/dev/null 2>&1 & echo LAUNCHED",
        timeout=30,
    )
    c.close()

    for i in range(180):
        time.sleep(10)
        try:
            c2 = connect()
            text = run(
                c2,
                "if [ -f /tmp/edgemed_full_eval.done ]; then echo DONEFILE; cat /tmp/edgemed_full_eval.done; "
                "echo ---; tail -n 40 /tmp/edgemed_full_eval.log; else echo WAITING; "
                "wc -l /tmp/edgemed_full_eval.log 2>/dev/null; tail -n 3 /tmp/edgemed_full_eval.log 2>/dev/null; "
                "free -m | head -n 2; fi",
                timeout=60,
            )
            c2.close()
        except Exception as exc:
            print("poll err", exc, flush=True)
            continue
        if "DONEFILE" in text and "FULL_EVAL_DONE" in text:
            c3 = connect()
            sftp = c3.open_sftp()
            out = ROOT / "artifacts" / "eval" / "official_test_full_pi.json"
            out.parent.mkdir(parents=True, exist_ok=True)
            sftp.get(
                "/home/fju/sensel-ot-edge-sensor/services/edgemed/artifacts/eval/official_test_full_pi.json",
                str(out),
            )
            sftp.close()
            c3.close()
            print("PI_EVAL_OK", out, flush=True)
            return 0
        if "DONEFILE" in text:
            print("PI_EVAL_FAIL", flush=True)
            return 1
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
