#!/usr/bin/env python3
"""Finish extract on Pi, upload eval script, run full official test eval."""

from __future__ import annotations

import time
from pathlib import Path

import paramiko

HOST, USER, PW = "192.168.50.90", "fju", "0000"
ROOT = Path(__file__).resolve().parents[1]


def connect() -> paramiko.SSHClient:
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
        t.set_keepalive(20)
    return c


def run(c: paramiko.SSHClient, cmd: str, timeout: int = 600) -> str:
    print(">>>", cmd[:160], flush=True)
    _, o, e = c.exec_command(cmd, timeout=timeout)
    out = o.read().decode("utf-8", "replace")
    err = e.read().decode("utf-8", "replace")
    if err.strip():
        print("ERR", err[-500:], flush=True)
    print(out[-1500:], flush=True)
    return out


def main() -> int:
    c = connect()
    run(
        c,
        "mkdir -p /home/fju/dataset; "
        "if [ ! -d /home/fju/dataset/WiFI_and_MQTTattacksCSVtest ]; then "
        "tar -xzf /home/fju/ciciomt_test_full.tgz -C /home/fju/dataset; fi; "
        "ls /home/fju/dataset/WiFI_and_MQTTattacksCSVtest | wc -l; "
        "du -sh /home/fju/dataset/WiFI_and_MQTTattacksCSVtest",
        timeout=300,
    )
    sftp = c.open_sftp()
    for rel in (
        "scripts/eval_official_test_full.py",
        "artifacts/classifiers/xgboost_binary.joblib",
        "artifacts/classifiers/xgboost_category.joblib",
        "artifacts/detector.joblib",
    ):
        local = ROOT / rel
        remote = f"/home/fju/sensel-ot-edge-sensor/services/edgemed/{rel.replace(chr(92), '/')}"
        # ensure parent
        parent = str(Path(remote).parent).replace("\\", "/")
        run(c, f"mkdir -p {parent}", timeout=30)
        print(f"put {local} -> {remote}", flush=True)
        sftp.put(str(local), remote)
    sftp.close()

    # background eval
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

    for i in range(120):
        time.sleep(10)
        c2 = connect()
        _, o, _ = c2.exec_command(
            "if [ -f /tmp/edgemed_full_eval.done ]; then cat /tmp/edgemed_full_eval.done; "
            "echo '---'; tail -n 30 /tmp/edgemed_full_eval.log; else "
            "echo WAITING; tail -n 5 /tmp/edgemed_full_eval.log 2>/dev/null; free -m | head -n 2; fi",
            timeout=40,
        )
        text = o.read().decode("utf-8", "replace")
        c2.close()
        print(f"[{i}]", text[-800:], flush=True)
        if "EXIT:" in text and "FULL_EVAL_DONE" in text:
            print("PI_EVAL_OK", flush=True)
            # fetch result
            c3 = connect()
            sftp = c3.open_sftp()
            local_out = ROOT / "artifacts" / "eval" / "official_test_full_pi.json"
            local_out.parent.mkdir(parents=True, exist_ok=True)
            sftp.get("/home/fju/sensel-ot-edge-sensor/services/edgemed/artifacts/eval/official_test_full_pi.json", str(local_out))
            sftp.close()
            c3.close()
            print("fetched", local_out, flush=True)
            return 0
        if "EXIT:" in text and "FULL_EVAL_DONE" not in text:
            print("PI_EVAL_FAIL", flush=True)
            return 1
    print("PI_EVAL_TIMEOUT", flush=True)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
