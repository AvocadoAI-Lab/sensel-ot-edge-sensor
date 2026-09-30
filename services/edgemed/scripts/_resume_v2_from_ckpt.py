#!/usr/bin/env python3
"""Resume V2 from checkpoint: finish Pi tests + write MD."""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path

import httpx

# reuse helpers from compare script
sys.path.insert(0, str(Path(__file__).resolve().parent))
from compare_pc_pi_v2 import (  # noqa: E402
    OUT,
    PI,
    REMOTE,
    ROOT,
    _pi_start_api,
    _pi_stop_api,
    _ssh_cat,
    _ssh_exec,
    render,
)

CKPT = ROOT / "docs" / "_v2_checkpoint.json"


def _ssh_exec_safe(cmd: str, timeout: int = 30) -> tuple[int, str]:
    try:
        return _ssh_exec(cmd, timeout=timeout)
    except Exception as exc:
        return -1, f"ERR:{exc}"


def one(label: str, py_args: str, max_wait_s: int = 2400) -> dict:
    log = f"/tmp/edgemed_v2_{label}.log"
    marker = f"/tmp/edgemed_v2_{label}.done"
    t0 = time.perf_counter()

    # resume if previous run left a done marker
    done_existing = _ssh_cat(marker)
    if done_existing is not None:
        text = _ssh_cat(log) or ""
        code = 1
        for line in done_existing.splitlines():
            if line.startswith("EXIT:"):
                try:
                    code = int(line.split(":", 1)[1].strip())
                except ValueError:
                    code = 1
        summary = ""
        for line in text.splitlines()[::-1]:
            if line.startswith("OK") or line.startswith("FAILED"):
                summary = line
                break
        print(f"  Pi {label}: reuse existing result {summary or code}", flush=True)
        return {
            "returncode": code,
            "latency_ms": 0.0,
            "summary": summary or ("pass" if code == 0 else "fail"),
            "tail": text[-1800:],
        }

    _ssh_exec_safe(f"rm -f {log} {marker}")
    time.sleep(0.5)
    # write launcher script to avoid paramiko & issues
    launcher = f"/tmp/run_edgemed_{label}.sh"
    body = (
        "#!/bin/bash\n"
        f"cd {REMOTE}\n"
        "source .venv/bin/activate\n"
        "export OMP_NUM_THREADS=1 OPENBLAS_NUM_THREADS=1 MKL_NUM_THREADS=1\n"
        f"python -m unittest {py_args} -v >{log} 2>&1\n"
        f"echo EXIT:$? >{marker}\n"
    )
    # upload via printf over ssh
    import base64

    b64 = base64.b64encode(body.encode()).decode()
    _ssh_exec_safe(f"echo {b64} | base64 -d > {launcher} && chmod +x {launcher}")
    _ssh_exec_safe(f"nohup bash {launcher} >/dev/null 2>&1 & echo LAUNCHED")
    print(f"  Pi {label}: launched", flush=True)

    text = ""
    exit_code = 1
    while True:
        elapsed = time.perf_counter() - t0
        if elapsed > max_wait_s:
            text = _ssh_cat(log) or text
            return {
                "returncode": -1,
                "latency_ms": round(elapsed * 1000, 1),
                "summary": "TIMEOUT",
                "tail": (text or "")[-1800:],
            }
        time.sleep(15)
        _, up = _ssh_exec_safe("cut -d. -f1 /proc/uptime || echo 9999")
        try:
            up_s = int((up or "9999").strip().split()[0])
        except Exception:
            up_s = 9999
        if up_s < 90 and elapsed > 120:
            text = (_ssh_cat(log) or "") + "\n[host rebooted — likely OOM]"
            return {
                "returncode": -2,
                "latency_ms": round(elapsed * 1000, 1),
                "summary": "HOST_REBOOT_LIKELY_OOM",
                "tail": text[-1800:],
            }
        done = _ssh_cat(marker)
        if done is None:
            if int(elapsed) % 60 < 20:
                _, ps = _ssh_exec_safe(
                    "pgrep -af 'python -m unittest' || true; "
                    f"wc -c {log} 2>/dev/null || true; free -m | head -n 2"
                )
                print(f"  Pi {label}: waiting {int(elapsed)}s | {ps.strip()[:180]}", flush=True)
            continue
        text = _ssh_cat(log) or ""
        for line in done.splitlines():
            if line.startswith("EXIT:"):
                try:
                    exit_code = int(line.split(":", 1)[1].strip())
                except ValueError:
                    exit_code = 1
        break
    summary = ""
    for line in text.splitlines()[::-1]:
        if line.startswith("OK") or line.startswith("FAILED"):
            summary = line
            break
    return {
        "returncode": exit_code,
        "latency_ms": round((time.perf_counter() - t0) * 1000, 1),
        "summary": summary or ("pass" if exit_code == 0 else "fail"),
        "tail": text[-1800:],
    }


def start_api_solid() -> None:
    print("  restarting Pi API (solid)...", flush=True)
    _ssh_exec_safe("pkill -f 'uvicorn app.main:app' || true")
    time.sleep(1)
    body = (
        "#!/bin/bash\n"
        f"cd {REMOTE}\n"
        "source .venv/bin/activate\n"
        "export OMP_NUM_THREADS=1 OPENBLAS_NUM_THREADS=1\n"
        "nohup uvicorn app.main:app --host 0.0.0.0 --port 8000 "
        ">/tmp/edgemed-uvicorn.log 2>&1 &\n"
        "echo $! > /tmp/edgemed-uvicorn.pid\n"
    )
    import base64

    b64 = base64.b64encode(body.encode()).decode()
    _ssh_exec_safe(f"echo {b64} | base64 -d > /tmp/start_edgemed_api.sh && chmod +x /tmp/start_edgemed_api.sh")
    _ssh_exec_safe("bash /tmp/start_edgemed_api.sh", timeout=20)
    for i in range(40):
        time.sleep(3)
        try:
            r = httpx.get(f"{PI}/health", timeout=8)
            if r.status_code == 200:
                print(f"  Pi API back ({i})", flush=True)
                return
        except Exception:
            pass
    print("  WARN: Pi API not back", flush=True)


def main() -> int:
    data = json.loads(CKPT.read_text(encoding="utf-8"))
    pc, pi, pc_t = data["pc"], data["pi"], data["pc_t"]
    print("resuming Pi tests from checkpoint...", flush=True)
    _pi_stop_api()
    try:
        pi_t = {
            "dataset": one(
                "dataset",
                "tests.test_dataset_m1 tests.test_ciciomt_prepare",
                max_wait_s=900,
            ),
            "full": one("full", "discover -s tests", max_wait_s=2400),
        }
    finally:
        start_api_solid()
    text = render(pc, pi, pc_t, pi_t)
    OUT.write_text(text, encoding="utf-8")
    print(f"wrote {OUT}", flush=True)
    print("V2_DONE", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
