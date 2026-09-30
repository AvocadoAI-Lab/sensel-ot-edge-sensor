#!/usr/bin/env python3
"""Verify that the Pi FL worker rejects a mismatched global-model checksum."""

from __future__ import annotations

import argparse
import json
import time
from datetime import datetime, timezone
from pathlib import Path

from _pi_reboot_bringup import connect
from lab_paths import EDGEMED_ROOT, PI_EDGEMED_ROOT


ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    remote_root = PI_EDGEMED_ROOT
    exchange = f"{remote_root}/data/hybrid-pi-fl"
    worker = f"{remote_root}/scripts/pi_xgb_local_update.py"
    client = connect()
    sftp = client.open_sftp()
    started = time.perf_counter()
    sftp.put(str(EDGEMED_ROOT / "scripts" / "pi_xgb_local_update.py"), worker)
    transfer_seconds = time.perf_counter() - started
    worker_bytes = int(sftp.stat(worker).st_size)
    sftp.close()
    command = (
        f"cd {remote_root} && .venv/bin/python scripts/pi_xgb_local_update.py "
        f"--global-model {exchange}/global.json "
        f"--local-csv {exchange}/site-bpm-local-train.csv "
        f"--classifier-bundle artifacts/classifiers/xgboost_binary.joblib "
        f"--output-model {exchange}/should-not-exist.json "
        f"--report {exchange}/checksum-rejection.json "
        f"--expected-global-sha256 {'0' * 64}"
    )
    _, stdout, stderr = client.exec_command(command, timeout=120)
    output = stdout.read().decode("utf-8", "replace").strip()
    error = stderr.read().decode("utf-8", "replace").strip()
    status = stdout.channel.recv_exit_status()
    sftp = client.open_sftp()
    with sftp.open(f"{exchange}/checksum-rejection.json", "r") as handle:
        rejection = json.loads(handle.read().decode("utf-8"))
    output_exists = True
    try:
        sftp.stat(f"{exchange}/should-not-exist.json")
    except FileNotFoundError:
        output_exists = False
    sftp.close()
    client.close()
    report = {
        "tested_at": datetime.now(timezone.utc).isoformat(),
        "worker_transfer": {
            "bytes": worker_bytes,
            "seconds": round(transfer_seconds, 6),
        },
        "exit_status": status,
        "stdout": output,
        "stderr": error,
        "rejection": rejection,
        "rejected": status == 2
        and rejection.get("reason") == "global_model_sha256_mismatch",
        "output_model_created": output_exists,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0 if report["rejected"] and not output_exists else 1


if __name__ == "__main__":
    raise SystemExit(main())
