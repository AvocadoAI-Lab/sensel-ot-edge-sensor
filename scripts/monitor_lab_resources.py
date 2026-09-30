#!/usr/bin/env python3
"""Continuously sample PC Docker and Pi resources for short or soak tests."""

from __future__ import annotations

import argparse
import json
import statistics
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from _pi_reboot_bringup import connect


PI_COMMAND = r"""python3 - <<'PY'
import json, os, shutil
mem = {}
with open("/proc/meminfo", encoding="utf-8") as handle:
    for line in handle:
        key, value = line.split(":", 1)
        if key in {"MemTotal", "MemAvailable", "SwapTotal", "SwapFree"}:
            mem[key] = int(value.strip().split()[0]) * 1024
net = {}
with open("/proc/net/dev", encoding="utf-8") as handle:
    for line in handle:
        if ":" not in line:
            continue
        name, values = line.split(":", 1)
        fields = values.split()
        if name.strip() != "lo":
            net[name.strip()] = {"rx_bytes": int(fields[0]), "tx_bytes": int(fields[8])}
disk = shutil.disk_usage("/")
print(json.dumps({
    "load_average": os.getloadavg(),
    "memory": mem,
    "disk": {"total": disk.total, "used": disk.used, "free": disk.free},
    "network": net,
}))
PY"""


def utc() -> str:
    return datetime.now(timezone.utc).isoformat()


def docker_snapshot() -> list[dict[str, Any]]:
    result = subprocess.run(
        ["docker", "stats", "--no-stream", "--format", "{{json .}}"],
        capture_output=True,
        text=True,
        check=False,
    )
    return [
        json.loads(line)
        for line in result.stdout.splitlines()
        if line.strip()
    ]


def pi_snapshot(client: Any) -> dict[str, Any]:
    _, stdout, stderr = client.exec_command(PI_COMMAND, timeout=20)
    raw = stdout.read().decode("utf-8", "replace").strip()
    error = stderr.read().decode("utf-8", "replace").strip()
    if error:
        raise RuntimeError(error)
    return json.loads(raw)


def percentile(values: list[float], percentile_value: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    index = min(round((len(ordered) - 1) * percentile_value), len(ordered) - 1)
    return round(ordered[index], 3)


def aggregate(samples: list[dict[str, Any]]) -> dict[str, Any]:
    pi_load = [float(sample["pi"]["load_average"][0]) for sample in samples]
    pi_memory_used = [
        (
            sample["pi"]["memory"]["MemTotal"]
            - sample["pi"]["memory"]["MemAvailable"]
        )
        / 1024
        / 1024
        for sample in samples
    ]
    containers: dict[str, list[float]] = {}
    for sample in samples:
        for row in sample["docker"]:
            name = str(row["Name"])
            containers.setdefault(name, []).append(
                float(str(row["CPUPerc"]).rstrip("%"))
            )
    return {
        "samples": len(samples),
        "pi_load_1m": {
            "mean": round(statistics.mean(pi_load), 3) if pi_load else None,
            "p95": percentile(pi_load, 0.95),
            "maximum": round(max(pi_load), 3) if pi_load else None,
        },
        "pi_memory_used_mb": {
            "mean": round(statistics.mean(pi_memory_used), 3)
            if pi_memory_used
            else None,
            "p95": percentile(pi_memory_used, 0.95),
            "maximum": round(max(pi_memory_used), 3)
            if pi_memory_used
            else None,
        },
        "docker_cpu_percent": {
            name: {
                "mean": round(statistics.mean(values), 3),
                "p95": percentile(values, 0.95),
                "maximum": round(max(values), 3),
            }
            for name, values in sorted(containers.items())
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--duration-seconds", type=int, default=60)
    parser.add_argument("--duration-hours", type=float)
    parser.add_argument("--interval-seconds", type=float, default=5)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    duration = (
        args.duration_hours * 3600
        if args.duration_hours is not None
        else args.duration_seconds
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    client = connect()
    started = time.monotonic()
    started_at = utc()
    samples: list[dict[str, Any]] = []
    try:
        while True:
            sample_started = time.monotonic()
            samples.append(
                {
                    "timestamp": utc(),
                    "elapsed_seconds": round(sample_started - started, 3),
                    "docker": docker_snapshot(),
                    "pi": pi_snapshot(client),
                }
            )
            if time.monotonic() - started >= duration:
                break
            time.sleep(
                max(
                    0.0,
                    args.interval_seconds - (time.monotonic() - sample_started),
                )
            )
    finally:
        client.close()
    report = {
        "started_at": started_at,
        "completed_at": utc(),
        "requested_duration_seconds": duration,
        "actual_duration_seconds": round(time.monotonic() - started, 3),
        "interval_seconds": args.interval_seconds,
        "summary": aggregate(samples),
        "samples": samples,
        "scope": (
            "soak_test" if duration >= 3600 else "short_resource_sampling_not_soak"
        ),
    }
    args.output.write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(report["summary"], ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
