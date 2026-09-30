#!/usr/bin/env python3
"""Record Raspberry Pi 5 edge measurements when hardware is available.

This script intentionally no-ops with a structured unavailable report on
non-Pi hosts so CI/dev machines do not invent latency numbers.
"""

from __future__ import annotations

import argparse
import json
import platform
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", default=str(ROOT / "artifacts" / "pi5_measurements.json"))
    args = parser.parse_args()

    machine = platform.machine().lower()
    system = platform.system().lower()
    looks_like_pi = "aarch64" in machine and "linux" in system
    report = {
        "recorded_at": datetime.now(timezone.utc).isoformat(),
        "host": platform.platform(),
        "status": "unavailable" if not looks_like_pi else "ready_for_manual_fill",
        "targets": {
            "slm_p95_latency_sec": None,
            "detector_p95_latency_ms": None,
            "peak_rss_gb": None,
            "cpu_temp_c": None,
        },
        "gates": {
            "slm_p95_le_10s": None,
            "detector_p95_le_500ms": None,
            "peak_rss_le_4gb": None,
        },
        "notes": [
            "Do not fabricate Pi 5 measurements on developer laptops.",
            "Fill targets after running warm-start single-event inference on Pi 5 8GB.",
        ],
    }
    Path(args.output).parent.mkdir(parents=True, exist_ok=True)
    Path(args.output).write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
