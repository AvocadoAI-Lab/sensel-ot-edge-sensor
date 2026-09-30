#!/usr/bin/env python3
"""Finalize V2 MD: restart PC, re-probe both sides (keep prior unittest numbers)."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from pathlib import Path

import httpx

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from compare_pc_pi_v2 import (  # noqa: E402
    OUT,
    PC,
    PI,
    ensure_pc_server,
    probe,
    render,
    run_pc_tests,
    run_pi_tests,
)


def main() -> int:
    os.chdir(ROOT)
    print("ensure PC SLM...", flush=True)
    # force restart so health includes backend field
    if os.name == "nt":
        subprocess.run(
            [
                "powershell",
                "-NoProfile",
                "-Command",
                "Get-NetTCPConnection -LocalPort 8000 -EA SilentlyContinue | "
                "ForEach-Object { Stop-Process -Id $_.OwningProcess -Force -EA SilentlyContinue }",
            ],
            check=False,
        )
        time.sleep(2)
    ensure_pc_server()

    print("probe PC...", flush=True)
    pc = probe(PC, "PC")
    print("probe Pi...", flush=True)
    pi = probe(PI, "Pi")
    print("PC tests...", flush=True)
    pc_t = run_pc_tests()
    # reuse prior Pi unittest outcomes from last successful remote run if API must stay up;
    # still run dataset quickly on Pi via SSH through run_pi_tests (stops API briefly).
    print("Pi tests...", flush=True)
    pi_t = run_pi_tests()
    text = render(pc, pi, pc_t, pi_t)
    OUT.write_text(text, encoding="utf-8")
    print(f"wrote {OUT}", flush=True)
    print("V2_DONE", flush=True)
    # also dump compact JSON for debug
    (ROOT / "docs" / "_v2_last_probe.json").write_text(
        json.dumps(
            {
                "pc_health": (pc.get("health") or {}).get("body"),
                "pi_health": (pi.get("health") or {}).get("body"),
                "pc_cold": pc.get("score_cold_summary"),
                "pi_cold": pi.get("score_cold_summary"),
                "pc_score": pc.get("score_summary"),
                "pi_score": pi.get("score_summary"),
                "pc_inv": pc.get("investigate_summary"),
                "pi_inv": pi.get("investigate_summary"),
                "pc_lstm": pc.get("lstm_final"),
                "pi_lstm": pi.get("lstm_final"),
            },
            ensure_ascii=False,
            indent=2,
        ),
        encoding="utf-8",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
