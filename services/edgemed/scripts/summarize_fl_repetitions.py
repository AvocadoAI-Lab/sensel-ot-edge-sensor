#!/usr/bin/env python3
"""Summarize three corrected federated-XGBoost proxy repetitions."""

from __future__ import annotations

import json
import statistics
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
INPUTS = (
    ROOT / "artifacts" / "fl-experiment" / "summary.json",
    ROOT / "artifacts" / "fl-experiment-repeats" / "seed-20260819" / "summary.json",
    ROOT / "artifacts" / "fl-experiment-repeats" / "seed-20260820" / "summary.json",
)
OUTPUT = ROOT / "artifacts" / "fl-experiment" / "repetition-summary.json"


def stats(values: list[float]) -> dict[str, float]:
    return {
        "mean": round(statistics.mean(values), 6),
        "sample_standard_deviation": round(statistics.stdev(values), 6),
        "minimum": round(min(values), 6),
        "maximum": round(max(values), 6),
    }


def main() -> int:
    runs = [json.loads(path.read_text(encoding="utf-8")) for path in INPUTS]
    metrics = (
        "E0_round0_macro_f1",
        "E1_local_cross_site_macro_f1_mean",
        "E2_round5_macro_f1",
        "E3_centralized_macro_f1",
    )
    report: dict[str, Any] = {
        "runs": len(runs),
        "seeds": [int(run["seed"]) for run in runs],
        "metric_definition": "unweighted mean of per-site Attack-class F1",
        "metrics": {
            name: stats([float(run[name]) for run in runs])
            for name in metrics
        },
        "rounds": {},
    }
    for round_no in range(1, 6):
        values = [
            float(run["federated_rounds"][round_no - 1]["macro_f1"])
            for run in runs
        ]
        report["rounds"][str(round_no)] = stats(values)
    OUTPUT.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
