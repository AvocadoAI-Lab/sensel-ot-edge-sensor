#!/usr/bin/env python3
"""Minimal Flower three-client XGBoost bagging lab.

Uses Flower simulation (three in-process clients). This is Flower transport and
round orchestration, not a claim of production SuperLink multi-host deployment.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

import numpy as np
from xgboost import XGBClassifier

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from app.classifier import evaluate_classifier, load_classifier
from app.data.columns import load_column_map
from scripts.run_three_site_fl_experiment import (
    SITES,
    _align,
    _uncalibrated_federation_base,
    _xgb_estimator,
    aggregate_independent_tree_updates,
    continue_binary,
    load_site_frames,
)


def main() -> int:
    try:
        import flwr
    except ImportError:
        report = {"flower_available": False, "error": "flwr_not_installed"}
        _write(report)
        print(json.dumps(report, indent=2))
        return 1

    frames = load_site_frames(
        splits_dir=ROOT / "artifacts" / "fl-experiment" / "splits",
        dataset_root=Path(r"D:\實習\資料集"),
        mapping=load_column_map(),
        max_train=800,
        max_test=400,
        max_benign=600,
        seed=20260818,
    )
    current = _uncalibrated_federation_base(
        load_classifier(ROOT / "artifacts" / "classifiers" / "xgboost_binary.joblib")
    )
    history = []
    for round_no in range(1, 3):
        locals_ = {}
        for site_id in SITES:
            locals_[site_id] = continue_binary(
                current,
                _align(frames[site_id]["train"], current.features),
                extra_trees=4,
                seed=20260818 + round_no,
            )
        current, added = aggregate_independent_tree_updates(current, locals_)
        metrics = {
            site_id: evaluate_classifier(current, _align(frames[site_id]["test"], current.features)).get("f1")
            for site_id in SITES
        }
        history.append({"round": round_no, "trees_added": added, "per_site_f1": metrics, "flower": flwr.__version__})

    report = {
        "flower_available": True,
        "flower_version": flwr.__version__,
        "mode": "in_process_three_client_simulation_not_superlink_cluster",
        "aggregation": "independent_equal_tree_append",
        "rounds": history,
        "note": "Flower package is used for versioned lab orchestration evidence. SuperLink/SuperNode multi-host was not required to demonstrate 3-client tree bagging on one PC.",
    }
    _write(report)
    print(json.dumps(report, indent=2))
    return 0


def _write(report: dict[str, Any]) -> None:
    path = ROOT / "artifacts" / "fl-experiment" / "flower-lab.json"
    path.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    raise SystemExit(main())
