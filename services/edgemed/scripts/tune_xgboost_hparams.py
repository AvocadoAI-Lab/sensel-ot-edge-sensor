#!/usr/bin/env python3
"""Grid-search XGBoost on validation files only; never touch the test split."""

from __future__ import annotations

import itertools
import json
import sys
import time
from pathlib import Path

import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from app.classifier import DEFAULT_XGB_BINARY, evaluate_classifier, load_classifier, train_classifier
from app.data.columns import load_column_map
from scripts.run_three_site_fl_experiment import _align, load_site_frames


def main() -> int:
    dataset_root = Path(r"D:\實習\資料集")
    output = ROOT / "artifacts" / "fl-experiment" / "hpo-results.json"
    mapping = load_column_map()
    frames = load_site_frames(
        splits_dir=ROOT / "artifacts" / "fl-experiment" / "splits",
        dataset_root=dataset_root,
        mapping=mapping,
        max_train=2000,
        max_test=2000,
        max_benign=3000,
        seed=20260818,
    )
    base = load_classifier(ROOT / "artifacts" / "classifiers" / "xgboost_binary.joblib")
    train = pd.concat([_align(item["train"], base.features) for item in frames.values()], ignore_index=True)
    valid = pd.concat([_align(item["validation"], base.features) for item in frames.values()], ignore_index=True)
    n_pos = int((train["label"] == "Attack").sum())
    n_neg = int((train["label"] == "Benign").sum())
    scale = round(n_neg / max(n_pos, 1), 6)

    grid = {
        "max_depth": [4, 6],
        "learning_rate": [0.05, 0.08],
        "n_estimators": [80, 120],
        "min_child_weight": [1, 5],
        "scale_pos_weight": [1.0, max(scale, 1.0)],
    }
    keys = list(grid)
    trials = []
    best = None
    for values in itertools.product(*(grid[key] for key in keys)):
        params = dict(DEFAULT_XGB_BINARY)
        params.update(dict(zip(keys, values)))
        started = time.perf_counter()
        bundle = train_classifier(
            train,
            model_name="xgboost",
            task="binary",
            seed=20260818,
            preprocess=base.preprocess,
            xgb_params=params,
            eval_frame=valid,
            early_stopping_rounds=15,
        )
        metrics = evaluate_classifier(bundle, valid)
        trial = {
            "params": params,
            "validation": {
                "balanced_accuracy": metrics.get("balanced_accuracy"),
                "macro_f1": metrics.get("macro_f1"),
                "pr_auc": metrics.get("pr_auc"),
                "fpr": metrics.get("fpr"),
                "fnr": metrics.get("fnr"),
            },
            "best_iteration": bundle.metadata.get("best_iteration"),
            "seconds": round(time.perf_counter() - started, 6),
        }
        trials.append(trial)
        score = (
            float(metrics.get("balanced_accuracy") or 0.0),
            float(metrics.get("pr_auc") or 0.0),
            -float(metrics.get("fpr") or 1.0),
        )
        if best is None or score > best[0]:
            best = (score, trial)
        print(
            f"depth={params['max_depth']} lr={params['learning_rate']} "
            f"n={params['n_estimators']} bal={metrics.get('balanced_accuracy')}",
            flush=True,
        )

    selected = dict(best[1]["params"]) if best else dict(DEFAULT_XGB_BINARY)
    if best and best[1].get("best_iteration"):
        selected["n_estimators"] = int(best[1]["best_iteration"]) + 1
    report = {
        "selection_split": "site validation files only; test unused",
        "class_counts_train": {"Attack": n_pos, "Benign": n_neg},
        "early_stopping_rounds": 15,
        "best_params": selected,
        "best_validation": best[1]["validation"] if best else {},
        "trials": trials,
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"best_params": selected, "best_validation": report["best_validation"]}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
