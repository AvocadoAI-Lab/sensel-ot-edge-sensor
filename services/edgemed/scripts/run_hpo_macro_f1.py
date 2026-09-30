#!/usr/bin/env python3
"""Grid search XGBoost hyperparameters; select by macro-F1 (accuracy-first for FL).

Uses site validation splits only (test held out). Writes JSON consumable by
``run_three_site_fl_experiment.py --xgb-params`` and cohort FL runner.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path
from typing import Any

import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from app.classifier import DEFAULT_XGB_BINARY, evaluate_classifier, train_classifier
from app.data.columns import load_column_map
from scripts.run_three_site_fl_experiment import _align, load_site_frames


def _score(metrics: dict[str, Any]) -> tuple[float, float, float]:
    return (
        float(metrics.get("macro_f1") or 0.0),
        float(metrics.get("balanced_accuracy") or 0.0),
        float(metrics.get("pr_auc") or 0.0),
    )


def main() -> int:
    parser = argparse.ArgumentParser(description="HPO for XGB binary (macro-F1 first)")
    parser.add_argument("--dataset-root", type=Path, default=Path(r"D:\實習\資料集"))
    parser.add_argument(
        "--splits-dir",
        type=Path,
        default=ROOT / "artifacts" / "fl-experiment-six" / "splits",
    )
    parser.add_argument("--seed", type=int, default=20260818)
    parser.add_argument("--output", type=Path, default=ROOT / "artifacts" / "hpo-macro-f1-results.json")
    parser.add_argument("--max-train", type=int, default=2500)
    parser.add_argument("--max-test", type=int, default=2500)
    parser.add_argument("--max-benign", type=int, default=3500)
    args = parser.parse_args()

    mapping = load_column_map()
    site_ids = tuple(p.stem for p in sorted(args.splits_dir.glob("site-*.json")))
    if not site_ids:
        raise SystemExit(f"No site manifests under {args.splits_dir}")

    frames = load_site_frames(
        splits_dir=args.splits_dir,
        dataset_root=args.dataset_root,
        mapping=mapping,
        max_train=args.max_train,
        max_test=args.max_test,
        max_benign=args.max_benign,
        seed=args.seed,
        site_ids=site_ids,
    )
    base = __import__(
        "app.classifier", fromlist=["load_classifier"]
    ).load_classifier(ROOT / "artifacts" / "classifiers" / "xgboost_binary.joblib")

    train = pd.concat([_align(item["train"], base.features) for item in frames.values()], ignore_index=True)
    valid = pd.concat([_align(item["validation"], base.features) for item in frames.values()], ignore_index=True)
    n_pos = int((train["label"] == "Attack").sum())
    n_neg = int((train["label"] == "Benign").sum())
    class_ratio = round(n_neg / max(n_pos, 1), 6)

    # Curated grid (~32 trials): depth/lr/regularization + class imbalance.
    candidates: list[dict[str, Any]] = []
    for max_depth, learning_rate, min_child_weight, gamma, reg_alpha, reg_lambda in [
        (4, 0.03, 1, 0.0, 0.0, 1.0),
        (6, 0.03, 1, 0.0, 0.0, 1.0),
        (8, 0.03, 1, 0.0, 0.0, 1.0),
        (4, 0.05, 5, 0.1, 0.1, 5.0),
        (6, 0.05, 5, 0.1, 0.1, 5.0),
        (8, 0.05, 5, 0.1, 0.1, 5.0),
        (4, 0.08, 1, 0.0, 0.0, 1.0),
        (6, 0.08, 1, 0.0, 0.0, 1.0),
        (8, 0.08, 1, 0.0, 0.0, 1.0),
        (4, 0.08, 10, 0.2, 0.5, 10.0),
        (6, 0.08, 10, 0.2, 0.5, 10.0),
        (8, 0.08, 10, 0.2, 0.5, 10.0),
    ]:
        for scale_pos_weight in (1.0, class_ratio):
            for n_estimators in (120, 200):
                candidates.append(
                    {
                        "max_depth": max_depth,
                        "learning_rate": learning_rate,
                        "min_child_weight": min_child_weight,
                        "gamma": gamma,
                        "reg_alpha": reg_alpha,
                        "reg_lambda": reg_lambda,
                        "scale_pos_weight": scale_pos_weight,
                        "n_estimators": n_estimators,
                    }
                )

    trials: list[dict[str, Any]] = []
    best: tuple[tuple[float, float, float], dict[str, Any]] | None = None
    total = len(candidates)
    print(f"HPO sites={len(site_ids)} trials={total} selection=macro_f1", flush=True)

    for index, candidate in enumerate(candidates):
        params = dict(DEFAULT_XGB_BINARY)
        params.update(candidate)
        started = time.perf_counter()
        bundle = train_classifier(
            train,
            model_name="xgboost",
            task="binary",
            seed=args.seed,
            preprocess=base.preprocess,
            xgb_params=params,
            eval_frame=valid,
            early_stopping_rounds=20,
        )
        metrics = evaluate_classifier(bundle, valid)
        trial = {
            "trial": index,
            "params": candidate,
            "validation": {
                "macro_f1": metrics.get("macro_f1"),
                "balanced_accuracy": metrics.get("balanced_accuracy"),
                "accuracy": metrics.get("accuracy"),
                "pr_auc": metrics.get("pr_auc"),
                "fpr": metrics.get("fpr"),
                "fnr": metrics.get("fnr"),
            },
            "best_iteration": bundle.metadata.get("best_iteration"),
            "seconds": round(time.perf_counter() - started, 6),
        }
        trials.append(trial)
        score = _score(metrics)
        if best is None or score > best[0]:
            best = (score, trial)
        print(
            f"[{index + 1}/{total}] macro_f1={metrics.get('macro_f1'):.4f} "
            f"depth={params['max_depth']} lr={params['learning_rate']} "
            f"mcw={params['min_child_weight']} spw={params['scale_pos_weight']}",
            flush=True,
        )

    assert best is not None
    selected = dict(best[1]["params"])
    if best[1].get("best_iteration"):
        selected["n_estimators"] = int(best[1]["best_iteration"]) + 1

    report = {
        "selection_criterion": "macro_f1_then_balanced_accuracy_then_pr_auc",
        "selection_split": "site validation only; test unused",
        "seed": args.seed,
        "site_ids": list(site_ids),
        "splits_dir": str(args.splits_dir),
        "class_counts_train": {"Attack": n_pos, "Benign": n_neg},
        "best_params": selected,
        "best_validation": best[1]["validation"],
        "baseline_default_validation": None,
        "trials": trials,
    }

    # baseline for comparison
    baseline_params = dict(DEFAULT_XGB_BINARY)
    baseline_bundle = train_classifier(
        train,
        model_name="xgboost",
        task="binary",
        seed=args.seed,
        preprocess=base.preprocess,
        xgb_params=baseline_params,
        eval_frame=valid,
        early_stopping_rounds=20,
    )
    report["baseline_default_validation"] = evaluate_classifier(baseline_bundle, valid)

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(
        json.dumps(
            {
                "best_params": selected,
                "best_macro_f1": best[1]["validation"]["macro_f1"],
                "baseline_macro_f1": report["baseline_default_validation"].get("macro_f1"),
                "output": str(args.output),
            },
            indent=2,
        ),
        flush=True,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
