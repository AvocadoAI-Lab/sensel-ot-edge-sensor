"""Tune a centralized XGBoost oracle without touching the frozen test sets.

The search uses manifest-level attack validation files and disjoint row ranges
from Benign_train. Final reporting uses the manifest test attacks plus disjoint
complete-schema chunks from Benign_test. The complete-schema benign control is
not claimed to be device-specific camera/pager traffic.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd
from xgboost import XGBClassifier

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from app.classifier import ClassifierBundle, binary_labels, save_classifier
from app.data.ciciomt import discover_ciciomt_csv_dirs
from app.data.columns import load_column_map
from app.data.preprocess import fit_preprocessor
from scripts.run_three_site_fl_experiment import (
    SITES,
    ProcessResourceMonitor,
    _align,
    _load_named_csv,
    _load_split_frame,
    _metrics_for,
)


def _benign_chunks(
    path: Path,
    mapping: dict[str, str],
    *,
    rows_per_site: int,
    seed: int,
) -> dict[str, pd.DataFrame]:
    frame = _load_named_csv(
        path,
        mapping,
        max_rows=rows_per_site * len(SITES),
        label="Benign",
    )
    if len(frame) < rows_per_site * len(SITES):
        raise ValueError(
            f"{path} has {len(frame)} rows; need {rows_per_site * len(SITES)}"
        )
    frame = frame.sample(frac=1.0, random_state=seed).reset_index(drop=True)
    return {
        site_id: frame.iloc[
            index * rows_per_site : (index + 1) * rows_per_site
        ].copy()
        for index, site_id in enumerate(SITES)
    }


def load_tuning_frames(
    *,
    dataset_root: Path,
    splits_dir: Path,
    max_attack_rows: int,
    benign_rows_per_site: int,
    seed: int,
) -> tuple[
    dict[str, dict[str, Any]],
    dict[str, dict[str, Any]],
    dict[str, dict[str, Any]],
]:
    mapping = load_column_map()
    dirs = discover_ciciomt_csv_dirs(dataset_root)
    train_benign = _benign_chunks(
        dirs["train"] / "Benign_train.pcap.csv",
        mapping,
        rows_per_site=benign_rows_per_site * 2,
        seed=seed,
    )
    test_benign = _benign_chunks(
        dirs["test"] / "Benign_test.pcap.csv",
        mapping,
        rows_per_site=benign_rows_per_site,
        seed=seed + 1,
    )

    train_frames: dict[str, dict[str, Any]] = {}
    validation_frames: dict[str, dict[str, Any]] = {}
    test_frames: dict[str, dict[str, Any]] = {}
    for site_id in SITES:
        spec = json.loads(
            (splits_dir / f"{site_id}.json").read_text(encoding="utf-8")
        )
        split = spec["splits"]
        common = {
            "device_type": spec["device_type"],
            "attack_family": spec["attack_family"],
        }
        attack_train = _load_split_frame(
            split.get("train") or [],
            dirs["train"],
            mapping=mapping,
            max_rows=max_attack_rows,
            default_label="Attack",
        )
        attack_validation = _load_split_frame(
            split.get("validation") or [],
            dirs["train"],
            mapping=mapping,
            max_rows=max_attack_rows,
            default_label="Attack",
        )
        attack_test = _load_split_frame(
            split.get("test") or [],
            dirs["test"],
            mapping=mapping,
            max_rows=max_attack_rows,
            default_label="Attack",
        )
        benign_pool = train_benign[site_id]
        benign_train = benign_pool.iloc[:benign_rows_per_site].copy()
        benign_validation = benign_pool.iloc[benign_rows_per_site:].copy()
        train_frames[site_id] = {
            **common,
            "train": pd.concat([attack_train, benign_train], ignore_index=True),
            "test": pd.DataFrame(),
        }
        validation_frames[site_id] = {
            **common,
            "train": pd.DataFrame(),
            "test": pd.concat(
                [attack_validation, benign_validation], ignore_index=True
            ),
        }
        test_frames[site_id] = {
            **common,
            "train": pd.DataFrame(),
            "test": pd.concat(
                [attack_test, test_benign[site_id]], ignore_index=True
            ),
        }
    return train_frames, validation_frames, test_frames


def _bundle(
    model: XGBClassifier,
    *,
    features: list[str],
    preprocess: Any,
    metadata: dict[str, Any],
) -> ClassifierBundle:
    return ClassifierBundle(
        model_name="xgboost",
        task="binary",
        pipeline=model,
        features=features,
        classes=["Benign", "Attack"],
        preprocess=preprocess,
        metadata=metadata,
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset-root", type=Path, default=Path(r"D:\實習\資料集"))
    parser.add_argument(
        "--splits-dir",
        type=Path,
        default=ROOT / "artifacts" / "fl-experiment" / "splits",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=ROOT / "artifacts" / "fl-experiment" / "tuning",
    )
    parser.add_argument("--max-attack-rows-per-file", type=int, default=2000)
    parser.add_argument("--benign-rows-per-site", type=int, default=1500)
    parser.add_argument("--seed", type=int, default=20260818)
    args = parser.parse_args()

    train_frames, validation_frames, test_frames = load_tuning_frames(
        dataset_root=args.dataset_root,
        splits_dir=args.splits_dir,
        max_attack_rows=args.max_attack_rows_per_file,
        benign_rows_per_site=args.benign_rows_per_site,
        seed=args.seed,
    )
    train = pd.concat(
        [payload["train"] for payload in train_frames.values()], ignore_index=True
    )
    validation = pd.concat(
        [payload["test"] for payload in validation_frames.values()],
        ignore_index=True,
    )
    preprocess = fit_preprocessor(train, label_column="label")
    features = preprocess.features
    x_train = preprocess.transform(_align(train, features))
    y_train = binary_labels(train["label"])
    x_validation = preprocess.transform(_align(validation, features))
    y_validation = binary_labels(validation["label"])
    class_ratio = float(np.sum(y_train == 0) / np.sum(y_train == 1))

    candidates = [
        {"max_depth": 4, "learning_rate": 0.03, "min_child_weight": 1, "gamma": 0.0, "reg_alpha": 0.0, "reg_lambda": 1.0, "scale_pos_weight": 1.0},
        {"max_depth": 6, "learning_rate": 0.03, "min_child_weight": 1, "gamma": 0.0, "reg_alpha": 0.0, "reg_lambda": 1.0, "scale_pos_weight": 1.0},
        {"max_depth": 4, "learning_rate": 0.08, "min_child_weight": 1, "gamma": 0.0, "reg_alpha": 0.0, "reg_lambda": 1.0, "scale_pos_weight": 1.0},
        {"max_depth": 6, "learning_rate": 0.08, "min_child_weight": 1, "gamma": 0.0, "reg_alpha": 0.0, "reg_lambda": 1.0, "scale_pos_weight": 1.0},
        {"max_depth": 4, "learning_rate": 0.05, "min_child_weight": 5, "gamma": 0.1, "reg_alpha": 0.1, "reg_lambda": 5.0, "scale_pos_weight": class_ratio},
        {"max_depth": 6, "learning_rate": 0.05, "min_child_weight": 5, "gamma": 0.1, "reg_alpha": 0.1, "reg_lambda": 5.0, "scale_pos_weight": class_ratio},
        {"max_depth": 4, "learning_rate": 0.08, "min_child_weight": 10, "gamma": 0.2, "reg_alpha": 0.5, "reg_lambda": 10.0, "scale_pos_weight": class_ratio},
        {"max_depth": 6, "learning_rate": 0.08, "min_child_weight": 10, "gamma": 0.2, "reg_alpha": 0.5, "reg_lambda": 10.0, "scale_pos_weight": class_ratio},
    ]
    trials: list[dict[str, Any]] = []
    for index, candidate in enumerate(candidates):
        model = XGBClassifier(
            n_estimators=500,
            subsample=0.9,
            colsample_bytree=0.9,
            objective="binary:logistic",
            eval_metric="logloss",
            tree_method="hist",
            random_state=args.seed,
            n_jobs=-1,
            early_stopping_rounds=30,
            **candidate,
        )
        started = time.perf_counter()
        model.fit(
            x_train,
            y_train,
            eval_set=[(x_validation, y_validation)],
            verbose=False,
        )
        bundle = _bundle(
            model,
            features=features,
            preprocess=preprocess,
            metadata={"candidate": candidate},
        )
        metrics = _metrics_for(bundle, validation_frames)
        global_metrics = metrics["global_holdout"]
        trial = {
            "trial": index,
            "parameters": candidate,
            "best_iteration": int(model.best_iteration),
            "training_seconds": round(time.perf_counter() - started, 6),
            "selection_balanced_accuracy": global_metrics["balanced_accuracy"],
            "selection_macro_f1": global_metrics["macro_f1"],
            "selection_pr_auc": global_metrics["pr_auc"],
            "metrics": metrics,
        }
        trials.append(trial)
        print(
            f"trial={index} balanced_accuracy={trial['selection_balanced_accuracy']:.6f} "
            f"best_iteration={trial['best_iteration']}",
            flush=True,
        )

    best = max(
        trials,
        key=lambda item: (
            float(item["selection_balanced_accuracy"]),
            float(item["selection_macro_f1"]),
        ),
    )
    combined = pd.concat([train, validation], ignore_index=True)
    final_preprocess = fit_preprocessor(combined, label_column="label")
    final_features = final_preprocess.features
    x_combined = final_preprocess.transform(_align(combined, final_features))
    y_combined = binary_labels(combined["label"])
    final_parameters = dict(best["parameters"])
    final_model = XGBClassifier(
        n_estimators=int(best["best_iteration"]) + 1,
        subsample=0.9,
        colsample_bytree=0.9,
        objective="binary:logistic",
        eval_metric="logloss",
        tree_method="hist",
        random_state=args.seed,
        n_jobs=-1,
        **final_parameters,
    )
    with ProcessResourceMonitor() as monitor:
        final_model.fit(x_combined, y_combined)
    final_bundle = _bundle(
        final_model,
        features=final_features,
        preprocess=final_preprocess,
        metadata={
            "artifact_version": "0.2.0-xgb-tuned",
            "task": "binary",
            "seed": args.seed,
            "selection": "validation_balanced_accuracy_then_macro_f1",
            "parameters": final_parameters,
            "n_estimators": int(best["best_iteration"]) + 1,
            "early_stopping_rounds_during_search": 30,
            "class_imbalance": {
                "method": "scale_pos_weight_candidate_search",
                "train_negative_positive_ratio": class_ratio,
            },
            "benign_test_scope": "complete-schema common control; not device-specific profiling",
        },
    )
    final_metrics = _metrics_for(final_bundle, test_frames)
    args.output_dir.mkdir(parents=True, exist_ok=True)
    model_path = args.output_dir / "xgboost-binary-tuned.joblib"
    save_classifier(final_bundle, model_path)
    report = {
        "seed": args.seed,
        "selection_split": "manifest validation attacks + disjoint Benign_train rows",
        "test_split": "manifest test attacks + disjoint complete-schema Benign_test rows",
        "feature_count": len(final_features),
        "features": final_features,
        "data_distribution": {
            split_name: {
                site_id: {
                    "rows": int(len(payload[key])),
                    "classes": {
                        str(name): int(count)
                        for name, count in payload[key]["label"].value_counts().items()
                    },
                }
                for site_id, payload in frames.items()
            }
            for split_name, frames, key in (
                ("train", train_frames, "train"),
                ("validation", validation_frames, "test"),
                ("test", test_frames, "test"),
            )
        },
        "search": {
            "candidate_count": len(candidates),
            "early_stopping_rounds": 30,
            "primary_metric": "global validation balanced_accuracy",
            "trials": trials,
            "selected_trial": best["trial"],
        },
        "final_model": {
            "artifact": str(model_path),
            "bytes": model_path.stat().st_size,
            "parameters": final_parameters,
            "n_estimators": int(best["best_iteration"]) + 1,
            "training_resources": monitor.result,
            "test_metrics": final_metrics,
        },
        "limitations": [
            "Complete-schema benign test is a common control, not camera/pager device-specific benign traffic.",
            "The search space is deliberately small and is not proof of a globally optimal configuration.",
        ],
    }
    report_path = args.output_dir / "report.json"
    report_path.write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(f"Wrote {report_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
