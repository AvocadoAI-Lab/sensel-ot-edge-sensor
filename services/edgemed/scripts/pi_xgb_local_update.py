#!/usr/bin/env python3
"""Train one XGBoost tree update on data stored locally on a Pi."""

from __future__ import annotations

import argparse
import hashlib
import json
import resource
import sys
import time
from pathlib import Path

import numpy as np
import pandas as pd
import xgboost as xgb
from xgboost import XGBClassifier

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from app.classifier import binary_labels, load_classifier


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--global-model", type=Path, required=True)
    parser.add_argument("--local-csv", type=Path, required=True)
    parser.add_argument("--classifier-bundle", type=Path, required=True)
    parser.add_argument("--output-model", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--expected-global-sha256")
    parser.add_argument("--extra-trees", type=int, default=8)
    parser.add_argument("--seed", type=int, default=20260818)
    args = parser.parse_args()

    started = time.perf_counter()
    global_sha256 = sha256_file(args.global_model)
    if (
        args.expected_global_sha256
        and global_sha256 != args.expected_global_sha256
    ):
        rejection = {
            "site_id": "site-bpm",
            "accepted": False,
            "reason": "global_model_sha256_mismatch",
            "expected_sha256": args.expected_global_sha256,
            "actual_sha256": global_sha256,
        }
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(
            json.dumps(rejection, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        print(json.dumps(rejection, ensure_ascii=False))
        return 2
    frame = pd.read_csv(args.local_csv)
    bundle = load_classifier(args.classifier_bundle)
    for feature in bundle.features:
        if feature not in frame.columns:
            frame[feature] = np.nan
    matrix = bundle.preprocess.transform(frame)
    labels = binary_labels(frame["label"])
    if len(np.unique(labels)) < 2:
        raise ValueError("Pi local update requires both Benign and Attack rows")

    booster = xgb.Booster()
    booster.load_model(args.global_model)
    rounds_before = int(booster.num_boosted_rounds())
    model = XGBClassifier(
        n_estimators=args.extra_trees,
        max_depth=6,
        learning_rate=0.08,
        subsample=0.9,
        colsample_bytree=0.9,
        objective="binary:logistic",
        eval_metric="logloss",
        tree_method="hist",
        random_state=args.seed,
        n_jobs=2,
    )
    model.fit(matrix, labels, xgb_model=booster)
    args.output_model.parent.mkdir(parents=True, exist_ok=True)
    model.save_model(args.output_model)
    rounds_after = int(model.get_booster().num_boosted_rounds())
    report = {
        "site_id": "site-bpm",
        "execution_host": "raspberry-pi",
        "training_rows": int(len(frame)),
        "classes": {
            "Benign": int(np.sum(labels == 0)),
            "Attack": int(np.sum(labels == 1)),
        },
        "feature_count": len(bundle.features),
        "rounds_before": rounds_before,
        "rounds_after": rounds_after,
        "trees_added": rounds_after - rounds_before,
        "wall_seconds": round(time.perf_counter() - started, 6),
        "peak_rss_mb": round(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024, 3),
        "output_bytes": args.output_model.stat().st_size,
        "output_sha256": sha256_file(args.output_model),
        "global_model_sha256": global_sha256,
        "accepted": True,
        "xgboost_version": xgb.__version__,
    }
    args.report.write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(report, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
