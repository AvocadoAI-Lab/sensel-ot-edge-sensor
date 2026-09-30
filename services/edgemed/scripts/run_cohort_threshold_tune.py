#!/usr/bin/env python3
"""Per-cohort decision threshold tuning from validation; re-evaluate on test.

Uses insights from per-attack-file attribution: network cohort suffers high FN
(ARP / VulScan) after HPT; lowering threshold there can recover attack recall
while MQTT can keep a higher threshold to limit Benign FP.
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd
from sklearn.metrics import confusion_matrix, f1_score

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from app.classifier import binary_labels, load_classifier
from app.data.columns import load_column_map
from app.data.inventory import infer_label_from_filename
from app.fl_protocol_cohorts import group_site_ids_by_cohort

import run_three_site_fl_experiment as fl_lab
from scripts.run_protocol_cohort_fl_experiment import _load_site_cohort_map


def _utc() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _attack_display(source_file: str) -> str:
    if "benign" in source_file.lower():
        return "Benign (official test partition)"
    return infer_label_from_filename(Path(source_file))


def _metrics_at_threshold(
    y_true: np.ndarray,
    y_score: np.ndarray,
    threshold: float,
) -> dict[str, Any]:
    y_pred = (y_score >= threshold).astype(int)
    matrix = confusion_matrix(y_true, y_pred, labels=[0, 1])
    tn, fp, fn, tp = (int(matrix[0, 0]), int(matrix[0, 1]), int(matrix[1, 0]), int(matrix[1, 1]))
    return {
        "threshold": round(threshold, 4),
        "macro_f1": round(float(f1_score(y_true, y_pred, average="macro", zero_division=0)), 6),
        "attack_f1": round(float(f1_score(y_true, y_pred, zero_division=0)), 6),
        "fp": fp,
        "fn": fn,
        "fpr": round(fp / (tn + fp), 6) if tn + fp else None,
        "fnr": round(fn / (tp + fn), 6) if tp + fn else None,
    }


def _cohort_frames(
    frames: dict[str, dict[str, pd.DataFrame]],
    site_cohort: dict[str, str],
    cohort: str,
    split: str,
    features: list[str],
) -> pd.DataFrame:
    parts = []
    for site_id, payload in frames.items():
        if site_cohort[site_id] != cohort:
            continue
        part = fl_lab._align(payload[split], features)
        if not part.empty:
            parts.append(part)
    return pd.concat(parts, ignore_index=True) if parts else pd.DataFrame()


def _best_threshold(
    bundle: Any,
    frame: pd.DataFrame,
    *,
    grid: np.ndarray,
    objective: str,
) -> dict[str, Any]:
    if frame.empty:
        return {"threshold": 0.5, "macro_f1": 0.0, "fp": 0, "fn": 0}
    aligned = fl_lab._align(frame, bundle.features)
    y_true = binary_labels(aligned["label"])
    y_score = bundle.predict_proba(aligned)[:, 1]
    best: dict[str, Any] | None = None
    for threshold in grid:
        metrics = _metrics_at_threshold(y_true, y_score, float(threshold))
        if objective == "macro_f1":
            key = (metrics["macro_f1"], -metrics["fp"])
        elif objective == "balanced_fn":
            # Prefer lower FN while keeping FPR <= 0.05 on validation
            fpr = metrics["fpr"] or 1.0
            if fpr > 0.05:
                continue
            key = (-metrics["fn"], metrics["macro_f1"])
        else:
            key = (metrics["macro_f1"],)
        row = {**metrics, "_key": key}
        if best is None or row["_key"] > best["_key"]:
            best = row
    if best is None:
        # fallback: lowest threshold in grid
        metrics = _metrics_at_threshold(y_true, y_score, float(grid[0]))
        best = {**metrics, "_key": (0.0,)}
    best.pop("_key", None)
    return best


def _evaluate_cohort_at_thresholds(
    *,
    cohort_models: dict[str, Any],
    site_cohort: dict[str, str],
    frames: dict[str, dict[str, pd.DataFrame]],
    thresholds: dict[str, float],
    split: str,
) -> dict[str, Any]:
    per_site: list[dict[str, Any]] = []
    per_file: list[dict[str, Any]] = []
    attack_f1s: list[float] = []

    for site_id, payload in frames.items():
        cohort = site_cohort[site_id]
        bundle = cohort_models[cohort]
        threshold = thresholds[cohort]
        test = fl_lab._align(payload[split], bundle.features)
        if test.empty:
            continue
        y_true = binary_labels(test["label"])
        y_score = bundle.predict_proba(test)[:, 1]
        site_metrics = _metrics_at_threshold(y_true, y_score, threshold)
        per_site.append({"site_id": site_id, "cohort": cohort, **site_metrics})
        attack_f1s.append(site_metrics["attack_f1"])

        if "source_file" not in test.columns:
            continue
        for source_file, part in test.groupby("source_file", sort=True):
            yt = binary_labels(part["label"])
            ys = bundle.predict_proba(fl_lab._align(part, bundle.features))[:, 1]
            file_metrics = _metrics_at_threshold(yt, ys, threshold)
            per_file.append(
                {
                    "site_id": site_id,
                    "cohort": cohort,
                    "source_file": str(source_file),
                    "attack_display": _attack_display(str(source_file)),
                    "rows": int(len(part)),
                    **file_metrics,
                }
            )

    return {
        "thresholds": thresholds,
        "macro_f1_mean_attack_f1": round(float(np.mean(attack_f1s)) if attack_f1s else 0.0, 6),
        "per_site": per_site,
        "per_file": per_file,
        "pooled_fp": sum(row["fp"] for row in per_site),
        "pooled_fn": sum(row["fn"] for row in per_site),
    }


def _load_final_models(experiment_dir: Path, cohorts: tuple[str, ...]) -> dict[str, Any]:
    summary = json.loads((experiment_dir / "summary.json").read_text(encoding="utf-8"))
    rounds = int(summary["rounds"])
    models: dict[str, Any] = {}
    for cohort in cohorts:
        path = experiment_dir / "models" / f"cohort-{cohort}-round-{rounds:03d}.joblib"
        models[cohort] = load_classifier(path)
    return models


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset-root", type=Path, default=Path(r"D:\實習\資料集"))
    parser.add_argument("--splits-dir", type=Path, default=ROOT / "artifacts" / "fl-experiment-six" / "splits")
    parser.add_argument(
        "--experiment-dir",
        type=Path,
        default=ROOT / "artifacts" / "fl-experiment-six-cohort-hpo-full",
    )
    parser.add_argument("--seed", type=int, default=20260818)
    parser.add_argument("--output", type=Path, default=ROOT / "artifacts" / "cohort-threshold-tune-six.json")
    args = parser.parse_args()

    grid_default = np.round(np.arange(0.20, 0.81, 0.02), 2)
    grid_network = np.round(np.arange(0.20, 0.51, 0.02), 2)
    site_ids = fl_lab.discover_site_ids(args.splits_dir)
    site_cohort = _load_site_cohort_map(args.splits_dir, site_ids)
    cohorts = tuple(sorted(group_site_ids_by_cohort(site_ids, splits_dir=args.splits_dir)))
    cohort_models = _load_final_models(args.experiment_dir, cohorts)

    mapping = load_column_map()
    frames = fl_lab.load_site_frames(
        splits_dir=args.splits_dir,
        dataset_root=args.dataset_root,
        mapping=mapping,
        max_train=2000,
        max_test=2000,
        max_benign=3000,
        seed=args.seed,
        site_ids=site_ids,
    )

    default_thresholds = {c: 0.5 for c in cohorts}
    tuned_thresholds: dict[str, float] = {}
    tune_details: dict[str, Any] = {}

    for cohort in cohorts:
        valid = _cohort_frames(frames, site_cohort, cohort, "validation", cohort_models[cohort].features)
        grid = grid_network if cohort == "network" else grid_default
        best = _best_threshold(cohort_models[cohort], valid, grid=grid, objective="macro_f1")
        tuned_thresholds[cohort] = float(best["threshold"])
        tune_details[cohort] = best

    baseline_test = _evaluate_cohort_at_thresholds(
        cohort_models=cohort_models,
        site_cohort=site_cohort,
        frames=frames,
        thresholds=default_thresholds,
        split="test",
    )
    tuned_test = _evaluate_cohort_at_thresholds(
        cohort_models=cohort_models,
        site_cohort=site_cohort,
        frames=frames,
        thresholds=tuned_thresholds,
        split="test",
    )

    payload = {
        "generated_at": _utc(),
        "experiment_dir": str(args.experiment_dir),
        "tune_details_validation": tune_details,
        "default_threshold_test": baseline_test,
        "tuned_threshold_test": tuned_test,
        "delta_attack_f1_mean": round(
            tuned_test["macro_f1_mean_attack_f1"] - baseline_test["macro_f1_mean_attack_f1"],
            6,
        ),
        "delta_pooled_fp": tuned_test["pooled_fp"] - baseline_test["pooled_fp"],
        "delta_pooled_fn": tuned_test["pooled_fn"] - baseline_test["pooled_fn"],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    print("==> Per-cohort thresholds (validation)", flush=True)
    for cohort in cohorts:
        detail = tune_details[cohort]
        print(
            f"  {cohort}: {detail['threshold']:.2f} "
            f"(val macro_f1={detail['macro_f1']}, FP={detail['fp']}, FN={detail['fn']})",
            flush=True,
        )
    print(
        f"==> Test @0.5: attack_f1_mean={baseline_test['macro_f1_mean_attack_f1']:.4f} "
        f"FP={baseline_test['pooled_fp']} FN={baseline_test['pooled_fn']}",
        flush=True,
    )
    print(
        f"==> Test tuned: attack_f1_mean={tuned_test['macro_f1_mean_attack_f1']:.4f} "
        f"FP={tuned_test['pooled_fp']} FN={tuned_test['pooled_fn']} "
        f"(dF1={payload['delta_attack_f1_mean']:+.4f}, dFP={payload['delta_pooled_fp']:+d}, dFN={payload['delta_pooled_fn']:+d})",
        flush=True,
    )
    print(f"Wrote {args.output}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
