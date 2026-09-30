#!/usr/bin/env python3
"""Evaluate deployed IF + XGBoost on ALL official CICIoMT test rows (no per-file sampling)."""

from __future__ import annotations

import argparse
import json
import platform
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd
from sklearn.metrics import (
    accuracy_score,
    average_precision_score,
    f1_score,
    precision_recall_fscore_support,
    roc_auc_score,
)

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from app.classifier import binary_labels, evaluate_classifier, load_classifier  # noqa: E402
from app.data.ciciomt import (  # noqa: E402
    discover_ciciomt_csv_dirs,
    resolve_manifest_files,
)
from app.data.columns import apply_column_mapping, load_column_map
from app.data.inventory import infer_attack_family, infer_label_from_filename
from app.detector import load_bundle  # noqa: E402


def hardware_snapshot() -> dict[str, Any]:
    info: dict[str, Any] = {
        "platform": platform.platform(),
        "machine": platform.machine(),
        "processor": platform.processor(),
        "python": platform.python_version(),
    }
    try:
        import psutil

        vm = psutil.virtual_memory()
        info["ram_total_gb"] = round(vm.total / (1024**3), 2)
        info["ram_available_gb"] = round(vm.available / (1024**3), 2)
    except Exception as exc:  # pragma: no cover
        info["ram_error"] = str(exc)
    return info


def load_full_test_frame(files: list[Path], label_column: str = "label") -> pd.DataFrame:
    mapping = load_column_map()
    frames: list[pd.DataFrame] = []
    per_file: list[dict[str, Any]] = []
    for path in files:
        frame = pd.read_csv(path)
        rename = apply_column_mapping(list(frame.columns), mapping)
        frame = frame.rename(columns=rename)
        frame["source_file"] = path.name
        if label_column not in frame.columns:
            frame[label_column] = infer_label_from_filename(path)
        frame["attack_family"] = frame[label_column].astype(str).map(infer_attack_family)
        per_file.append(
            {
                "file": path.name,
                "rows": int(len(frame)),
                "bytes": int(path.stat().st_size),
                "label": infer_label_from_filename(path),
                "attack_family": infer_attack_family(infer_label_from_filename(path)),
            }
        )
        frames.append(frame)
        print(f"  loaded {path.name}: {len(frame)} rows", flush=True)
    if not frames:
        raise SystemExit("No test files loaded")
    out = pd.concat(frames, ignore_index=True)
    return out, per_file


def evaluate_isolation_forest(bundle, frame: pd.DataFrame, label_column: str, benign_value: str) -> dict[str, Any]:
    y_true = binary_labels(frame[label_column], benign_value=benign_value)
    scores = []
    preds = []
    # Score in chunks to keep memory calm on Pi.
    chunk = 50000
    for start in range(0, len(frame), chunk):
        part = frame.iloc[start : start + chunk]
        for _, row in part.iterrows():
            feats = {
                name: float(row[name])
                for name in bundle.features
                if name in row and pd.notna(row[name])
            }
            # fill missing as nan path inside score via .get
            feats = {name: float(row[name]) if name in row and pd.notna(row[name]) else float("nan") for name in bundle.features}
            score, anomalous, _ = bundle.score(feats)
            scores.append(score)
            preds.append(1 if anomalous else 0)
        print(f"  IF scored {min(start + chunk, len(frame))}/{len(frame)}", flush=True)
    y_score = np.asarray(scores, dtype=float)
    y_pred = np.asarray(preds, dtype=int)
    metrics: dict[str, Any] = {
        "detector": "isolation_forest",
        "rows": int(len(frame)),
        "accuracy": float(accuracy_score(y_true, y_pred)),
        "f1": float(f1_score(y_true, y_pred, zero_division=0)),
        "anomalous_rate_overall": float(y_pred.mean()),
        "anomalous_rate_on_benign": float(y_pred[y_true == 0].mean()) if (y_true == 0).any() else None,
        "anomalous_rate_on_attack": float(y_pred[y_true == 1].mean()) if (y_true == 1).any() else None,
        "mean_score": float(y_score.mean()),
    }
    if len(np.unique(y_true)) > 1:
        metrics["roc_auc"] = float(roc_auc_score(y_true, y_score))
        metrics["pr_auc"] = float(average_precision_score(y_true, y_score))
    precision, recall, f1, support = precision_recall_fscore_support(
        y_true, y_pred, labels=[0, 1], zero_division=0
    )
    metrics["per_class"] = {
        "Benign": {
            "precision": float(precision[0]),
            "recall": float(recall[0]),
            "f1": float(f1[0]),
            "support": int(support[0]),
        },
        "Attack": {
            "precision": float(precision[1]),
            "recall": float(recall[1]),
            "f1": float(f1[1]),
            "support": int(support[1]),
        },
    }
    return metrics


def evaluate_isolation_forest_fast(bundle, frame: pd.DataFrame, label_column: str, benign_value: str) -> dict[str, Any]:
    """Vectorized-ish IF scoring via pipeline decision_function on feature matrix."""
    y_true = binary_labels(frame[label_column], benign_value=benign_value)
    matrix = pd.DataFrame(
        [{name: row.get(name, np.nan) for name in bundle.features} for _, row in frame[bundle.features].iterrows()]
    ) if False else frame.reindex(columns=bundle.features)
    # Use same normalization as DetectorBundle.score
    raw = -bundle.pipeline.decision_function(matrix.replace([np.inf, -np.inf], np.nan))
    scale = max(abs(bundle.threshold), 0.05)
    y_score = 1.0 / (1.0 + np.exp(-(raw - bundle.threshold) / scale))
    y_pred = (raw >= bundle.threshold).astype(int)
    metrics: dict[str, Any] = {
        "detector": "isolation_forest",
        "rows": int(len(frame)),
        "accuracy": float(accuracy_score(y_true, y_pred)),
        "f1": float(f1_score(y_true, y_pred, zero_division=0)),
        "anomalous_rate_overall": float(y_pred.mean()),
        "anomalous_rate_on_benign": float(y_pred[y_true == 0].mean()) if (y_true == 0).any() else None,
        "anomalous_rate_on_attack": float(y_pred[y_true == 1].mean()) if (y_true == 1).any() else None,
        "mean_score": float(np.mean(y_score)),
    }
    if len(np.unique(y_true)) > 1:
        metrics["roc_auc"] = float(roc_auc_score(y_true, y_score))
        metrics["pr_auc"] = float(average_precision_score(y_true, y_score))
    precision, recall, f1, support = precision_recall_fscore_support(
        y_true, y_pred, labels=[0, 1], zero_division=0
    )
    metrics["per_class"] = {
        "Benign": {
            "precision": float(precision[0]),
            "recall": float(recall[0]),
            "f1": float(f1[0]),
            "support": int(support[0]),
        },
        "Attack": {
            "precision": float(precision[1]),
            "recall": float(recall[1]),
            "f1": float(f1[1]),
            "support": int(support[1]),
        },
    }
    return metrics


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--dataset-root", default=r"D:\實習\資料集")
    parser.add_argument("--manifest", default=str(ROOT / "artifacts" / "ciciomt" / "official_file_manifest.json"))
    parser.add_argument("--detector", default=str(ROOT / "artifacts" / "detector.joblib"))
    parser.add_argument("--xgb-binary", default=str(ROOT / "artifacts" / "classifiers" / "xgboost_binary.joblib"))
    parser.add_argument("--xgb-category", default=str(ROOT / "artifacts" / "classifiers" / "xgboost_category.joblib"))
    parser.add_argument("--output", default=str(ROOT / "artifacts" / "eval" / "official_test_full.json"))
    parser.add_argument("--label-column", default="label")
    parser.add_argument("--benign-value", default="Benign")
    parser.add_argument("--test-dir", default=None, help="If set, load ALL csv from this dir as test (no train required)")
    parser.add_argument("--skip-if", action="store_true", help="Skip Isolation Forest evaluation")
    args = parser.parse_args()

    t0 = time.perf_counter()
    hw = hardware_snapshot()
    print("hardware", json.dumps(hw, ensure_ascii=False), flush=True)

    if args.test_dir:
        test_dir = Path(args.test_dir)
        test_files = sorted(test_dir.glob("*.csv"))
        manifest_meta = {"strategy": "test_dir_all_csv", "test_dir": str(test_dir.resolve())}
    else:
        manifest = json.loads(Path(args.manifest).read_text(encoding="utf-8"))
        dirs = discover_ciciomt_csv_dirs(Path(args.dataset_root))
        resolved = resolve_manifest_files(manifest, dirs)
        test_files = resolved["test"]
        manifest_meta = {"strategy": manifest.get("strategy")}
    print(f"official test files: {len(test_files)}", flush=True)

    frame, per_file = load_full_test_frame(test_files, label_column=args.label_column)
    print(f"TOTAL test rows: {len(frame)}", flush=True)

    result: dict[str, Any] = {
        "created_at": datetime.now(timezone.utc).isoformat(),
        "mode": "official_test_FULL_ROWS",
        "dataset_root": str(Path(args.dataset_root).resolve()) if not args.test_dir else str(Path(args.test_dir).resolve()),
        "hardware": hw,
        "split": {
            **manifest_meta,
            "test_files": len(test_files),
            "test_rows": int(len(frame)),
            "benign_rows": int((frame[args.label_column].astype(str).str.casefold() == args.benign_value.casefold()).sum()),
            "attack_rows": int((frame[args.label_column].astype(str).str.casefold() != args.benign_value.casefold()).sum()),
            "per_file": per_file,
        },
        "pipeline_order": [
            "CICIoMT CSV features",
            "column mapping + label from filename",
            "Isolation Forest (anomaly)",
            "XGBoost binary / category (known attack)",
            "(LSTM skipped: official CIC CSV lacks reliable device/session timestamps)",
            "metrics vs ground-truth labels",
        ],
        "algorithms": {
            "isolation_forest": "sklearn IsolationForest anomaly score (deployed detector.joblib)",
            "xgboost_binary": "XGBoost Attack/Benign (deployed xgboost_binary.joblib)",
            "xgboost_category": "XGBoost attack-family (deployed xgboost_category.joblib)",
            "lstm_autoencoder": "not evaluated on full CIC CSV (no trusted temporal keys)",
        },
        "metrics": {},
    }

    if Path(args.xgb_binary).exists():
        print("evaluating xgboost_binary...", flush=True)
        t1 = time.perf_counter()
        bin_bundle = load_classifier(Path(args.xgb_binary))
        result["metrics"]["xgboost_binary"] = evaluate_classifier(
            bin_bundle, frame, label_column=args.label_column, benign_value=args.benign_value
        )
        result["metrics"]["xgboost_binary"]["latency_sec"] = round(time.perf_counter() - t1, 3)
        print(json.dumps(result["metrics"]["xgboost_binary"], ensure_ascii=False), flush=True)
    else:
        result["metrics"]["xgboost_binary"] = {"error": f"missing {args.xgb_binary}"}

    if Path(args.xgb_category).exists():
        print("evaluating xgboost_category...", flush=True)
        t1 = time.perf_counter()
        cat_bundle = load_classifier(Path(args.xgb_category))
        result["metrics"]["xgboost_category"] = evaluate_classifier(
            cat_bundle, frame, label_column=args.label_column, benign_value=args.benign_value
        )
        result["metrics"]["xgboost_category"]["latency_sec"] = round(time.perf_counter() - t1, 3)
        print(json.dumps(result["metrics"]["xgboost_category"], ensure_ascii=False), flush=True)
    else:
        result["metrics"]["xgboost_category"] = {"error": f"missing {args.xgb_category}"}

    if not args.skip_if and Path(args.detector).exists():
        print("evaluating isolation_forest (full rows)...", flush=True)
        t1 = time.perf_counter()
        det = load_bundle(Path(args.detector))
        result["metrics"]["isolation_forest"] = evaluate_isolation_forest_fast(
            det, frame, args.label_column, args.benign_value
        )
        result["metrics"]["isolation_forest"]["latency_sec"] = round(time.perf_counter() - t1, 3)
        print(json.dumps(result["metrics"]["isolation_forest"], ensure_ascii=False), flush=True)
    elif args.skip_if:
        result["metrics"]["isolation_forest"] = {"skipped": True}
    else:
        result["metrics"]["isolation_forest"] = {"error": f"missing {args.detector}"}

    result["total_latency_sec"] = round(time.perf_counter() - t0, 3)
    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"wrote {out}", flush=True)
    print("FULL_EVAL_DONE", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
