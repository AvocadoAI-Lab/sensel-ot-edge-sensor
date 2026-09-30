#!/usr/bin/env python3
"""Streaming/chunked CIC official test eval — memory-friendly for Pi 4GB."""

from __future__ import annotations

import argparse
import gc
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
    classification_report,
    f1_score,
    precision_recall_fscore_support,
    roc_auc_score,
)

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from app.classifier import binary_labels, load_classifier  # noqa: E402
from app.data.columns import apply_column_mapping, load_column_map  # noqa: E402
from app.data.inventory import infer_attack_family, infer_label_from_filename  # noqa: E402
from app.detector import load_bundle  # noqa: E402


def hardware_snapshot() -> dict[str, Any]:
    info: dict[str, Any] = {
        "platform": platform.platform(),
        "machine": platform.machine(),
        "processor": platform.processor() or "",
        "python": platform.python_version(),
    }
    if Path("/proc/cpuinfo").exists():
        txt = Path("/proc/cpuinfo").read_text(encoding="utf-8", errors="replace")
        for line in txt.splitlines():
            if line.startswith("Model") or line.startswith("model name"):
                info["processor"] = line.split(":", 1)[-1].strip()
                break
        mem = Path("/proc/meminfo").read_text(encoding="utf-8", errors="replace")
        for line in mem.splitlines():
            if line.startswith("MemTotal:"):
                info["ram_total_gb"] = round(int(line.split()[1]) / (1024**2), 2)
            if line.startswith("MemAvailable:"):
                info["ram_available_gb"] = round(int(line.split()[1]) / (1024**2), 2)
    else:
        try:
            import psutil

            vm = psutil.virtual_memory()
            info["ram_total_gb"] = round(vm.total / (1024**3), 2)
            info["ram_available_gb"] = round(vm.available / (1024**3), 2)
        except Exception as exc:
            info["ram_error"] = str(exc)
    return info


def prepare_chunk(frame: pd.DataFrame, path: Path, label_column: str, mapping: dict) -> pd.DataFrame:
    rename = apply_column_mapping(list(frame.columns), mapping)
    frame = frame.rename(columns=rename)
    frame["source_file"] = path.name
    if label_column not in frame.columns:
        frame[label_column] = infer_label_from_filename(path)
    frame["attack_family"] = frame[label_column].astype(str).map(infer_attack_family)
    return frame


def accumulate_binary(store: dict[str, Any], y_true: np.ndarray, y_score: np.ndarray, y_pred: np.ndarray) -> None:
    store["y_true"].append(y_true.astype(np.int8, copy=False))
    store["y_score"].append(y_score.astype(np.float32, copy=False))
    store["y_pred"].append(y_pred.astype(np.int8, copy=False))


def finalize_binary(store: dict[str, Any], name: str) -> dict[str, Any]:
    y_true = np.concatenate(store["y_true"]) if store["y_true"] else np.array([], dtype=np.int8)
    y_score = np.concatenate(store["y_score"]) if store["y_score"] else np.array([], dtype=np.float32)
    y_pred = np.concatenate(store["y_pred"]) if store["y_pred"] else np.array([], dtype=np.int8)
    metrics: dict[str, Any] = {"detector": name, "rows": int(len(y_true))}
    if len(y_true) == 0:
        return metrics
    metrics["accuracy"] = float(accuracy_score(y_true, y_pred))
    metrics["f1"] = float(f1_score(y_true, y_pred, zero_division=0))
    if len(np.unique(y_true)) > 1 and len(y_score) == len(y_true):
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


def score_chunk(
    frame: pd.DataFrame,
    *,
    label_column: str,
    benign_value: str,
    bin_bundle,
    cat_bundle,
    det,
    bin_store,
    if_store,
    cat_true: list[str],
    cat_pred: list[str],
) -> None:
    y_true = binary_labels(frame[label_column], benign_value=benign_value)

    if bin_bundle is not None:
        proba = bin_bundle.predict_proba(frame)
        y_score = proba[:, 1] if proba.shape[1] == 2 else proba.ravel()
        y_pred = (y_score >= 0.5).astype(np.int8)
        accumulate_binary(bin_store, y_true, np.asarray(y_score), y_pred)

    if cat_bundle is not None:
        preds = cat_bundle.predict(frame)
        if "label_encoder" in cat_bundle.metadata:
            encoder = cat_bundle.metadata["label_encoder"]
            pred_labels = encoder.inverse_transform(preds.astype(int))
        else:
            pred_labels = preds.astype(str)
        true_labels = frame["attack_family"].astype(str)
        pred_arr = np.asarray(pred_labels).astype(str)
        classes = set(str(x) for x in getattr(cat_bundle.metadata.get("label_encoder"), "classes_", []))
        if classes:
            mask = true_labels.isin(classes).to_numpy()
            cat_true.extend(true_labels.to_numpy()[mask].astype(str).tolist())
            cat_pred.extend(pred_arr[mask].tolist())
        else:
            cat_true.extend(true_labels.astype(str).tolist())
            cat_pred.extend(pred_arr.tolist())

    if det is not None:
        matrix = frame.reindex(columns=det.features)
        raw = -det.pipeline.decision_function(matrix.replace([np.inf, -np.inf], np.nan))
        scale = max(abs(det.threshold), 0.05)
        y_score = 1.0 / (1.0 + np.exp(-(raw - det.threshold) / scale))
        y_pred = (raw >= det.threshold).astype(np.int8)
        accumulate_binary(if_store, y_true, np.asarray(y_score), y_pred)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--test-dir", required=True)
    parser.add_argument("--detector", default=str(ROOT / "artifacts" / "detector.joblib"))
    parser.add_argument("--xgb-binary", default=str(ROOT / "artifacts" / "classifiers" / "xgboost_binary.joblib"))
    parser.add_argument("--xgb-category", default=str(ROOT / "artifacts" / "classifiers" / "xgboost_category.joblib"))
    parser.add_argument("--output", default=str(ROOT / "artifacts" / "eval" / "official_test_full.json"))
    parser.add_argument("--label-column", default="label")
    parser.add_argument("--benign-value", default="Benign")
    parser.add_argument("--skip-if", action="store_true")
    parser.add_argument("--chunk-size", type=int, default=10000)
    args = parser.parse_args()

    t0 = time.perf_counter()
    hw = hardware_snapshot()
    print("hardware", json.dumps(hw, ensure_ascii=False), flush=True)

    files = sorted(Path(args.test_dir).glob("*.csv"))
    print(f"test files: {len(files)} chunk_size={args.chunk_size}", flush=True)

    mapping = load_column_map()
    bin_bundle = load_classifier(Path(args.xgb_binary)) if Path(args.xgb_binary).exists() else None
    cat_bundle = load_classifier(Path(args.xgb_category)) if Path(args.xgb_category).exists() else None
    det = None if args.skip_if or not Path(args.detector).exists() else load_bundle(Path(args.detector))

    bin_store: dict[str, Any] = {"y_true": [], "y_score": [], "y_pred": []}
    if_store: dict[str, Any] = {"y_true": [], "y_score": [], "y_pred": []}
    cat_true: list[str] = []
    cat_pred: list[str] = []
    per_file: list[dict[str, Any]] = []
    total_rows = 0

    for path in files:
        label = infer_label_from_filename(path)
        file_rows = 0
        print(f"scoring {path.name} ...", flush=True)
        for chunk in pd.read_csv(path, chunksize=max(1000, args.chunk_size)):
            frame = prepare_chunk(chunk, path, args.label_column, mapping)
            n = int(len(frame))
            file_rows += n
            total_rows += n
            score_chunk(
                frame,
                label_column=args.label_column,
                benign_value=args.benign_value,
                bin_bundle=bin_bundle,
                cat_bundle=cat_bundle,
                det=det,
                bin_store=bin_store,
                if_store=if_store,
                cat_true=cat_true,
                cat_pred=cat_pred,
            )
            del frame, chunk
            gc.collect()
            print(f"  chunk ok cumulative_rows={file_rows}", flush=True)

        per_file.append(
            {
                "file": path.name,
                "rows": file_rows,
                "bytes": int(path.stat().st_size),
                "label": label,
                "attack_family": infer_attack_family(label),
            }
        )
        print(f"done {path.name} ({file_rows})", flush=True)
        gc.collect()

    metrics: dict[str, Any] = {}
    if bin_bundle is not None:
        metrics["xgboost_binary"] = finalize_binary(bin_store, "xgboost_binary")
    if det is not None:
        m = finalize_binary(if_store, "isolation_forest")
        y_true = np.concatenate(if_store["y_true"]) if if_store["y_true"] else np.array([], dtype=np.int8)
        y_pred = np.concatenate(if_store["y_pred"]) if if_store["y_pred"] else np.array([], dtype=np.int8)
        if len(y_true):
            m["anomalous_rate_overall"] = float(y_pred.mean())
            m["anomalous_rate_on_benign"] = float(y_pred[y_true == 0].mean()) if (y_true == 0).any() else None
            m["anomalous_rate_on_attack"] = float(y_pred[y_true == 1].mean()) if (y_true == 1).any() else None
        metrics["isolation_forest"] = m
    if cat_bundle is not None and cat_true:
        labels = sorted(set(cat_true) | set(cat_pred))
        report = classification_report(cat_true, cat_pred, labels=labels, output_dict=True, zero_division=0)
        metrics["xgboost_category"] = {
            "task": "category",
            "rows": len(cat_true),
            "accuracy": float(report.get("accuracy", 0.0)),
            "macro_f1": float(report.get("macro avg", {}).get("f1-score", 0.0)),
            "per_class": {
                k: {
                    "precision": float(v["precision"]),
                    "recall": float(v["recall"]),
                    "f1": float(v["f1-score"]),
                    "support": int(v["support"]),
                }
                for k, v in report.items()
                if isinstance(v, dict) and "precision" in v and k not in {"macro avg", "weighted avg"}
            },
        }

    benign_rows = sum(p["rows"] for p in per_file if str(p["attack_family"]).lower() == "benign")
    attack_rows = total_rows - benign_rows

    result = {
        "created_at": datetime.now(timezone.utc).isoformat(),
        "mode": "official_test_FULL_ROWS_chunked",
        "dataset_root": str(Path(args.test_dir).resolve()),
        "hardware": hw,
        "chunk_size": args.chunk_size,
        "skip_if": bool(args.skip_if),
        "split": {
            "strategy": "test_dir_all_csv_chunked",
            "test_files": len(files),
            "test_rows": total_rows,
            "benign_rows": benign_rows,
            "attack_rows": attack_rows,
            "per_file": per_file,
        },
        "pipeline_order": [
            "CICIoMT CSV features (chunked file-by-file)",
            "column mapping + label from filename",
            "Isolation Forest (anomaly)" + (" [SKIPPED]" if args.skip_if else ""),
            "XGBoost binary / category (known attack)",
            "(LSTM skipped: official CIC CSV lacks reliable device/session timestamps)",
            "metrics vs ground-truth labels",
        ],
        "algorithms": {
            "isolation_forest": "sklearn IsolationForest (deployed detector.joblib; demo 8-feature artifact may not align with CIC columns)",
            "xgboost_binary": "XGBoost Attack/Benign (deployed)",
            "xgboost_category": "XGBoost attack-family (deployed)",
            "lstm_autoencoder": "not evaluated on full CIC CSV",
        },
        "metrics": metrics,
        "total_latency_sec": round(time.perf_counter() - t0, 3),
    }
    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps({k: result["metrics"].get(k) for k in result["metrics"]}, ensure_ascii=False)[:2000], flush=True)
    print(f"wrote {out}", flush=True)
    print("FULL_EVAL_DONE", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
