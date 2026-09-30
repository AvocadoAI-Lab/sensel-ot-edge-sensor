#!/usr/bin/env python3
"""Phase A: offline LR / LightGBM / XGBoost multiclass benchmark on CICIoMT2024."""

from __future__ import annotations

import argparse
import json
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import joblib
import numpy as np
import pandas as pd
import psutil
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score
from sklearn.preprocessing import LabelEncoder, StandardScaler
from xgboost import XGBClassifier

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from app.classifier import DEFAULT_LGBM_BINARY, DEFAULT_XGB_BINARY
from app.data.ciciomt import discover_ciciomt_csv_dirs, list_split_csvs
from app.data.columns import apply_column_mapping, load_column_map
from app.data.inventory import infer_attack_family, infer_label_from_filename
from app.data.preprocess import fit_preprocessor

try:
    from lightgbm import LGBMClassifier
except ImportError as exc:
    raise SystemExit("lightgbm is required for Phase A benchmark") from exc

TEACHER_CLASSES = ("Spoofing", "Benign", "MQTT", "PortScan", "DDoS", "DoS")

FAMILY_TO_TEACHER: dict[str, str] = {
    "spoofing": "Spoofing",
    "benign": "Benign",
    "mqtt": "MQTT",
    "recon": "PortScan",
    "ddos": "DDoS",
    "dos": "DoS",
}


def _utc() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _teacher_label(path: Path) -> str | None:
    raw = infer_label_from_filename(path)
    family = infer_attack_family(raw)
    return FAMILY_TO_TEACHER.get(family)


def _load_limited_csv(path: Path, mapping: dict[str, str], max_rows: int) -> pd.DataFrame:
    frame = pd.read_csv(path, nrows=max_rows if max_rows > 0 else None)
    renamed = apply_column_mapping(list(frame.columns), mapping)
    frame.columns = renamed
    return frame


def build_multiclass_frames(
    *,
    dataset_root: Path,
    max_rows_per_file: int,
    seed: int,
) -> tuple[pd.DataFrame, pd.DataFrame, dict[str, Any]]:
    mapping = load_column_map()
    dirs = discover_ciciomt_csv_dirs(dataset_root)
    train_files = list_split_csvs(dirs["train"])
    test_files = list_split_csvs(dirs["test"])
    train_parts: list[pd.DataFrame] = []
    test_parts: list[pd.DataFrame] = []
    skipped: list[str] = []
    for path in train_files:
        teacher = _teacher_label(path)
        if teacher is None:
            skipped.append(path.name)
            continue
        frame = _load_limited_csv(path, mapping, max_rows_per_file)
        frame["teacher_class"] = teacher
        train_parts.append(frame)
    for path in test_files:
        teacher = _teacher_label(path)
        if teacher is None:
            skipped.append(path.name)
            continue
        frame = _load_limited_csv(path, mapping, max_rows_per_file)
        frame["teacher_class"] = teacher
        test_parts.append(frame)
    if not train_parts or not test_parts:
        raise RuntimeError("No multiclass frames loaded; check dataset_root and class mapping")
    train = pd.concat(train_parts, ignore_index=True).sample(frac=1.0, random_state=seed).reset_index(drop=True)
    test = pd.concat(test_parts, ignore_index=True).sample(frac=1.0, random_state=seed + 1).reset_index(drop=True)
    profile = {
        "train_rows": int(len(train)),
        "test_rows": int(len(test)),
        "classes": sorted(train["teacher_class"].unique().tolist()),
        "skipped_files": sorted(set(skipped)),
        "train_dir": str(dirs["train"]),
        "test_dir": str(dirs["test"]),
    }
    return train, test, profile


def _peak_rss_mb() -> float:
    return round(psutil.Process().memory_info().rss / 1024 / 1024, 3)


def _evaluate(model: Any, x_test: np.ndarray, y_test: np.ndarray) -> dict[str, Any]:
    started = time.perf_counter()
    preds = model.predict(x_test)
    infer_seconds = time.perf_counter() - started
    return {
        "accuracy": round(float(accuracy_score(y_test, preds)), 6),
        "inference_seconds": round(infer_seconds, 6),
        "inference_ms_per_row": round(infer_seconds * 1000.0 / max(len(y_test), 1), 6),
        "rows_per_second": round(len(y_test) / infer_seconds, 3) if infer_seconds else None,
    }


def _model_bytes(model: Any) -> int:
    path = Path(".__bench_model__.joblib")
    joblib.dump(model, path)
    try:
        return path.stat().st_size
    finally:
        path.unlink(missing_ok=True)


def bench_lr(x_train: np.ndarray, y_train: np.ndarray, x_test: np.ndarray, y_test: np.ndarray, seed: int) -> dict[str, Any]:
    peak_before = _peak_rss_mb()
    started = time.perf_counter()
    scaler = StandardScaler()
    x_scaled = scaler.fit_transform(x_train)
    x_test_scaled = scaler.transform(x_test)
    model = LogisticRegression(max_iter=1000, random_state=seed, n_jobs=-1)
    model.fit(x_scaled, y_train)
    train_seconds = time.perf_counter() - started
    metrics = _evaluate(model, x_test_scaled, y_test)
    bundle = {"scaler": scaler, "model": model}
    return {
        "model": "logistic_regression",
        "train_seconds": round(train_seconds, 6),
        "peak_rss_mb": max(peak_before, _peak_rss_mb()),
        "model_bytes": _model_bytes(bundle),
        **metrics,
    }


def bench_lgbm(x_train: np.ndarray, y_train: np.ndarray, x_test: np.ndarray, y_test: np.ndarray, seed: int) -> dict[str, Any]:
    peak_before = _peak_rss_mb()
    params = dict(DEFAULT_LGBM_BINARY)
    params.update({"objective": "multiclass", "num_class": len(np.unique(y_train)), "random_state": seed, "verbose": -1})
    started = time.perf_counter()
    model = LGBMClassifier(**params)
    model.fit(x_train, y_train)
    train_seconds = time.perf_counter() - started
    metrics = _evaluate(model, x_test, y_test)
    return {
        "model": "lightgbm",
        "train_seconds": round(train_seconds, 6),
        "peak_rss_mb": max(peak_before, _peak_rss_mb()),
        "model_bytes": _model_bytes(model),
        **metrics,
    }


def bench_xgb(x_train: np.ndarray, y_train: np.ndarray, x_test: np.ndarray, y_test: np.ndarray, seed: int) -> dict[str, Any]:
    peak_before = _peak_rss_mb()
    params = dict(DEFAULT_XGB_BINARY)
    params.update(
        {
            "objective": "multi:softprob",
            "num_class": int(len(np.unique(y_train))),
            "eval_metric": "mlogloss",
            "random_state": seed,
        }
    )
    started = time.perf_counter()
    model = XGBClassifier(**params)
    model.fit(x_train, y_train)
    train_seconds = time.perf_counter() - started
    metrics = _evaluate(model, x_test, y_test)
    return {
        "model": "xgboost",
        "train_seconds": round(train_seconds, 6),
        "peak_rss_mb": max(peak_before, _peak_rss_mb()),
        "model_bytes": _model_bytes(model),
        **metrics,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Phase A CICIoMT multiclass benchmark")
    parser.add_argument("--dataset-root", type=Path, default=Path(r"D:\實習\資料集"))
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--max-rows-per-file", type=int, default=5000)
    parser.add_argument(
        "--output",
        type=Path,
        default=ROOT / "artifacts" / "xgb-lgbm-benchmark" / "phase-a-comparison.json",
    )
    args = parser.parse_args()

    train, test, profile = build_multiclass_frames(
        dataset_root=args.dataset_root,
        max_rows_per_file=args.max_rows_per_file,
        seed=args.seed,
    )
    preprocess = fit_preprocessor(train, label_column="teacher_class")
    feature_names = preprocess.features
    x_train = preprocess.transform(train)
    x_test = preprocess.transform(test)
    encoder = LabelEncoder()
    y_train = encoder.fit_transform(train["teacher_class"].astype(str))
    y_test = encoder.transform(test["teacher_class"].astype(str))

    results = [
        bench_lr(x_train, y_train, x_test, y_test, args.seed),
        bench_lgbm(x_train, y_train, x_test, y_test, args.seed),
        bench_xgb(x_train, y_train, x_test, y_test, args.seed),
    ]
    lgbm_acc = next(item["accuracy"] for item in results if item["model"] == "lightgbm")
    lr_acc = next(item["accuracy"] for item in results if item["model"] == "logistic_regression")
    xgb_acc = next(item["accuracy"] for item in results if item["model"] == "xgboost")
    report = {
        "phase": "A",
        "recorded_at": _utc(),
        "task": "multiclass_teacher_six_class",
        "teacher_classes": list(TEACHER_CLASSES),
        "dataset_root": str(args.dataset_root),
        "seed": args.seed,
        "max_rows_per_file": args.max_rows_per_file,
        "feature_contract": "ciciomt-xgb-v1",
        "feature_count": len(feature_names),
        "data_profile": profile,
        "acceptance": {
            "lgbm_accuracy_gt_lr": bool(lgbm_acc > lr_acc),
            "xgb_lgbm_gap_abs_le_2pt": bool(abs(xgb_acc - lgbm_acc) <= 0.02),
        },
        "models": results,
        "summary_table": [
            {
                "model": item["model"],
                "accuracy": item["accuracy"],
                "model_kb": round(item["model_bytes"] / 1024, 2),
                "train_s": item["train_seconds"],
                "inference_s": item["inference_seconds"],
                "inference_ms_per_row": item["inference_ms_per_row"],
                "peak_rss_mb": item["peak_rss_mb"],
            }
            for item in results
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"output": str(args.output), "acceptance": report["acceptance"], "summary_table": report["summary_table"]}, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
