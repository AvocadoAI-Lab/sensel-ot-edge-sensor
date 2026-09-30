from __future__ import annotations

from typing import Any

import numpy as np
import pandas as pd
from sklearn.metrics import average_precision_score, roc_auc_score

from .classifier import (
    binary_labels,
    evaluate_classifier,
    train_classifier,
)
from .data.inventory import infer_attack_family
from .detector import train_detector
from .lstm_ae import train_lstm_detector
from .ticks import build_sequences, build_ticks


def leave_one_attack_family_out(
    frame: pd.DataFrame,
    *,
    model_name: str = "xgboost",
    label_column: str = "label",
    benign_value: str = "Benign",
    seed: int = 42,
) -> dict[str, Any]:
    work = frame.copy()
    if "attack_family" not in work.columns:
        work["attack_family"] = work[label_column].astype(str).map(infer_attack_family)

    families = sorted(
        family for family in work["attack_family"].astype(str).unique()
        if family.casefold() != "benign"
    )
    folds = []
    for held_out in families:
        train = work[work["attack_family"].astype(str) != held_out]
        test = work[
            (work["attack_family"].astype(str) == held_out)
            | (work[label_column].astype(str).str.casefold() == benign_value.casefold())
        ]
        if train.empty or test.empty:
            continue
        if binary_labels(train[label_column], benign_value).sum() == 0:
            continue
        bundle = train_classifier(
            train,
            model_name=model_name,
            task="binary",
            label_column=label_column,
            benign_value=benign_value,
            calibrate=False,
            seed=seed,
        )
        metrics = evaluate_classifier(
            bundle,
            test,
            label_column=label_column,
            benign_value=benign_value,
        )
        folds.append({"held_out_family": held_out, "metrics": metrics})

    summary = {
        "strategy": "leave_one_attack_family_out",
        "model_name": model_name,
        "folds": folds,
    }
    roc_values = [fold["metrics"]["roc_auc"] for fold in folds if "roc_auc" in fold["metrics"]]
    if roc_values:
        summary["mean_roc_auc"] = float(np.mean(roc_values))
        summary["std_roc_auc"] = float(np.std(roc_values))
    return summary


def compare_isolation_forest_and_lstm(
    frame: pd.DataFrame,
    *,
    label_column: str = "label",
    benign_value: str = "Benign",
    tick_seconds: int = 60,
    seq_len: int = 5,
    lstm_epochs: int = 8,
) -> dict[str, Any]:
    """Compare IF (tabular rows) vs LSTM AE (tick sequences) on the same labeled frame."""
    if "timestamp" not in frame.columns or "device_id" not in frame.columns:
        return {
            "status": "unavailable",
            "reason": "frame lacks timestamp/device_id required for LSTM sequence comparison",
        }

    if_bundle = train_detector(frame, label_column, benign_value)
    y_true = binary_labels(frame[label_column], benign_value)
    if_scores = []
    for _, row in frame.iterrows():
        features = {name: float(row[name]) for name in if_bundle.features if name in row and pd.notna(row[name])}
        if_scores.append(if_bundle.score(features)[0])
    if_scores_arr = np.asarray(if_scores, dtype=float)

    lstm_bundle = train_lstm_detector(
        frame,
        label_column=label_column,
        benign_value=benign_value,
        tick_seconds=tick_seconds,
        seq_len=seq_len,
        epochs=lstm_epochs,
    )
    ticks = build_ticks(
        frame,
        label_column=label_column,
        benign_value=benign_value,
        tick_seconds=tick_seconds,
        feature_columns=lstm_bundle.features,
    )
    sequences, labels, _ = build_sequences(
        ticks,
        feature_columns=lstm_bundle.features,
        seq_len=lstm_bundle.seq_len,
        label_column=label_column,
        benign_value=benign_value,
        benign_only=False,
    )
    lstm_true = (labels.astype(str) != benign_value).astype(int)
    lstm_scores = np.asarray([
        lstm_bundle.score_sequence(sequence)[0] for sequence in sequences
    ], dtype=float)

    result: dict[str, Any] = {
        "status": "ok",
        "isolation_forest": _score_metrics(y_true, if_scores_arr),
        "lstm_autoencoder": _score_metrics(lstm_true, lstm_scores),
        "lstm_sequences": int(len(sequences)),
        "tabular_rows": int(len(frame)),
    }
    if_pr = result["isolation_forest"].get("pr_auc")
    lstm_pr = result["lstm_autoencoder"].get("pr_auc")
    if if_pr is not None and lstm_pr is not None:
        result["pr_auc_delta_lstm_minus_if"] = float(lstm_pr - if_pr)
    return result


def compare_logreg_and_xgboost(
    train_frame: pd.DataFrame,
    test_frame: pd.DataFrame,
    *,
    label_column: str = "label",
    benign_value: str = "Benign",
    seed: int = 42,
) -> dict[str, Any]:
    report: dict[str, Any] = {"binary": {}, "category": {}}
    for model_name in ("logreg", "xgboost"):
        binary = train_classifier(
            train_frame,
            model_name=model_name,
            task="binary",
            label_column=label_column,
            benign_value=benign_value,
            calibrate=True,
            seed=seed,
        )
        category = train_classifier(
            train_frame,
            model_name=model_name,
            task="category",
            label_column=label_column,
            benign_value=benign_value,
            calibrate=False,
            seed=seed,
        )
        report["binary"][model_name] = evaluate_classifier(
            binary, test_frame, label_column=label_column, benign_value=benign_value
        )
        report["category"][model_name] = evaluate_classifier(
            category, test_frame, label_column=label_column, benign_value=benign_value
        )

    xgb_f1 = report["category"]["xgboost"].get("macro_f1")
    lr_f1 = report["category"]["logreg"].get("macro_f1")
    if xgb_f1 is not None and lr_f1 is not None:
        report["category_macro_f1_delta_xgb_minus_logreg"] = float(xgb_f1 - lr_f1)
    return report


def _score_metrics(y_true: np.ndarray, scores: np.ndarray) -> dict[str, Any]:
    metrics: dict[str, Any] = {"rows": int(len(y_true))}
    if len(np.unique(y_true)) > 1:
        metrics["roc_auc"] = float(roc_auc_score(y_true, scores))
        metrics["pr_auc"] = float(average_precision_score(y_true, scores))
    return metrics
