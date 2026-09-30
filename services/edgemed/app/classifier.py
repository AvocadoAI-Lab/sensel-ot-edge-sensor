from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal

import joblib
import numpy as np
import pandas as pd
from sklearn.calibration import CalibratedClassifierCV
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    average_precision_score,
    balanced_accuracy_score,
    confusion_matrix,
    f1_score,
    precision_recall_curve,
    precision_recall_fscore_support,
    roc_curve,
    roc_auc_score,
)
from sklearn.preprocessing import LabelEncoder
from xgboost import XGBClassifier

try:
    from lightgbm import LGBMClassifier
except ImportError:  # pragma: no cover - optional until requirements install
    LGBMClassifier = None  # type: ignore[misc, assignment]

from .data.inventory import infer_attack_family
from .data.preprocess import PreprocessBundle, fit_preprocessor, select_feature_columns


ARTIFACT_VERSION = "0.1.0-xgb"
TaskName = Literal["binary", "category"]


def _sample_curve(values: np.ndarray, *, maximum_points: int = 201) -> list[float]:
    if len(values) <= maximum_points:
        return [float(value) for value in values]
    indices = np.linspace(0, len(values) - 1, maximum_points, dtype=int)
    return [float(values[index]) for index in indices]


def binary_labels(labels: pd.Series, benign_value: str = "Benign") -> np.ndarray:
    return (
        labels.astype(str).str.casefold() != benign_value.casefold()
    ).astype(int).to_numpy()


def category_labels(frame: pd.DataFrame, label_column: str = "label") -> pd.Series:
    if "attack_family" in frame.columns:
        return frame["attack_family"].astype(str)
    return frame[label_column].astype(str).map(infer_attack_family)


@dataclass
class ClassifierBundle:
    model_name: str
    task: TaskName
    pipeline: Any
    features: list[str]
    classes: list[str]
    preprocess: PreprocessBundle | None
    metadata: dict[str, Any]

    def predict_proba(self, frame: pd.DataFrame) -> np.ndarray:
        matrix = self._matrix(frame)
        return self.pipeline.predict_proba(matrix)

    def predict(self, frame: pd.DataFrame) -> np.ndarray:
        matrix = self._matrix(frame)
        return self.pipeline.predict(matrix)

    def score_rows(self, frame: pd.DataFrame, limit: int | None = None) -> list[dict[str, Any]]:
        work = frame if limit is None else frame.head(limit)
        proba = self.predict_proba(work)
        preds = self.predict(work)
        if self.task == "category" and "label_encoder" in self.metadata:
            encoder = self.metadata["label_encoder"]
            pred_labels = encoder.inverse_transform(preds.astype(int))
            class_names = [str(item) for item in encoder.classes_]
        else:
            pred_labels = np.asarray(["Attack" if int(value) == 1 else "Benign" for value in preds])
            class_names = self.classes
        events = []
        for index, (_, row) in enumerate(work.iterrows()):
            probabilities = {
                class_names[i]: float(proba[index, i]) for i in range(min(len(class_names), proba.shape[1]))
            }
            events.append(classifier_security_event(
                self,
                features={name: float(row[name]) for name in self.features if name in row and pd.notna(row[name])},
                probabilities=probabilities,
                predicted=str(pred_labels[index]),
                device_id=str(row.get("device_id", row.get("source_file", f"row-{index}"))),
                device_type=str(row.get("device_type", "medical_aiot")),
                operating_state=str(row.get("operating_state", "unknown")),
            ))
        return events

    def _matrix(self, frame: pd.DataFrame) -> np.ndarray:
        if self.preprocess is not None:
            return self.preprocess.transform(frame)
        return frame[self.features].replace([np.inf, -np.inf], np.nan).to_numpy(dtype=float)


def _top_feature_evidence(bundle: ClassifierBundle, top_k: int = 5) -> list[dict[str, Any]]:
    model = bundle.pipeline
    if hasattr(model, "calibrated_classifiers_"):
        # CalibratedClassifierCV wraps estimators differently across sklearn versions.
        try:
            model = model.calibrated_classifiers_[0].estimator
        except Exception:
            model = getattr(model, "estimator", model)

    if hasattr(model, "feature_importances_"):
        values = np.asarray(model.feature_importances_, dtype=float)
        order = np.argsort(values)[::-1][:top_k]
        return [
            {"feature": bundle.features[i], "importance": float(values[i])}
            for i in order
        ]
    if hasattr(model, "coef_"):
        coef = np.asarray(model.coef_, dtype=float)
        magnitudes = np.mean(np.abs(coef), axis=0) if coef.ndim == 2 else np.abs(coef)
        order = np.argsort(magnitudes)[::-1][:top_k]
        return [
            {"feature": bundle.features[i], "abs_coef": float(magnitudes[i])}
            for i in order
        ]
    return []


def classifier_security_event(
    bundle: ClassifierBundle,
    *,
    features: dict[str, float],
    probabilities: dict[str, float],
    predicted: str,
    device_id: str,
    device_type: str,
    operating_state: str,
) -> dict[str, Any]:
    top_class = max(probabilities, key=probabilities.get)
    attack_probability = float(sum(
        score for name, score in probabilities.items() if name.casefold() not in {"benign", "0"}
    )) if bundle.task == "category" else float(probabilities.get("1", probabilities.get("Attack", 0.0)))
    severity = "high" if attack_probability >= 0.85 else "medium" if attack_probability >= 0.65 else "low"
    event_key = json.dumps([bundle.model_name, device_id, predicted, probabilities], sort_keys=True).encode()
    return {
        "schema_version": "0.1",
        "event_id": "evt_" + hashlib.sha256(event_key).hexdigest()[:16],
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "asset": {
            "device_id": device_id,
            "device_type": device_type,
            "operating_state": operating_state,
        },
        "detection": {
            "detector": bundle.model_name,
            "task": bundle.task,
            "verdict": "anomalous" if predicted.casefold() not in {"benign", "0"} else "baseline",
            "predicted_class": predicted,
            "top_class": top_class,
            "probabilities": {key: round(value, 6) for key, value in probabilities.items()},
            "model_version": bundle.metadata.get("artifact_version", ARTIFACT_VERSION),
            "top_features": _top_feature_evidence(bundle),
        },
        "evidence": [
            {"feature": name, "observed": value}
            for name, value in sorted(features.items())[:5]
        ],
        "assessment": {
            "severity": severity,
            "summary": (
                f"{bundle.model_name} {bundle.task} prediction={predicted} "
                f"with top class {top_class}."
            ),
        },
        "response": {
            "mode": "advisory_only",
            "recommended_actions": [
                "Verify the device operating state",
                "Review top contributing features",
                "Preserve relevant flow metadata",
            ] if predicted.casefold() not in {"benign", "0"} else [],
        },
    }


DEFAULT_XGB_BINARY: dict[str, Any] = {
    "n_estimators": 120,
    "max_depth": 6,
    "learning_rate": 0.08,
    "subsample": 0.9,
    "colsample_bytree": 0.9,
    "min_child_weight": 1,
    "gamma": 0.0,
    "reg_alpha": 0.0,
    "reg_lambda": 1.0,
    "objective": "binary:logistic",
    "eval_metric": "logloss",
    "tree_method": "hist",
    "n_jobs": -1,
}


DEFAULT_LGBM_BINARY: dict[str, Any] = {
    "n_estimators": 120,
    "max_depth": 6,
    "learning_rate": 0.08,
    "subsample": 0.9,
    "colsample_bytree": 0.9,
    "num_leaves": 63,
    "objective": "binary",
    "n_jobs": -1,
}


def _make_estimator(
    model_name: str,
    task: TaskName,
    n_classes: int,
    seed: int,
    xgb_params: dict[str, Any] | None = None,
    lgbm_params: dict[str, Any] | None = None,
):
    if model_name == "logreg":
        return LogisticRegression(
            max_iter=5000,
            class_weight="balanced",
            solver="lbfgs",
            random_state=seed,
        )
    if model_name == "xgboost":
        params = dict(DEFAULT_XGB_BINARY)
        if xgb_params:
            params.update({key: value for key, value in xgb_params.items() if value is not None})
        params["random_state"] = seed
        if task != "binary":
            params["objective"] = "multi:softprob"
            params["num_class"] = n_classes
            params["eval_metric"] = "mlogloss"
        return XGBClassifier(**params)
    if model_name == "lightgbm":
        if LGBMClassifier is None:
            raise ImportError("lightgbm is required for model_name='lightgbm'")
        params = dict(DEFAULT_LGBM_BINARY)
        if lgbm_params:
            params.update({key: value for key, value in lgbm_params.items() if value is not None})
        params["random_state"] = seed
        params["verbose"] = -1
        if task != "binary":
            params["objective"] = "multiclass"
            params["num_class"] = n_classes
        return LGBMClassifier(**params)
    raise ValueError(f"Unsupported model_name: {model_name}")


def train_classifier(
    train_frame: pd.DataFrame,
    *,
    model_name: str = "xgboost",
    task: TaskName = "binary",
    label_column: str = "label",
    benign_value: str = "Benign",
    preprocess: PreprocessBundle | None = None,
    calibrate: bool = False,
    seed: int = 42,
    xgb_params: dict[str, Any] | None = None,
    lgbm_params: dict[str, Any] | None = None,
    eval_frame: pd.DataFrame | None = None,
    early_stopping_rounds: int | None = None,
) -> ClassifierBundle:
    features = (
        preprocess.features
        if preprocess is not None
        else select_feature_columns(train_frame, label_column=label_column)
    )
    if not features:
        raise ValueError("No usable features for classifier training")

    local_preprocess = preprocess
    if local_preprocess is None:
        local_preprocess = fit_preprocessor(
            train_frame,
            features=features,
            label_column=label_column,
        )

    x = local_preprocess.transform(train_frame)
    if task == "binary":
        y = binary_labels(train_frame[label_column], benign_value=benign_value)
        classes = ["Benign", "Attack"]
        y_model = y
        label_encoder = None
    else:
        raw = category_labels(train_frame, label_column=label_column)
        label_encoder = LabelEncoder()
        y_model = label_encoder.fit_transform(raw)
        classes = [str(item) for item in label_encoder.classes_]
        y = y_model

    if len(np.unique(y_model)) < 2:
        raise ValueError(
            f"Classifier training requires at least 2 classes for task={task}; "
            f"got {np.unique(y_model).tolist()}"
        )

    estimator = _make_estimator(
        model_name,
        task,
        n_classes=len(np.unique(y_model)),
        seed=seed,
        xgb_params=xgb_params,
        lgbm_params=lgbm_params,
    )
    if calibrate and len(np.unique(y_model)) >= 2 and len(train_frame) >= 50:
        model: Any = CalibratedClassifierCV(estimator, method="sigmoid", cv=3)
        model.fit(x, y_model)
    else:
        model = estimator
        fit_kwargs: dict[str, Any] = {}
        if (
            early_stopping_rounds
            and eval_frame is not None
            and not eval_frame.empty
            and hasattr(model, "set_params")
        ):
            x_eval = local_preprocess.transform(eval_frame)
            if task == "binary":
                y_eval = binary_labels(eval_frame[label_column], benign_value=benign_value)
            else:
                y_eval = label_encoder.transform(category_labels(eval_frame, label_column=label_column))
            model.set_params(early_stopping_rounds=int(early_stopping_rounds))
            fit_kwargs["eval_set"] = [(x_eval, y_eval)]
            fit_kwargs["verbose"] = False
        model.fit(x, y_model, **fit_kwargs)

    metadata = {
        "artifact_version": ARTIFACT_VERSION,
        "trained_at": datetime.now(timezone.utc).isoformat(),
        "model_name": model_name,
        "task": task,
        "classes": classes,
        "training_rows": int(len(train_frame)),
        "features": features,
        "calibrated": bool(calibrate),
        "label_column": label_column,
        "benign_value": benign_value,
        "label_encoder_classes": classes if task == "category" else None,
        "xgb_params": xgb_params,
        "early_stopping_rounds": early_stopping_rounds,
        "best_iteration": getattr(model, "best_iteration", None),
    }
    bundle = ClassifierBundle(
        model_name=model_name,
        task=task,
        pipeline=model,
        features=features,
        classes=classes,
        preprocess=local_preprocess,
        metadata=metadata,
    )
    # Store encoder on metadata for category inverse transform during eval helpers.
    if label_encoder is not None:
        bundle.metadata["label_encoder"] = label_encoder
    return bundle


def evaluate_classifier(
    bundle: ClassifierBundle,
    frame: pd.DataFrame,
    *,
    label_column: str = "label",
    benign_value: str = "Benign",
    include_curves: bool = False,
    decision_threshold: float = 0.5,
) -> dict[str, Any]:
    if bundle.task == "binary":
        y_true = binary_labels(frame[label_column], benign_value=benign_value)
        proba = bundle.predict_proba(frame)
        # Ensure attack probability is column 1 when classes are [Benign, Attack]/ordered by estimator.
        threshold = float(decision_threshold)
        if proba.shape[1] == 2:
            y_score = proba[:, 1]
            y_pred = (y_score >= threshold).astype(int)
        else:
            y_score = proba.ravel()
            y_pred = (y_score >= threshold).astype(int)
        metrics: dict[str, Any] = {
            "task": "binary",
            "rows": int(len(frame)),
            "accuracy": float(accuracy_score(y_true, y_pred)),
            "balanced_accuracy": (
                float(balanced_accuracy_score(y_true, y_pred))
                if len(np.unique(y_true)) > 1
                else None
            ),
            "f1": float(f1_score(y_true, y_pred, zero_division=0)),
            "macro_f1": float(f1_score(y_true, y_pred, average="macro", zero_division=0)),
            "weighted_f1": float(f1_score(y_true, y_pred, average="weighted", zero_division=0)),
        }
        if len(np.unique(y_true)) > 1:
            metrics["roc_auc"] = float(roc_auc_score(y_true, y_score))
            metrics["pr_auc"] = float(average_precision_score(y_true, y_score))
            if include_curves:
                fpr_curve, tpr_curve, roc_thresholds = roc_curve(y_true, y_score)
                pr_precision, pr_recall, pr_thresholds = precision_recall_curve(y_true, y_score)
                metrics["roc_curve"] = {
                    "fpr": _sample_curve(fpr_curve),
                    "tpr": _sample_curve(tpr_curve),
                    "thresholds": _sample_curve(roc_thresholds),
                }
                metrics["pr_curve"] = {
                    "precision": _sample_curve(pr_precision),
                    "recall": _sample_curve(pr_recall),
                    "thresholds": _sample_curve(pr_thresholds),
                }
        precision, recall, f1, support = precision_recall_fscore_support(
            y_true, y_pred, labels=[0, 1], zero_division=0
        )
        matrix = confusion_matrix(y_true, y_pred, labels=[0, 1])
        tn, fp, fn, tp = (
            int(matrix[0, 0]),
            int(matrix[0, 1]),
            int(matrix[1, 0]),
            int(matrix[1, 1]),
        )
        metrics["macro_precision"] = float(np.mean(precision))
        metrics["macro_recall"] = float(np.mean(recall))
        metrics["confusion_matrix"] = {"tn": tn, "fp": fp, "fn": fn, "tp": tp}
        row_sums = matrix.sum(axis=1)
        metrics["confusion_matrix_normalized"] = {
            "tn": float(tn / row_sums[0]) if row_sums[0] else None,
            "fp": float(fp / row_sums[0]) if row_sums[0] else None,
            "fn": float(fn / row_sums[1]) if row_sums[1] else None,
            "tp": float(tp / row_sums[1]) if row_sums[1] else None,
        }
        metrics["fpr"] = float(fp / (tn + fp)) if tn + fp else None
        metrics["fnr"] = float(fn / (tp + fn)) if tp + fn else None
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

    y_true_raw = category_labels(frame, label_column=label_column)
    encoder: LabelEncoder = bundle.metadata["label_encoder"]
    # Map unseen labels to a dedicated bucket for scoring safety.
    known = set(encoder.classes_)
    filtered = frame.loc[y_true_raw.isin(known)].copy()
    if filtered.empty:
        return {"task": "category", "rows": 0, "error": "no overlapping category labels"}
    y_true = encoder.transform(category_labels(filtered, label_column=label_column))
    y_pred = bundle.pipeline.predict(bundle._matrix(filtered))
    macro_f1 = float(f1_score(y_true, y_pred, average="macro", zero_division=0))
    precision, recall, f1, support = precision_recall_fscore_support(
        y_true, y_pred, labels=list(range(len(encoder.classes_))), zero_division=0
    )
    per_class = {}
    for index, name in enumerate(encoder.classes_):
        per_class[str(name)] = {
            "precision": float(precision[index]),
            "recall": float(recall[index]),
            "f1": float(f1[index]),
            "support": int(support[index]),
        }
    return {
        "task": "category",
        "rows": int(len(filtered)),
        "macro_f1": macro_f1,
        "accuracy": float(accuracy_score(y_true, y_pred)),
        "per_class": per_class,
    }


def score_known_attack(
    bundle: ClassifierBundle,
    features: dict[str, float],
    *,
    decision_threshold: float = 0.5,
) -> dict[str, Any] | None:
    """Score one feature row into a fusion-ready known_attack payload."""
    missing = [name for name in bundle.features if name not in features]
    if missing:
        return None
    frame = pd.DataFrame([{name: features.get(name) for name in bundle.features}])
    proba = bundle.predict_proba(frame)[0]
    if bundle.task == "category" and "label_encoder" in bundle.metadata:
        encoder: LabelEncoder = bundle.metadata["label_encoder"]
        class_names = [str(item) for item in encoder.classes_]
        pred_idx = int(np.argmax(proba))
        predicted = class_names[pred_idx]
        probabilities = {class_names[i]: float(proba[i]) for i in range(len(class_names))}
        attack_probability = float(
            sum(score for name, score in probabilities.items() if name.casefold() != "benign")
        )
    else:
        class_names = list(bundle.classes) if bundle.classes else ["Benign", "Attack"]
        threshold = float(decision_threshold)
        if len(proba) == 2:
            attack_probability = float(proba[1])
            predicted = "Attack" if attack_probability >= threshold else "Benign"
            probabilities = {
                str(class_names[0]): float(proba[0]),
                str(class_names[1]): float(proba[1]),
            }
        else:
            attack_probability = float(proba[0])
            predicted = "Attack" if attack_probability >= threshold else "Benign"
            probabilities = {"Attack": attack_probability}
    return {
        "category": predicted,
        "probability": round(attack_probability, 6),
        "top_probability": round(float(max(probabilities.values())), 6),
        "probabilities": {key: round(value, 6) for key, value in probabilities.items()},
        "decision_threshold": round(float(decision_threshold), 6),
        "model_version": bundle.metadata.get("artifact_version", ARTIFACT_VERSION),
        "detector": bundle.model_name,
        "task": bundle.task,
    }


def save_classifier(bundle: ClassifierBundle, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(bundle, path)


def load_classifier(path: Path) -> ClassifierBundle:
    return joblib.load(path)
