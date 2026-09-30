from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.impute import SimpleImputer
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import RobustScaler

from .data.leakage import is_leakage_column


ARTIFACT_VERSION = "0.1.0"


def numeric_feature_columns(frame: pd.DataFrame, label_column: str | None = None) -> list[str]:
    excluded = {label_column} if label_column else set()
    return [
        column for column in frame.select_dtypes(include=[np.number]).columns
        if column not in excluded and not is_leakage_column(column)
    ]


@dataclass
class DetectorBundle:
    pipeline: Pipeline
    features: list[str]
    threshold: float
    metadata: dict[str, Any]

    def score(self, features: dict[str, float]) -> tuple[float, bool, list[dict[str, float]]]:
        row = pd.DataFrame([{name: features.get(name, np.nan) for name in self.features}])
        raw = -float(self.pipeline.decision_function(row)[0])
        scale = max(abs(self.threshold), 0.05)
        normalized = float(1.0 / (1.0 + np.exp(-(raw - self.threshold) / scale)))
        anomalous = raw >= self.threshold

        center = self.metadata.get("feature_medians", {})
        spread = self.metadata.get("feature_iqrs", {})
        evidence = []
        for name in self.features:
            value = features.get(name)
            if value is None:
                continue
            deviation = abs(float(value) - float(center.get(name, 0.0))) / max(
                float(spread.get(name, 1.0)), 1e-9
            )
            evidence.append({"feature": name, "observed": float(value), "deviation_iqr": deviation})
        evidence.sort(key=lambda item: item["deviation_iqr"], reverse=True)
        return normalized, anomalous, evidence[:3]


def train_detector(frame: pd.DataFrame, label_column: str | None, benign_value: str) -> DetectorBundle:
    features = numeric_feature_columns(frame, label_column)
    if not features:
        raise ValueError("No usable numeric features were found")

    training = frame
    if label_column and label_column in frame.columns:
        mask = frame[label_column].astype(str).str.casefold() == benign_value.casefold()
        if mask.any():
            training = frame.loc[mask]
    if len(training) < 30:
        raise ValueError("At least 30 benign/training rows are required")

    x = training[features].replace([np.inf, -np.inf], np.nan)
    pipeline = Pipeline([
        ("imputer", SimpleImputer(strategy="median")),
        ("scaler", RobustScaler()),
        ("model", IsolationForest(n_estimators=200, contamination="auto", random_state=42, n_jobs=-1)),
    ])
    pipeline.fit(x)
    raw_scores = -pipeline.decision_function(x)
    threshold = float(np.quantile(raw_scores, 0.99))
    medians = x.median(numeric_only=True).fillna(0).to_dict()
    iqrs = (x.quantile(0.75) - x.quantile(0.25)).replace(0, 1).fillna(1).to_dict()
    metadata = {
        "artifact_version": ARTIFACT_VERSION,
        "trained_at": datetime.now(timezone.utc).isoformat(),
        "training_rows": len(training),
        "total_rows": len(frame),
        "label_column": label_column,
        "benign_value": benign_value,
        "threshold_quantile": 0.99,
        "feature_medians": medians,
        "feature_iqrs": iqrs,
    }
    return DetectorBundle(pipeline, features, threshold, metadata)


def save_bundle(bundle: DetectorBundle, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(bundle, path)


def load_bundle(path: Path) -> DetectorBundle:
    return joblib.load(path)


def security_event(
    bundle: DetectorBundle,
    device_id: str,
    device_type: str,
    operating_state: str,
    features: dict[str, float],
) -> dict[str, Any]:
    score, anomalous, evidence = bundle.score(features)
    severity = "high" if score >= 0.85 else "medium" if score >= 0.65 else "low"
    verdict = "anomalous" if anomalous else "baseline"
    event_key = json.dumps([device_id, features], sort_keys=True).encode()
    event_id = "evt_" + hashlib.sha256(event_key).hexdigest()[:16]
    return {
        "schema_version": "0.1",
        "event_id": event_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "asset": {
            "device_id": device_id,
            "device_type": device_type,
            "operating_state": operating_state,
        },
        "detection": {
            "verdict": verdict,
            "anomaly_score": round(score, 6),
            "threshold_raw": round(bundle.threshold, 6),
            "model_version": bundle.metadata["artifact_version"],
        },
        "evidence": evidence,
        "assessment": {
            "severity": severity,
            "summary": f"{device_type} traffic is {verdict} for the observed feature window.",
        },
        "response": {
            "mode": "advisory_only",
            "recommended_actions": [
                "Verify the device operating state",
                "Review source and destination identities",
                "Preserve relevant flow metadata",
            ] if anomalous else [],
        },
    }
