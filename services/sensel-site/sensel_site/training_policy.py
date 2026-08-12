"""Immutable XGBoost training and candidate-validation policy."""

from __future__ import annotations

import hashlib
import json
import math
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from sensel_site.lineage import canonical_json

_IDENTITY = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
_PARAMETERS = {
    "objective",
    "eval_metric",
    "tree_method",
    "device",
    "max_depth",
    "eta",
    "subsample",
    "colsample_bytree",
    "min_child_weight",
    "lambda",
    "alpha",
    "seed",
    "nthread",
}


@dataclass(frozen=True)
class XGBoostTrainingPolicy:
    policy_id: str
    version: str
    definition_sha256: str
    positive_labels: frozenset[str]
    negative_labels: frozenset[str]
    validation_fraction: float
    minimum_samples: int
    minimum_per_class: int
    minimum_validation_per_class: int
    num_boost_round: int
    parameters: dict[str, Any]
    maximum_samples: int
    maximum_features: int
    maximum_dataset_bytes: int
    maximum_model_bytes: int
    maximum_boost_rounds: int
    minimum_balanced_accuracy: float
    maximum_logloss: float
    metric_tolerance: float

    def encode_label(self, value: Any) -> int:
        if not isinstance(value, str) or not value.strip():
            raise ValueError("training sample label is required")
        normalized = value.strip().casefold()
        if normalized in self.positive_labels:
            return 1
        if normalized in self.negative_labels:
            return 0
        raise ValueError(f"training sample label is not allowed by policy: {normalized}")


def load_xgboost_policy(path: str | Path) -> XGBoostTrainingPolicy:
    policy_path = Path(path)
    document = json.loads(policy_path.read_text(encoding="utf-8"))
    expected = str(document.pop("definition_sha256", "")).strip()
    actual = hashlib.sha256(canonical_json(document)).hexdigest()
    if not expected or actual != expected:
        raise ValueError(f"training policy definition digest mismatch: {policy_path}")
    if document.get("schema_version") != "sensel.site.xgboost-training-policy.v1":
        raise ValueError("unsupported XGBoost training policy schema")
    if document.get("algorithm") != "xgboost" or document.get("artifact_format") != "ubj":
        raise ValueError("training policy algorithm/artifact format is invalid")
    if not all(
        _IDENTITY.fullmatch(str(document.get(name) or ""))
        for name in ("policy_id", "version")
    ):
        raise ValueError("training policy identity/version is invalid")

    labels = document["labels"]
    if any(
        not isinstance(item, str) or not _IDENTITY.fullmatch(item.strip())
        for item in (*labels["positive"], *labels["negative"])
    ):
        raise ValueError("training policy labels contain invalid values")
    positive = frozenset(str(item).strip().casefold() for item in labels["positive"])
    negative = frozenset(str(item).strip().casefold() for item in labels["negative"])
    if not positive or not negative or positive & negative:
        raise ValueError("training policy labels must be non-empty and disjoint")
    split = document["split"]
    training = document["training"]
    gates = document["validation_gates"]
    parameters = dict(training["parameters"])
    if set(parameters) != _PARAMETERS:
        raise ValueError("training policy contains unsupported XGBoost parameters")
    if parameters.get("objective") != "binary:logistic":
        raise ValueError("only binary:logistic XGBoost training is allowed")
    if parameters.get("tree_method") != "hist" or parameters.get("device") != "cpu":
        raise ValueError("Site XGBoost policy requires CPU histogram training")
    if int(parameters.get("nthread", 0)) != 1:
        raise ValueError("Site XGBoost policy requires deterministic single-thread training")
    if parameters.get("eval_metric") != "logloss":
        raise ValueError("Site XGBoost policy requires logloss evaluation")
    if not 1 <= int(parameters["max_depth"]) <= 16:
        raise ValueError("XGBoost max_depth is outside policy bounds")
    for name in ("eta", "subsample", "colsample_bytree"):
        value = float(parameters[name])
        if not math.isfinite(value) or not 0 < value <= 1:
            raise ValueError(f"XGBoost parameter is outside policy bounds: {name}")
    for name in ("min_child_weight", "lambda", "alpha"):
        value = float(parameters[name])
        if not math.isfinite(value) or value < 0:
            raise ValueError(f"XGBoost parameter is outside policy bounds: {name}")

    policy = XGBoostTrainingPolicy(
        policy_id=str(document["policy_id"]),
        version=str(document["version"]),
        definition_sha256="sha256:" + expected,
        positive_labels=positive,
        negative_labels=negative,
        validation_fraction=float(split["validation_fraction"]),
        minimum_samples=int(split["minimum_samples"]),
        minimum_per_class=int(split["minimum_per_class"]),
        minimum_validation_per_class=int(split["minimum_validation_per_class"]),
        num_boost_round=int(training["num_boost_round"]),
        parameters=parameters,
        maximum_samples=int(gates["maximum_samples"]),
        maximum_features=int(gates["maximum_features"]),
        maximum_dataset_bytes=int(gates["maximum_dataset_bytes"]),
        maximum_model_bytes=int(gates["maximum_model_bytes"]),
        maximum_boost_rounds=int(gates["maximum_boost_rounds"]),
        minimum_balanced_accuracy=float(gates["minimum_balanced_accuracy"]),
        maximum_logloss=float(gates["maximum_logloss"]),
        metric_tolerance=float(gates["metric_tolerance"]),
    )
    if not 0 < policy.validation_fraction < 0.5:
        raise ValueError("validation_fraction must be between zero and 0.5")
    if (
        policy.minimum_samples < 4
        or policy.minimum_per_class < 2
        or policy.minimum_validation_per_class < 1
        or policy.maximum_samples < policy.minimum_samples
        or policy.maximum_features < 1
        or policy.maximum_dataset_bytes < 1_048_576
        or policy.maximum_model_bytes < 1024
        or policy.maximum_boost_rounds < 1
        or policy.num_boost_round < 1
    ):
        raise ValueError("training sample gates are unsafe")
    if not 0 <= policy.minimum_balanced_accuracy <= 1:
        raise ValueError("balanced accuracy gate is invalid")
    if policy.maximum_logloss <= 0 or policy.metric_tolerance <= 0:
        raise ValueError("metric validation gates are invalid")
    if policy.num_boost_round > policy.maximum_boost_rounds:
        raise ValueError("training rounds exceed validation policy")
    return policy
