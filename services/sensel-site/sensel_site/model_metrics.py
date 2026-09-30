"""Deterministic binary classification metrics used by trainer and validator."""

from __future__ import annotations

import math
from collections.abc import Sequence
from typing import Any


def binary_metrics(labels: Sequence[int], probabilities: Sequence[float]) -> dict[str, Any]:
    if not labels or len(labels) != len(probabilities):
        raise ValueError("metric inputs must be non-empty and equal length")
    if set(labels) != {0, 1}:
        raise ValueError("metric labels must contain both binary classes")
    if any(not math.isfinite(value) or not 0 <= value <= 1 for value in probabilities):
        raise ValueError("model probabilities must be finite and between zero and one")
    predicted = [1 if value >= 0.5 else 0 for value in probabilities]
    true_negative = sum(a == 0 and b == 0 for a, b in zip(labels, predicted))
    false_positive = sum(a == 0 and b == 1 for a, b in zip(labels, predicted))
    false_negative = sum(a == 1 and b == 0 for a, b in zip(labels, predicted))
    true_positive = sum(a == 1 and b == 1 for a, b in zip(labels, predicted))
    negative_count = true_negative + false_positive
    positive_count = true_positive + false_negative
    epsilon = 1e-15
    loss = -sum(
        label * math.log(min(1 - epsilon, max(epsilon, probability)))
        + (1 - label)
        * math.log(min(1 - epsilon, max(epsilon, 1 - probability)))
        for label, probability in zip(labels, probabilities)
    ) / len(labels)
    accuracy = (true_positive + true_negative) / len(labels)
    balanced = 0.5 * (
        true_positive / positive_count + true_negative / negative_count
    )
    return {
        "sample_count": len(labels),
        "accuracy": round(accuracy, 12),
        "balanced_accuracy": round(balanced, 12),
        "logloss": round(loss, 12),
        "confusion_matrix": {
            "true_negative": true_negative,
            "false_positive": false_positive,
            "false_negative": false_negative,
            "true_positive": true_positive,
        },
    }
