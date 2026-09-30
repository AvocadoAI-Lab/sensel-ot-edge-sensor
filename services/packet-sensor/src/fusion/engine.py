"""Versioned, deterministic, and auditable risk-score fusion."""

from __future__ import annotations

import math
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field


@dataclass(frozen=True)
class DetectionSignal:
    engine_id: str
    model_version: str
    score: float = 0.0
    label: str = ""
    rule_id: str = ""
    feature_contract_id: str = ""
    available: bool = True
    error: str = ""
    attributes: Mapping[str, object] = field(default_factory=dict)

    def validate(self) -> None:
        if not self.engine_id.strip():
            raise ValueError("detection signal engine_id is required")
        if self.available and (not math.isfinite(self.score) or not 0 <= self.score <= 1):
            raise ValueError(
                f"detection signal {self.engine_id} score must be between 0 and 1"
            )


@dataclass(frozen=True)
class FusionDecision:
    policy_version: str
    score: float
    threshold: float
    decision: str
    severity: str
    input_ids: tuple[str, ...]
    unavailable_ids: tuple[str, ...]
    weighted_mean: float
    maximum_score: float


@dataclass(frozen=True)
class RiskFusionPolicy:
    policy_version: str = "fusion-v1"
    alert_threshold: float = 0.75
    maximum_weight: float = 0.7
    engine_weights: Mapping[str, float] = field(default_factory=dict)
    severity_thresholds: tuple[tuple[float, str], ...] = (
        (0.0, "info"),
        (0.25, "low"),
        (0.5, "medium"),
        (0.75, "high"),
        (0.95, "critical"),
    )

    def __post_init__(self) -> None:
        if not self.policy_version.strip():
            raise ValueError("fusion policy_version is required")
        if not 0 <= self.alert_threshold <= 1:
            raise ValueError("fusion alert_threshold must be between 0 and 1")
        if not 0 <= self.maximum_weight <= 1:
            raise ValueError("fusion maximum_weight must be between 0 and 1")
        for engine_id, weight in self.engine_weights.items():
            if not engine_id.strip() or not math.isfinite(weight) or weight <= 0:
                raise ValueError("fusion engine weights must be positive and finite")
        if not self.severity_thresholds:
            raise ValueError("fusion severity thresholds are required")
        thresholds = [threshold for threshold, _name in self.severity_thresholds]
        if thresholds != sorted(thresholds) or thresholds[0] != 0:
            raise ValueError("fusion severity thresholds must be ordered from zero")
        if any(not 0 <= threshold <= 1 for threshold in thresholds):
            raise ValueError("fusion severity thresholds must be between 0 and 1")

    def fuse(self, signals: Sequence[DetectionSignal]) -> FusionDecision:
        engine_ids: set[str] = set()
        available: list[DetectionSignal] = []
        unavailable: list[str] = []
        input_ids: list[str] = []
        for signal in signals:
            signal.validate()
            engine_id = signal.engine_id.strip()
            if engine_id in engine_ids:
                raise ValueError(f"duplicate detection engine_id: {engine_id}")
            engine_ids.add(engine_id)
            if signal.available:
                available.append(signal)
                input_ids.append(engine_id)
            else:
                unavailable.append(engine_id)

        if not available:
            return FusionDecision(
                policy_version=self.policy_version,
                score=0.0,
                threshold=self.alert_threshold,
                decision="unavailable",
                severity="info",
                input_ids=(),
                unavailable_ids=tuple(unavailable),
                weighted_mean=0.0,
                maximum_score=0.0,
            )

        ordered = sorted(available, key=lambda item: item.engine_id)
        weighted_total = 0.0
        total_weight = 0.0
        for signal in ordered:
            weight = float(self.engine_weights.get(signal.engine_id, 1.0))
            weighted_total += signal.score * weight
            total_weight += weight
        weighted_mean = weighted_total / total_weight
        maximum_score = max(signal.score for signal in ordered)
        fused_score = (
            self.maximum_weight * maximum_score
            + (1 - self.maximum_weight) * weighted_mean
        )
        fused_score = min(1.0, max(0.0, fused_score))
        severity = "info"
        for threshold, name in self.severity_thresholds:
            if fused_score >= threshold:
                severity = name

        return FusionDecision(
            policy_version=self.policy_version,
            score=fused_score,
            threshold=self.alert_threshold,
            decision="alert" if fused_score >= self.alert_threshold else "observe",
            severity=severity,
            input_ids=tuple(input_ids),
            unavailable_ids=tuple(unavailable),
            weighted_mean=weighted_mean,
            maximum_score=maximum_score,
        )
