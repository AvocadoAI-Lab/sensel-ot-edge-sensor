from __future__ import annotations

import pytest

from src.fusion.engine import DetectionSignal, RiskFusionPolicy


def _signals() -> list[DetectionSignal]:
    return [
        DetectionSignal("isolation-forest", "1.0.0", 0.81),
        DetectionSignal("xgboost", "1.0.0", 0.88),
        DetectionSignal("tiny-lstm", "1.0.0", 0.93),
    ]


def test_default_fusion_matches_canonical_episode() -> None:
    decision = RiskFusionPolicy().fuse(_signals())

    assert decision.score == pytest.approx(0.913)
    assert decision.weighted_mean == pytest.approx((0.81 + 0.88 + 0.93) / 3)
    assert decision.maximum_score == 0.93
    assert decision.decision == "alert"
    assert decision.severity == "high"
    assert decision.input_ids == (
        "isolation-forest",
        "xgboost",
        "tiny-lstm",
    )


def test_unavailable_engine_is_audited_but_not_scored() -> None:
    decision = RiskFusionPolicy().fuse(
        [
            DetectionSignal("isolation-forest", "1.0.0", 0.8),
            DetectionSignal(
                "tiny-lstm",
                "1.0.0",
                available=False,
                error="runtime unavailable",
            ),
        ]
    )

    assert decision.score == pytest.approx(0.8)
    assert decision.input_ids == ("isolation-forest",)
    assert decision.unavailable_ids == ("tiny-lstm",)


def test_no_available_engine_has_safe_unavailable_decision() -> None:
    decision = RiskFusionPolicy().fuse(
        [DetectionSignal("tiny-lstm", "1.0.0", available=False)]
    )

    assert decision.score == 0
    assert decision.decision == "unavailable"
    assert decision.input_ids == ()


def test_invalid_available_score_is_rejected() -> None:
    with pytest.raises(ValueError, match="between 0 and 1"):
        RiskFusionPolicy().fuse([DetectionSignal("xgboost", "1.0.0", 1.01)])
