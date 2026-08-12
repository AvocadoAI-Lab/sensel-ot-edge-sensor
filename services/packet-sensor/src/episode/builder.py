"""Build an SLM-independent Trust Episode from local deterministic signals."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from datetime import datetime, timezone
from typing import Any

from src.features.contract import FeatureSequence
from src.fusion.engine import DetectionSignal, FusionDecision


def _timestamp(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def build_trust_episode(
    *,
    episode_id: str,
    asset_id: str,
    tenant_id: str,
    site_id: str,
    sensor_id: str,
    sequence_number: int,
    trace_id: str,
    producer_version: str,
    feature_sequence: FeatureSequence,
    detections: Sequence[DetectionSignal],
    fusion: FusionDecision,
    asset_identity: Mapping[str, Any] | None = None,
    evidence: Sequence[Mapping[str, Any]] = (),
    supply_chain: Mapping[str, Any] | None = None,
    policy: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Return the stable dictionary accepted by the Edge Agent protobuf codec."""

    required = {
        "episode_id": episode_id,
        "asset_id": asset_id,
        "tenant_id": tenant_id,
        "site_id": site_id,
        "sensor_id": sensor_id,
        "producer_version": producer_version,
    }
    missing = [name for name, value in required.items() if not str(value).strip()]
    if missing:
        raise ValueError(f"Trust Episode requires: {', '.join(sorted(missing))}")
    if sequence_number < 0:
        raise ValueError("Trust Episode sequence_number must be non-negative")
    if not detections:
        raise ValueError("Trust Episode requires at least one detection signal")
    detection_ids = [signal.engine_id for signal in detections if signal.available]
    if tuple(detection_ids) != fusion.input_ids:
        raise ValueError("fusion input_ids must match available detection order")

    return {
        "episode_id": episode_id.strip(),
        "asset_id": asset_id.strip(),
        "tenant_id": tenant_id.strip(),
        "site_id": site_id.strip(),
        "sensor_id": sensor_id.strip(),
        "observed_at": _timestamp(feature_sequence.ended_at),
        "started_at": _timestamp(feature_sequence.started_at),
        "ended_at": _timestamp(feature_sequence.ended_at),
        "sequence": sequence_number,
        "trace_id": trace_id,
        "producer_version": producer_version.strip(),
        "asset_identity": dict(asset_identity or {}),
        "features": {
            "feature_contract_id": feature_sequence.contract_id,
            "sequence_length": len(feature_sequence.frames),
            "sequence_ref": f"sha256:{feature_sequence.sequence_sha256}",
            "latest_values": list(feature_sequence.latest_values),
        },
        "detections": [
            {
                "engine_id": signal.engine_id,
                "model_version": signal.model_version,
                "score": signal.score,
                "label": signal.label,
                "rule_id": signal.rule_id,
                "feature_contract_id": signal.feature_contract_id,
                "available": signal.available,
                "error": signal.error,
                "attributes": dict(signal.attributes),
            }
            for signal in detections
        ],
        "fusion": {
            "policy_version": fusion.policy_version,
            "score": fusion.score,
            "threshold": fusion.threshold,
            "decision": fusion.decision,
            "severity": fusion.severity,
            "input_ids": list(fusion.input_ids),
        },
        "evidence": [dict(item) for item in evidence],
        "supply_chain": dict(supply_chain or {}),
        "policy": dict(policy or {}),
        "ai_analysis_ref": "",
    }
