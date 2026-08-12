from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

from src.episode.builder import build_trust_episode
from src.features.contract import FeatureContractSpec, FeatureSequenceBuilder
from src.fusion.engine import DetectionSignal, RiskFusionPolicy


REPO_ROOT = Path(__file__).resolve().parents[3]
CONTRACT_PATH = REPO_ROOT / "config/model/feature-contract.ot-window-v1.json"


def _sequence():
    contract = FeatureContractSpec.load(CONTRACT_PATH)
    builder = FeatureSequenceBuilder(contract)
    started = datetime(2026, 8, 12, tzinfo=timezone.utc)
    sequence = None
    for offset in range(60):
        sequence = builder.add_frame(
            entity_id="sensor-a",
            observed_at=started + timedelta(minutes=offset),
            sequence_number=offset + 1,
            values={
                "packet_count": 500,
                "packet_rate": 10.0,
                "unique_mac_count": 4,
            },
        )
    assert sequence is not None
    return sequence


def test_episode_is_complete_without_ai_analysis() -> None:
    sequence = _sequence()
    signals = [
        DetectionSignal(
            "isolation-forest",
            "1.0.0",
            0.81,
            feature_contract_id="ot-window-v1",
        ),
        DetectionSignal(
            "xgboost",
            "1.0.0",
            0.88,
            feature_contract_id="ot-window-v1",
        ),
        DetectionSignal(
            "tiny-lstm",
            "1.0.0",
            0.93,
            feature_contract_id="ot-window-v1",
        ),
    ]
    fusion = RiskFusionPolicy().fuse(signals)

    episode = build_trust_episode(
        episode_id="episode-a",
        asset_id="asset-a",
        tenant_id="tenant-a",
        site_id="site-a",
        sensor_id="sensor-a",
        sequence_number=60,
        trace_id="trace-a",
        producer_version="0.2.0",
        feature_sequence=sequence,
        detections=signals,
        fusion=fusion,
    )

    assert episode["features"]["sequence_length"] == 60
    assert episode["features"]["sequence_ref"].startswith("sha256:")
    assert episode["fusion"]["score"] == fusion.score
    assert episode["ai_analysis_ref"] == ""
