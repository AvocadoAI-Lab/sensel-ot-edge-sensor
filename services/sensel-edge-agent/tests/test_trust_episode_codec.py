from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from src.contracts.trust_episode_codec import (
    decode_trust_episode,
    encode_trust_episode,
)


SERVICE_ROOT = Path(__file__).resolve().parents[1]
FIXTURE_PATH = Path(__file__).parent / "fixtures" / "trust_episode.v1.bin"
MANIFEST_PATH = SERVICE_ROOT / "sensel" / "CONTRACT_MANIFEST.json"


def _episode() -> dict:
    return {
        "episode_id": "episode-golden-v1-0001",
        "asset_id": "asset-plc-golden",
        "tenant_id": "tenant-golden",
        "site_id": "site-golden",
        "sensor_id": "sensor-golden",
        "observed_at": "2026-08-12T01:00:00Z",
        "started_at": "2026-08-12T00:01:00Z",
        "ended_at": "2026-08-12T01:00:00Z",
        "sequence": 43,
        "trace_id": "trace-episode-golden-0001",
        "producer_version": "0.2.0",
        "asset_identity": {
            "manufacturer": "Golden Controls",
            "product_family": "PLC",
            "model": "GC-100",
            "firmware_version": "1.2.3",
            "serial_number": "GOLDEN-0001",
            "confidence": 0.94,
            "attributes": {"identity_source": "edgex+passive"},
        },
        "features": {
            "feature_contract_id": "ot-window-v1",
            "sequence_length": 60,
            "sequence_ref": "sha256:golden-sequence",
            "latest_values": [
                6.216606,
                2.397895,
                1.609438,
                0.693147,
                0,
                0,
                0.693147,
                0.693147,
                1.098612,
                0,
                0,
            ],
        },
        "detections": [
            {
                "engine_id": "isolation-forest",
                "model_version": "1.0.0",
                "score": 0.81,
                "label": "anomaly",
                "feature_contract_id": "ot-window-v1",
                "available": True,
            },
            {
                "engine_id": "xgboost",
                "model_version": "1.0.0",
                "score": 0.88,
                "label": "lateral_movement",
                "feature_contract_id": "ot-window-v1",
                "available": True,
            },
            {
                "engine_id": "tiny-lstm",
                "model_version": "1.0.0",
                "score": 0.93,
                "label": "temporal_anomaly",
                "feature_contract_id": "ot-window-v1",
                "available": True,
            },
        ],
        "fusion": {
            "policy_version": "fusion-v1",
            "score": 0.913,
            "threshold": 0.75,
            "decision": "alert",
            "severity": "high",
            "input_ids": ["isolation-forest", "xgboost", "tiny-lstm"],
        },
        "evidence": [
            {
                "uri": "local-ringbuffer://episode-golden-v1-0001",
                "sha256": "golden-evidence-sha256",
                "media_type": "application/vnd.tcpdump.pcap",
                "retention_class": "security-event",
            }
        ],
        "supply_chain": {"vendor_risk": "review"},
        "policy": {
            "policy_id": "ot-default",
            "policy_version": "1.0.0",
            "operational_mode": "detect",
            "attributes": {"source": "local-cache"},
        },
        "ai_analysis_ref": "",
    }


def test_edge_encoder_matches_canonical_trust_episode_wire() -> None:
    manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    expected = FIXTURE_PATH.read_bytes()
    actual = encode_trust_episode(_episode())

    assert actual == expected
    assert hashlib.sha256(actual).hexdigest() == (
        manifest["golden_fixtures"]["trust_episode.v1.bin"]["sha256"]
    )


def test_trust_episode_round_trip_preserves_detection_and_fusion() -> None:
    decoded = decode_trust_episode(encode_trust_episode(_episode()))

    assert decoded["episode_id"] == "episode-golden-v1-0001"
    assert decoded["features"]["feature_contract_id"] == "ot-window-v1"
    assert [item["engine_id"] for item in decoded["detections"]] == [
        "isolation-forest",
        "xgboost",
        "tiny-lstm",
    ]
    assert decoded["fusion"]["score"] == pytest.approx(0.913)
    assert decoded["fusion"]["severity"] == "high"
    assert decoded["ai_analysis_ref"] == ""


def test_trust_episode_rejects_inverted_time_range() -> None:
    episode = _episode()
    episode["ended_at"] = "2026-08-11T23:00:00Z"

    with pytest.raises(ValueError, match="must not precede"):
        encode_trust_episode(episode)


def test_trust_episode_rejects_fusion_inputs_that_do_not_match_detections() -> None:
    episode = _episode()
    episode["fusion"]["input_ids"] = ["tiny-lstm"]

    with pytest.raises(ValueError, match="must match available detection order"):
        encode_trust_episode(episode)
