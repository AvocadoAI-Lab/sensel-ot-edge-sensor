from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

import httpx
import pytest

from src.episode.builder import build_trust_episode
from src.features.contract import FeatureContractSpec, FeatureSequenceBuilder
from src.inference.edgemed_client import (
    EdgeMedFeatureMapping,
    EdgeMedScoreClient,
    build_ai_analysis_ref,
    parse_edgemed_score_event,
)
from src.inference.edgemed_pipeline import build_edgemed_inference_pipeline
from src.config.settings import EdgeMedConfig, InferenceConfig


REPO_ROOT = Path(__file__).resolve().parents[3]
CONTRACT_PATH = REPO_ROOT / "config/model/feature-contract.ot-window-v1.json"
MAPPING_PATH = REPO_ROOT / "config/model/edgemed-feature-mapping.ot-window-v1.json"


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
    return sequence, contract


def _sample_event() -> dict:
    return {
        "event_id": "evt_demo123",
        "detection": {
            "status": "ok",
            "baseline": {
                "compliant": True,
                "score": 0.05,
                "violations": [],
                "profile_id": "cic-template-bp-monitor-v1",
                "model_version": "baseline-profile",
            },
            "known_attack": {
                "probability": 0.88,
                "category": "Scan",
                "model_version": "xgboost-category-v1",
            },
            "anomalies": {
                "isolation_forest": {
                    "score": 0.81,
                    "anomalous": True,
                    "model_version": "if-0.1.0",
                    "detector": "isolation_forest",
                },
                "lstm_autoencoder": {
                    "score": 0.93,
                    "anomalous": True,
                    "model_version": "lstm-ae-0.1.0",
                    "detector": "lstm_autoencoder",
                },
            },
        },
        "assessment": {
            "verdict": "suspected_attack",
            "severity": "high",
        },
    }


def test_feature_mapping_maps_ot_window_values() -> None:
    sequence, contract = _sequence()
    mapping = EdgeMedFeatureMapping.load(MAPPING_PATH)

    features = mapping.map_sequence(sequence, contract)

    assert features["packet_rate"] == pytest.approx(10.0)
    assert features["connection_rate"] == pytest.approx(500.0)
    assert features["syn_count"] == pytest.approx(4.0)
    assert features["flow_duration"] == pytest.approx(1.0)


def test_parse_edgemed_score_event_builds_trust_episode() -> None:
    sequence, _contract = _sequence()
    outcome = parse_edgemed_score_event(
        _sample_event(),
        feature_contract_id="ot-window-v1",
        alert_threshold=0.75,
        policy_version="edgemed-bridge-v1",
        latency_ms=12.5,
    )

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
        detections=outcome.signals,
        fusion=outcome.fusion,
    )

    assert outcome.fusion.decision == "alert"
    assert outcome.fusion.score == pytest.approx(0.93)
    assert outcome.fusion.input_ids == (
        "baseline",
        "isolation-forest",
        "xgboost",
        "tiny-lstm",
    )
    assert episode["fusion"]["score"] == pytest.approx(0.93)
    assert episode["ai_analysis_ref"] == ""


class _CapturingTransport(httpx.BaseTransport):
    def __init__(self, event: dict) -> None:
        self._event = event
        self.last_payload: dict | None = None

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        import json

        self.last_payload = json.loads(request.content.decode("utf-8"))
        return httpx.Response(200, json=self._event, request=request)


def test_edgemed_client_posts_mapped_features() -> None:
    sequence, contract = _sequence()
    mapping = EdgeMedFeatureMapping.load(MAPPING_PATH)
    transport = _CapturingTransport(_sample_event())
    http_client = httpx.Client(transport=transport)
    client = EdgeMedScoreClient(
        base_url="http://127.0.0.1:8000",
        timeout_sec=1.0,
        device_type="medical_aiot",
        operating_state="idle",
        criticality="high",
        feature_contract_id="ot-window-v1",
        alert_threshold=0.75,
        policy_version="edgemed-bridge-v1",
        mapping=mapping,
        contract=contract,
        transport=http_client,
    )

    outcome = client.score_sequence(sequence)

    assert transport.last_payload is not None
    assert transport.last_payload["features"]["packet_rate"] == pytest.approx(10.0)
    assert transport.last_payload["fuse"] is True
    assert outcome.fusion.decision == "alert"


def test_build_edgemed_inference_pipeline_uses_remote_backend() -> None:
    config = InferenceConfig(
        enabled=True,
        backend="edgemed",
        fusion_policy_version="edgemed-bridge-v1",
        edgemed=EdgeMedConfig(
            enabled=True,
            base_url="http://127.0.0.1:8000",
            mapping_path=str(MAPPING_PATH),
        ),
    )

    pipeline = build_edgemed_inference_pipeline(
        config,
        feature_contract_id="ot-window-v1",
        feature_contract_path=str(CONTRACT_PATH),
    )

    assert [state.engine_id for state in pipeline.states] == [
        "baseline",
        "isolation-forest",
        "xgboost",
        "tiny-lstm",
    ]


def test_investigate_attaches_ai_analysis_on_alert() -> None:
    score_event = _sample_event()
    investigate_event = {
        **score_event,
        "assessment": {
            "verdict": "suspected_attack",
            "severity": "high",
            "summary": "Observed elevated anomaly score on packet_rate.",
            "generation_status": "generated",
        },
    }

    class _DualTransport(httpx.BaseTransport):
        def handle_request(self, request: httpx.Request) -> httpx.Response:
            import json

            if request.url.path.endswith("/api/score"):
                return httpx.Response(200, json=score_event, request=request)
            if request.url.path.endswith("/api/investigate"):
                return httpx.Response(
                    200,
                    json={
                        "event": investigate_event,
                        "slm": {
                            "status": "runtime_loaded",
                            "model_id": "SmolLM2-360M",
                            "generation_status": "generated",
                        },
                    },
                    request=request,
                )
            raise AssertionError(f"unexpected path: {request.url.path}")

    sequence, contract = _sequence()
    mapping = EdgeMedFeatureMapping.load(MAPPING_PATH)
    client = EdgeMedScoreClient(
        base_url="http://127.0.0.1:8000",
        timeout_sec=1.0,
        investigate_timeout_sec=2.0,
        device_type="medical_aiot",
        operating_state="idle",
        criticality="high",
        feature_contract_id="ot-window-v1",
        alert_threshold=0.75,
        policy_version="edgemed-bridge-v1",
        mapping=mapping,
        contract=contract,
        investigate_enabled=True,
        transport=httpx.Client(transport=_DualTransport()),
    )

    outcome = client.score_sequence(sequence)

    assert outcome.ai_analysis is not None
    assert outcome.ai_analysis.event_id == "evt_demo123"
    assert outcome.ai_analysis.generation_status == "generated"
    assert "Observed elevated anomaly score" in outcome.ai_analysis.summary
    ai = build_ai_analysis_ref(
        investigate_event,
        slm_status={"status": "runtime_loaded", "model_id": "SmolLM2-360M"},
    )
    assert ai.ref.startswith('{"source":"edgemed"')
