from __future__ import annotations

import json
from pathlib import Path

from src.config.settings import SensorIdentity
from src.northbound.wire_mode import WireModeController
from src.upload.episode_spool import TrustEpisodeSpool
from src.upload.episodes import (
    TrustEpisodeTailer,
    drain_episode_spool,
    enqueue_pending_episodes,
)


def _episode() -> dict:
    return {
        "episode_id": "episode-p1b-1",
        "asset_id": "sensor:old",
        "tenant_id": "old-tenant",
        "site_id": "old-site",
        "sensor_id": "old-sensor",
        "observed_at": "2026-08-12T01:00:00Z",
        "started_at": "2026-08-12T00:01:00Z",
        "ended_at": "2026-08-12T01:00:00Z",
        "sequence": 60,
        "trace_id": "trace-p1b-1",
        "producer_version": "old",
        "asset_identity": {"confidence": 1.0},
        "features": {
            "feature_contract_id": "ot-window-v1",
            "sequence_length": 60,
            "sequence_ref": "sha256:test",
            "latest_values": [0.1, 0.2],
        },
        "detections": [
            {
                "engine_id": "isolation-forest",
                "model_version": "if-v1",
                "score": 0.9,
                "label": "anomaly",
                "feature_contract_id": "ot-window-v1",
                "available": True,
            }
        ],
        "fusion": {
            "policy_version": "fusion-v1",
            "score": 0.9,
            "threshold": 0.75,
            "decision": "alert",
            "severity": "high",
            "input_ids": ["isolation-forest"],
        },
        "policy": {},
    }


class _Mqtt:
    enabled = True
    connected = True

    def __init__(self, protobuf_results: list[bool] | None = None) -> None:
        self.protobuf_results = list(protobuf_results or [True])
        self.json_calls = 0
        self.protobuf_calls = 0

    def publish_trust_episode_json(self, _envelope) -> bool:
        self.json_calls += 1
        return True

    def publish_trust_episode_protobuf(self, _payload, *, trace_id: str) -> bool:
        assert trace_id == "trace-p1b-1"
        self.protobuf_calls += 1
        return self.protobuf_results.pop(0)


def _enqueue(tmp_path: Path) -> TrustEpisodeSpool:
    source = tmp_path / "trust-episodes.jsonl"
    source.write_text(json.dumps(_episode()) + "\n", encoding="utf-8")
    tailer = TrustEpisodeTailer(source, tmp_path / "episodes.offset")
    spool = TrustEpisodeSpool(tmp_path / "episodes.db")
    count = enqueue_pending_episodes(
        tailer,
        spool,
        tenant_id="tenant-current",
        sensor=SensorIdentity(
            id="sensor-current",
            site_id="site-current",
            software_version="0.2.0",
        ),
    )
    assert count == 1
    assert int((tmp_path / "episodes.offset").read_text()) == source.stat().st_size
    entry = spool.pending()[0]
    assert entry.json_envelope["tenant_id"] == "tenant-current"
    assert entry.json_envelope["sensor_id"] == "sensor-current"
    return spool


def test_dual_publish_requires_both_acks(tmp_path: Path) -> None:
    spool = _enqueue(tmp_path)
    wire = WireModeController(
        "dual",
        failure_threshold=3,
        state_path=tmp_path / "wire.json",
    )
    mqtt = _Mqtt([True])

    assert drain_episode_spool(spool, mqtt, wire) == 1
    assert spool.depth() == 0
    assert mqtt.json_calls == 1
    assert mqtt.protobuf_calls == 1
    spool.close()


def test_protobuf_failures_persistently_rollback_to_json(tmp_path: Path) -> None:
    spool = _enqueue(tmp_path)
    state_path = tmp_path / "wire.json"
    wire = WireModeController("dual", failure_threshold=1, state_path=state_path)
    mqtt = _Mqtt([False])

    # JSON is already delivered, so automatic rollback safely compacts this row.
    assert drain_episode_spool(spool, mqtt, wire) == 1
    assert wire.effective_mode == "json"
    assert json.loads(state_path.read_text())["effective_mode"] == "json"
    restarted = WireModeController("dual", failure_threshold=1, state_path=state_path)
    assert restarted.effective_mode == "json"
    spool.close()


def test_full_spool_backpressures_without_advancing_offset(tmp_path: Path) -> None:
    source = tmp_path / "trust-episodes.jsonl"
    second = _episode()
    second["episode_id"] = "episode-p1b-2"
    second["trace_id"] = "trace-p1b-2"
    source.write_text(
        json.dumps(_episode()) + "\n" + json.dumps(second) + "\n",
        encoding="utf-8",
    )
    first_line_size = len((json.dumps(_episode()) + "\n").encode())
    tailer = TrustEpisodeTailer(source, tmp_path / "episodes.offset")
    spool = TrustEpisodeSpool(tmp_path / "episodes.db", max_episodes=1)

    assert enqueue_pending_episodes(
        tailer,
        spool,
        tenant_id="tenant-current",
        sensor=SensorIdentity(id="sensor-current", site_id="site-current"),
    ) == 1
    assert tailer.offset == first_line_size
    assert spool.depth() == 1
    spool.close()
