"""S1-03 — EdgeX MQTT feature summary bridge tests."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

from service_loader import import_from_service

ROOT = Path(__file__).resolve().parents[2]


def _import_publisher():
    publisher, ethernet = import_from_service(
        "packet-sensor", "src.features.publisher", "src.parser.l2.ethernet"
    )
    return (
        publisher.FeaturePublisher,
        ethernet.L2Stats,
        ethernet.record_l2,
        ethernet.reset_l2_window,
    )


def test_edgex_mqtt_payload_format() -> None:
    FeaturePublisher, L2Stats, record_l2, reset_l2_window = _import_publisher()

    with tempfile.TemporaryDirectory() as tmp:
        pub = FeaturePublisher(
            sensor_id="ut-001",
            site_id="lab",
            output_dir=tmp,
            mqtt_host="127.0.0.1",
            mqtt_port=1883,
            edgex_device_name="packet-sensor-features",
        )
        published: list[tuple[str, dict]] = []

        def capture(topic: str, payload: dict) -> bool:
            published.append((topic, payload))
            return True

        pub._mqtt.publish_json = capture  # type: ignore[method-assign]

        stats = L2Stats()
        record_l2(stats, "aa:bb:cc:dd:ee:01")
        record_l2(stats, "aa:bb:cc:dd:ee:02")
        record_l2(stats, "aa:bb:cc:dd:ee:01")
        pub.publish_window(stats, window_sec=60)
        reset_l2_window(stats)

        edgex_msgs = [
            p
            for p in published
            if p[0] == "incoming/data/packet-sensor-features/FeatureSummary"
        ]
        assert len(edgex_msgs) == 1
        topic, body = edgex_msgs[0]
        assert topic == "incoming/data/packet-sensor-features/FeatureSummary"
        assert body["PacketRate"] == 0.05
        assert body["UniqueMacCount"] == 2
        assert "name" not in body
        assert "cmd" not in body

        summary_path = Path(tmp) / "feature-summary.json"
        assert summary_path.is_file()
        summary = json.loads(summary_path.read_text())
        assert summary["packet_count"] == 3
        assert summary["unique_mac_count"] == 2

        pub.close()


def test_window_resets_after_flush() -> None:
    FeaturePublisher, L2Stats, record_l2, _reset = _import_publisher()
    PacketPipeline = import_from_service("packet-sensor", "src.pipeline.processor").PacketPipeline

    policy = ROOT / "config/policy/baseline.example.json"
    with tempfile.TemporaryDirectory() as tmp:
        pipeline = PacketPipeline(
            sensor_id="ut-002",
            site_id="lab",
            policy_path=str(policy),
            assets_dir=tmp,
            mqtt_host="",
            feature_window_sec=60,
        )
        record_l2(pipeline.state.l2, "aa:bb:cc:dd:ee:ff")
        pipeline.flush_features()
        assert pipeline.state.l2.window_total == 0
        assert pipeline.state.l2.total == 1
        pipeline.close()
