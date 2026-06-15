"""Observe tick publisher tests."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock

from src.config.settings import AppConfig, LoggingConfig, NorthboundMqttConfig, PolicySyncConfig, SenselConfig, SensorIdentity
from src.northbound.observe_tick_publisher import ObserveTickPublisher
from src.policy.operational_mode_sync import OperationalModeSync
from src.policy.topology_override_sync import TopologyOverrideSync


def _config(tmp_path: Path) -> AppConfig:
    return AppConfig(
        sensor=SensorIdentity(id="s1", site_id="site-1"),
        sensel=SenselConfig(api_url="http://127.0.0.1:8081", api_key="k"),
        northbound_mqtt=NorthboundMqttConfig(enabled=True, host="mqtt", tenant_id="tenant-a"),
        policy_sync=PolicySyncConfig(
            operational_mode_enabled=True,
            operational_mode_path=str(tmp_path / "operational-mode.json"),
            operational_mode_stamp_path=str(tmp_path / "operational-mode.stamp"),
            observe_tick_enabled=True,
            observe_tick_interval_sec=60,
            capture_live_path=str(tmp_path / "capture-live.json"),
            live_observed_path=str(tmp_path / "live-observed.json"),
            observe_tick_state_path=str(tmp_path / "observe-tick-state.json"),
        ),
        logging=LoggingConfig(),
    )


def test_observe_tick_publisher_listen_mode(tmp_path: Path):
    cfg = _config(tmp_path)
    (tmp_path / "operational-mode.json").write_text(
        json.dumps({"mode": "listen", "session_id": "sess-1", "tenant_id": "tenant-a"}),
        encoding="utf-8",
    )
    (tmp_path / "capture-live.json").write_text(
        json.dumps({"total_packets": 100, "unique_ips": 5, "unique_macs": 3, "goose_messages": 1}),
        encoding="utf-8",
    )
    mqtt = MagicMock()
    mqtt.enabled = True
    mqtt.publish_observe_tick.return_value = True
    pub = ObserveTickPublisher(cfg, mqtt, OperationalModeSync(cfg))
    assert pub.maybe_publish(force=True) is True
    tick = mqtt.publish_observe_tick.call_args[0][0]
    assert tick["session_kind"] == "observe"
    assert tick["minute_index"] == 1
    assert "snapshot" not in tick


def test_observe_tick_publisher_learning_includes_snapshot(tmp_path: Path):
    cfg = _config(tmp_path)
    (tmp_path / "operational-mode.json").write_text(
        json.dumps({"mode": "learning", "session_id": "sess-2", "tenant_id": "tenant-a"}),
        encoding="utf-8",
    )
    (tmp_path / "capture-live.json").write_text(json.dumps({"total_packets": 10}), encoding="utf-8")
    (tmp_path / "live-observed.json").write_text(json.dumps({"schema": "sensel.baseline/1"}), encoding="utf-8")
    mqtt = MagicMock()
    mqtt.enabled = True
    mqtt.publish_observe_tick.return_value = True
    pub = ObserveTickPublisher(cfg, mqtt, OperationalModeSync(cfg))
    assert pub.maybe_publish(force=True) is True
    tick = mqtt.publish_observe_tick.call_args[0][0]
    assert tick["session_kind"] == "learn"
    assert tick["snapshot"]["schema"] == "sensel.baseline/1"


def test_observe_tick_skips_detect_mode(tmp_path: Path):
    cfg = _config(tmp_path)
    (tmp_path / "operational-mode.json").write_text(
        json.dumps({"mode": "detect", "session_id": "sess-3"}),
        encoding="utf-8",
    )
    mqtt = MagicMock()
    mqtt.enabled = True
    pub = ObserveTickPublisher(cfg, mqtt, OperationalModeSync(cfg))
    assert pub.maybe_publish(force=True) is False
    mqtt.publish_observe_tick.assert_not_called()


def test_observe_tick_listen_includes_topology_delta(tmp_path: Path):
    cfg = _config(tmp_path)
    (tmp_path / "operational-mode.json").write_text(
        json.dumps({"mode": "listen", "session_id": "sess-5", "tenant_id": "tenant-a"}),
        encoding="utf-8",
    )
    (tmp_path / "capture-live.json").write_text(json.dumps({"total_packets": 5}), encoding="utf-8")
    (tmp_path / "live-observed.json").write_text(
        json.dumps(
            {
                "observed": {
                    "topology": {
                        "assets": [{"asset_id": "a1"}, {"asset_id": "a2"}],
                        "conduits": [{"conduit_id": "c1"}],
                        "external_entities": [],
                    }
                }
            }
        ),
        encoding="utf-8",
    )
    (tmp_path / "observe-tick-state.json").write_text(
        json.dumps({"topology_counts": {"assets": 1, "conduits": 0, "external": 0}}),
        encoding="utf-8",
    )
    mqtt = MagicMock()
    mqtt.enabled = True
    mqtt.publish_observe_tick.return_value = True
    pub = ObserveTickPublisher(cfg, mqtt, OperationalModeSync(cfg))
    assert pub.maybe_publish(force=True) is True
    tick = mqtt.publish_observe_tick.call_args[0][0]
    assert tick["session_kind"] == "observe"
    assert tick["topology_delta"]["new_assets"] == 1
    assert tick["topology_delta"]["new_conduits"] == 1
    assert "snapshot" not in tick


def test_observe_tick_merges_topology_manual_overrides(tmp_path: Path):
    cfg = _config(tmp_path)
    override_path = tmp_path / "topology-asset-overrides.json"
    (tmp_path / "operational-mode.json").write_text(
        json.dumps({"mode": "learning", "session_id": "sess-4", "tenant_id": "tenant-a"}),
        encoding="utf-8",
    )
    (tmp_path / "capture-live.json").write_text(json.dumps({"total_packets": 10}), encoding="utf-8")
    (tmp_path / "live-observed.json").write_text(
        json.dumps({"schema": "sensel.baseline/1", "observed": {"comm_pairs": []}}),
        encoding="utf-8",
    )
    override_path.write_text(
        json.dumps(
            {
                "schema": "sensel.ot_topology.override_store.v1",
                "overrides": {
                    "asset-abc": {
                        "asset_id": "asset-abc",
                        "patch": {"purdue_level": "L2", "asset_type": "hmi"},
                        "manual_override": True,
                        "evidence_sources": ["manual_tag"],
                    }
                },
            }
        ),
        encoding="utf-8",
    )
    cfg.policy_sync.topology_override_path = str(override_path)
    mqtt = MagicMock()
    mqtt.enabled = True
    mqtt.publish_observe_tick.return_value = True
    override_sync = TopologyOverrideSync(cfg)
    pub = ObserveTickPublisher(cfg, mqtt, OperationalModeSync(cfg), topology_override_sync=override_sync)
    assert pub.maybe_publish(force=True) is True
    tick = mqtt.publish_observe_tick.call_args[0][0]
    assert tick["topology_manual_overrides"][0]["asset_id"] == "asset-abc"
    assert tick["snapshot"]["observed"]["topology_manual_overrides"][0]["patch"]["purdue_level"] == "L2"
