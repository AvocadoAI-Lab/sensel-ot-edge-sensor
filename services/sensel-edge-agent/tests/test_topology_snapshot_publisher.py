"""Topology snapshot publisher tests (PRD §6.1)."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock

from src.config.settings import AppConfig, LoggingConfig, NorthboundMqttConfig, PolicySyncConfig, SenselConfig, SensorIdentity
from src.northbound.topology_snapshot_publisher import TopologySnapshotPublisher
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
            topology_snapshot_enabled=True,
            topology_snapshot_interval_sec=60,
            live_observed_path=str(tmp_path / "live-observed.json"),
            topology_snapshot_state_path=str(tmp_path / "topology-snapshot-state.json"),
            topology_override_path=str(tmp_path / "topology-asset-overrides.json"),
            topology_override_stamp_path=str(tmp_path / "topology-asset-overrides.stamp"),
        ),
        logging=LoggingConfig(),
    )


def _topology() -> dict:
    return {
        "schema": "sensel.ot_topology.snapshot.v1",
        "assets": [{"asset_id": "asset-1", "ip": "10.0.0.1", "purdue_level": "L1"}],
        "conduits": [{"src_asset_id": "asset-1", "dst_asset_id": "asset-2"}],
        "zone_counts": {"L1": 1},
    }


def test_topology_snapshot_learning_mode(tmp_path: Path):
    cfg = _config(tmp_path)
    (tmp_path / "operational-mode.json").write_text(
        json.dumps({"mode": "learning", "session_id": "sess-1", "tenant_id": "tenant-a"}),
        encoding="utf-8",
    )
    (tmp_path / "live-observed.json").write_text(
        json.dumps({"schema": "sensel.baseline/1", "observed": {"topology": _topology()}}),
        encoding="utf-8",
    )
    mqtt = MagicMock()
    mqtt.enabled = True
    mqtt.publish_topology_snapshot.return_value = True
    pub = TopologySnapshotPublisher(cfg, mqtt, OperationalModeSync(cfg))
    assert pub.maybe_publish(force=True) is True
    payload = mqtt.publish_topology_snapshot.call_args[0][0]
    assert payload["operational_mode"] == "learning"
    assert payload["snapshot"]["assets"][0]["asset_id"] == "asset-1"
    state = json.loads((tmp_path / "topology-snapshot-state.json").read_text(encoding="utf-8"))
    assert state["asset_count"] == 1


def test_topology_snapshot_detect_mode_delta_only(tmp_path: Path):
    cfg = _config(tmp_path)
    cfg.policy_sync.topology_snapshot_detect_interval_sec = 60
    (tmp_path / "operational-mode.json").write_text(
        json.dumps({"mode": "detect", "session_id": "sess-2", "tenant_id": "tenant-a"}),
        encoding="utf-8",
    )
    (tmp_path / "live-observed.json").write_text(
        json.dumps(
            {
                "observed": {
                    "topology": {
                        "assets": [{"asset_id": "a1"}, {"asset_id": "a2"}, {"asset_id": "a3"}],
                        "conduits": [{"conduit_id": "c1"}],
                        "external_entities": [],
                    }
                }
            }
        ),
        encoding="utf-8",
    )
    (tmp_path / "topology-snapshot-state.json").write_text(
        json.dumps({"topology_counts": {"assets": 2, "conduits": 0, "external": 0}}),
        encoding="utf-8",
    )
    mqtt = MagicMock()
    mqtt.enabled = True
    mqtt.publish_topology_snapshot.return_value = True
    pub = TopologySnapshotPublisher(cfg, mqtt, OperationalModeSync(cfg))
    assert pub.maybe_publish(force=True) is True
    payload = mqtt.publish_topology_snapshot.call_args[0][0]
    assert payload["operational_mode"] == "detect"
    assert payload["topology_delta"]["new_assets"] == 1
    assert "snapshot" not in payload


def test_topology_snapshot_detect_skips_without_topology(tmp_path: Path):
    cfg = _config(tmp_path)
    (tmp_path / "operational-mode.json").write_text(
        json.dumps({"mode": "detect", "session_id": "sess-2b", "tenant_id": "tenant-a"}),
        encoding="utf-8",
    )
    mqtt = MagicMock()
    mqtt.enabled = True
    pub = TopologySnapshotPublisher(cfg, mqtt, OperationalModeSync(cfg))
    assert pub.maybe_publish(force=True) is False
    mqtt.publish_topology_snapshot.assert_not_called()


def test_topology_snapshot_skips_listen_mode(tmp_path: Path):
    cfg = _config(tmp_path)
    (tmp_path / "operational-mode.json").write_text(
        json.dumps({"mode": "listen", "session_id": "sess-3"}),
        encoding="utf-8",
    )
    (tmp_path / "live-observed.json").write_text(
        json.dumps({"observed": {"topology": _topology()}}),
        encoding="utf-8",
    )
    mqtt = MagicMock()
    mqtt.enabled = True
    pub = TopologySnapshotPublisher(cfg, mqtt, OperationalModeSync(cfg))
    assert pub.maybe_publish(force=True) is False
    mqtt.publish_topology_snapshot.assert_not_called()


def test_topology_snapshot_applies_manual_overrides(tmp_path: Path):
    cfg = _config(tmp_path)
    (tmp_path / "operational-mode.json").write_text(
        json.dumps({"mode": "learning", "session_id": "sess-4", "tenant_id": "tenant-a"}),
        encoding="utf-8",
    )
    topo = _topology()
    (tmp_path / "live-observed.json").write_text(
        json.dumps({"observed": {"topology": topo}}),
        encoding="utf-8",
    )
    (tmp_path / "topology-asset-overrides.json").write_text(
        json.dumps(
            {
                "schema": "sensel.ot_topology.override_store.v1",
                "overrides": {
                    "asset-1": {
                        "asset_id": "asset-1",
                        "patch": {"purdue_level": "L2", "asset_type": "hmi"},
                    }
                },
            }
        ),
        encoding="utf-8",
    )
    mqtt = MagicMock()
    mqtt.enabled = True
    mqtt.publish_topology_snapshot.return_value = True
    override_sync = TopologyOverrideSync(cfg)
    pub = TopologySnapshotPublisher(
        cfg, mqtt, OperationalModeSync(cfg), topology_override_sync=override_sync
    )
    assert pub.maybe_publish(force=True) is True
    asset = mqtt.publish_topology_snapshot.call_args[0][0]["snapshot"]["assets"][0]
    assert asset["purdue_level"] == "L2"
    assert asset["asset_type"] == "hmi"
    assert asset["manual_override"] is True
