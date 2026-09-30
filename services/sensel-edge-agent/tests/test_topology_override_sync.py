"""Topology override artifact apply tests."""

from __future__ import annotations

import json
from pathlib import Path

from src.config.settings import AppConfig, LoggingConfig, PolicySyncConfig, SenselConfig, SensorIdentity
from src.policy.topology_override_sync import TopologyOverrideSync


def _config(tmp_path: Path) -> AppConfig:
    return AppConfig(
        sensor=SensorIdentity(id="ot-edge-001", site_id="factory-lab-001"),
        sensel=SenselConfig(api_url="http://127.0.0.1:8081", api_key="k"),
        policy_sync=PolicySyncConfig(
            topology_override_enabled=True,
            topology_override_path=str(tmp_path / "topology-asset-overrides.json"),
            topology_override_stamp_path=str(tmp_path / "topology-asset-overrides.stamp"),
        ),
        logging=LoggingConfig(),
    )


def test_apply_topology_override_writes_store(tmp_path: Path):
    sync = TopologyOverrideSync(_config(tmp_path))
    artifact = {
        "schema": "sensel.ot_topology.override.v1",
        "tenant_id": "company-a9ae1234648ee138",
        "sensor_id": "ot-edge-001",
        "asset_id": "asset-50",
        "issued_at": "2026-06-14T09:30:00Z",
        "patch": {"purdue_level": "L2", "asset_type": "plc", "criticality": "medium"},
        "evidence_sources": ["manual_tag"],
    }
    out = sync.apply_artifact(artifact, tenant_id="company-a9ae1234648ee138", source="mqtt")
    assert out.ok and out.changed
    data = json.loads((tmp_path / "topology-asset-overrides.json").read_text(encoding="utf-8"))
    entry = data["overrides"]["asset-50"]
    assert entry["patch"]["purdue_level"] == "L2"
    assert entry["manual_override"] is True
    assert (tmp_path / "topology-asset-overrides.stamp").is_file()


def test_apply_topology_override_merges_patch(tmp_path: Path):
    sync = TopologyOverrideSync(_config(tmp_path))
    sync.apply_artifact(
        {
            "schema": "sensel.ot_topology.override.v1",
            "tenant_id": "t1",
            "sensor_id": "ot-edge-001",
            "asset_id": "a1",
            "patch": {"purdue_level": "L1"},
        },
        tenant_id="t1",
    )
    out = sync.apply_artifact(
        {
            "schema": "sensel.ot_topology.override.v1",
            "tenant_id": "t1",
            "sensor_id": "ot-edge-001",
            "asset_id": "a1",
            "patch": {"asset_type": "hmi"},
        },
        tenant_id="t1",
    )
    assert out.ok and out.changed
    entry = sync.get_override("a1")
    assert entry["patch"]["purdue_level"] == "L1"
    assert entry["patch"]["asset_type"] == "hmi"


def test_apply_topology_override_sensor_mismatch(tmp_path: Path):
    sync = TopologyOverrideSync(_config(tmp_path))
    out = sync.apply_artifact(
        {
            "tenant_id": "t1",
            "sensor_id": "other-sensor",
            "asset_id": "a1",
            "patch": {"purdue_level": "L2"},
        },
        tenant_id="t1",
    )
    assert not out.ok
