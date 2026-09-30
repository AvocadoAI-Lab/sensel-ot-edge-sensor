"""Detection policy MQTT artifact apply tests."""

from __future__ import annotations

import json
from pathlib import Path

from src.config.settings import AppConfig, LoggingConfig, PolicySyncConfig, SenselConfig, SensorIdentity
from src.policy.detection_policy_sync import DetectionPolicySync


def _config(tmp_path: Path) -> AppConfig:
    return AppConfig(
        sensor=SensorIdentity(id="s1", site_id="factory-lab-001"),
        sensel=SenselConfig(api_url="http://127.0.0.1:8081", api_key="k"),
        policy_sync=PolicySyncConfig(
            detection_policy_enabled=True,
            detection_policy_path=str(tmp_path / "detection-policy.json"),
            detection_policy_stamp_path=str(tmp_path / "detection-policy.stamp"),
        ),
        logging=LoggingConfig(),
    )


def test_apply_detection_policy_writes_files(tmp_path: Path):
    sync = DetectionPolicySync(_config(tmp_path))
    artifact = {
        "schema_version": "ot_detection_policy.v1",
        "tenant_id": "tenant-a",
        "site_id": "factory-lab-001",
        "version": "2026.06.05.1",
        "rules_enabled": ["OT-016", "OT-019"],
        "baseline": {"iec61850": {"mms_ieds": []}},
    }
    out = sync.apply_artifact(artifact, tenant_id="tenant-a", source="mqtt")
    assert out.ok and out.changed
    data = json.loads((tmp_path / "detection-policy.json").read_text(encoding="utf-8"))
    assert data["rules_enabled"] == ["OT-016", "OT-019"]
    assert (tmp_path / "detection-policy.stamp").is_file()


def test_apply_detection_policy_idempotent(tmp_path: Path):
    sync = DetectionPolicySync(_config(tmp_path))
    artifact = {
        "version": "v1",
        "tenant_id": "tenant-a",
        "rules_enabled": ["OT-016"],
        "baseline": {},
    }
    sync.apply_artifact(artifact, tenant_id="tenant-a")
    out = sync.apply_artifact(artifact, tenant_id="tenant-a")
    assert out.ok and not out.changed
