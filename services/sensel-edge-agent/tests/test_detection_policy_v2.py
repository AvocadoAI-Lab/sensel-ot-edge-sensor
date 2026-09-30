"""Tests for detection policy v2 apply on edge-agent."""

from __future__ import annotations

import json
from pathlib import Path

from src.policy.detection_policy_sync import DetectionPolicySync


def test_detection_policy_v2_stores_rules_without_baseline(tmp_path: Path):
    cfg = type(
        "Cfg",
        (),
        {
            "policy_sync": type(
                "PS",
                (),
                {
                    "detection_policy_enabled": True,
                    "detection_policy_path": str(tmp_path / "detection-policy.json"),
                    "detection_policy_stamp_path": str(tmp_path / "detection-policy.stamp"),
                },
            )(),
        },
    )()
    sync = DetectionPolicySync(cfg)  # type: ignore[arg-type]
    result = sync.apply_artifact(
        {
            "schema_version": "ot_detection_policy.v2",
            "tenant_id": "tenant-a",
            "version": "2026.06.13.v2",
            "rules_enabled": ["OT-001", "OT-005"],
            "thresholds": {"port_scan_unique_ports": 12},
        },
        tenant_id="tenant-a",
    )
    assert result.ok and result.changed
    saved = json.loads((tmp_path / "detection-policy.json").read_text(encoding="utf-8"))
    assert saved["schema_version"] == "ot_detection_policy.v2"
    assert "baseline" not in saved
    assert saved["thresholds"]["port_scan_unique_ports"] == 12
