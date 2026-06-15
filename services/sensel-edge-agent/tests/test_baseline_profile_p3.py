"""Tests for baseline profile sync and event context enrichment."""

from __future__ import annotations

import json
from pathlib import Path

from src.policy.baseline_profile_sync import BaselineProfileSync
from src.upload.event_context import enrich_security_event


def test_baseline_profile_sync_writes_artifact(tmp_path: Path):
    cfg = type(
        "Cfg",
        (),
        {
            "policy_sync": type(
                "PS",
                (),
                {
                    "baseline_profile_enabled": True,
                    "baseline_profile_path": str(tmp_path / "baseline-profile.json"),
                    "baseline_profile_stamp_path": str(tmp_path / "baseline-profile.stamp"),
                },
            )(),
            "sensor": type("S", (), {"id": "sensor-1"})(),
        },
    )()
    sync = BaselineProfileSync(cfg)  # type: ignore[arg-type]
    result = sync.apply_artifact(
        {
            "schema": "sensel.baseline.profile.v1",
            "profile_id": "prof-1",
            "sensor_id": "sensor-1",
            "version": "2026.06.13.1",
            "observed": {"iec61850": {"mms_ieds": []}},
        },
        tenant_id="tenant-a",
    )
    assert result.ok and result.changed
    saved = json.loads((tmp_path / "baseline-profile.json").read_text(encoding="utf-8"))
    assert saved["profile_id"] == "prof-1"


def test_enrich_security_event_adds_context(tmp_path: Path):
    op_path = tmp_path / "operational-mode.json"
    pol_path = tmp_path / "detection-policy.json"
    prof_path = tmp_path / "baseline-profile.json"
    op_path.write_text(
        json.dumps({"mode": "detect", "baseline_profile_id": "prof-1", "baseline_profile_version": "v1"}),
        encoding="utf-8",
    )
    pol_path.write_text(json.dumps({"version": "pol-v2"}), encoding="utf-8")
    prof_path.write_text(json.dumps({"profile_id": "prof-1", "version": "v1"}), encoding="utf-8")

    out = enrich_security_event(
        {"event_id": "e1", "rule_id": "OT-001"},
        operational_mode_path=op_path,
        detection_policy_path=pol_path,
        baseline_profile_path=prof_path,
    )
    assert out["operational_mode"] == "detect"
    assert out["baseline_profile_id"] == "prof-1"
    assert out["context"]["detection_policy_version"] == "pol-v2"
