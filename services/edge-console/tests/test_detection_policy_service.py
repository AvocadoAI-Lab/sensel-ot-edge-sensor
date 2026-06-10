"""Applied detection policy read-only service tests."""

from __future__ import annotations

import json
from pathlib import Path

from src.detection_policy_service import build_applied_detection_policy


def _write_policy(tmp_path: Path, payload: dict) -> Path:
    path = tmp_path / "detection-policy.json"
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    stamp = tmp_path / "detection-policy.stamp"
    stamp.write_text("2026-06-05T02:24:52Z\n2026.06.05.022452\n", encoding="utf-8")
    return path


def test_build_applied_policy_parses_rules_and_mms(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("DETECTION_POLICY_PATH", str(tmp_path / "detection-policy.json"))
    monkeypatch.setenv("DETECTION_POLICY_STAMP_PATH", str(tmp_path / "detection-policy.stamp"))
    _write_policy(
        tmp_path,
        {
            "schema_version": "ot_detection_policy.v1",
            "tenant_id": "company-a9ae1234648ee138",
            "site_id": "",
            "version": "2026.06.05.022452",
            "updated_at": "2026-06-05T02:24:52.175347Z",
            "generated_at": "2026-06-05T02:24:52.149780Z",
            "source": "mqtt",
            "rules_enabled": ["OT-016", "OT-001"],
            "baseline": {
                "iec61850": {
                    "mms_ieds": [
                        {
                            "asset_id": "ied-lab-01",
                            "ied_ip": "192.168.10.50",
                            "allowed_mms_clients": ["192.168.10.88"],
                        }
                    ]
                }
            },
        },
    )

    out = build_applied_detection_policy()
    assert out["loaded"] is True
    assert out["version"] == "2026.06.05.022452"
    assert out["source"] == "mqtt"
    assert out["rules_count"] == 2
    assert out["rules_enabled"] == ["OT-001", "OT-016"]
    assert out["mms_summary"][0]["ied_ip"] == "192.168.10.50"
    assert out["mms_summary"][0]["allowed_mms_clients"] == ["192.168.10.88"]
    assert out["stamp"]["version"] == "2026.06.05.022452"


def test_build_applied_policy_missing_file(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("DETECTION_POLICY_PATH", str(tmp_path / "missing.json"))
    monkeypatch.setenv("DETECTION_POLICY_STAMP_PATH", str(tmp_path / "missing.stamp"))

    out = build_applied_detection_policy()
    assert out["loaded"] is False
    assert out["fallback"] is not None


def test_build_applied_policy_invalid_json(tmp_path: Path, monkeypatch):
    policy = tmp_path / "detection-policy.json"
    policy.write_text("{not json", encoding="utf-8")
    monkeypatch.setenv("DETECTION_POLICY_PATH", str(policy))
    monkeypatch.setenv("DETECTION_POLICY_STAMP_PATH", str(tmp_path / "detection-policy.stamp"))

    out = build_applied_detection_policy()
    assert out["loaded"] is False
    assert out["error"]
