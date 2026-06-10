"""Detection policy hot-reload store tests."""

from __future__ import annotations

import json
from pathlib import Path

from src.policy.detection_policy_store import DetectionPolicyStore


def test_detection_policy_store_reload(tmp_path: Path):
    fallback = tmp_path / "baseline.json"
    fallback.write_text('{"iec61850": {"mms_ieds": []}}', encoding="utf-8")
    policy_path = tmp_path / "detection-policy.json"
    stamp_path = tmp_path / "detection-policy.stamp"

    store = DetectionPolicyStore(
        policy_path=policy_path,
        stamp_path=stamp_path,
        fallback_policy_path=fallback,
        reload_check_sec=0,
    )
    assert store.rules_enabled() == set()

    policy_path.write_text(
        json.dumps(
            {
                "version": "v1",
                "rules_enabled": ["OT-016"],
                "baseline": {
                    "iec61850": {
                        "mms_ieds": [
                            {"ied_ip": "192.168.10.50", "allowed_mms_clients": ["192.168.10.88"]}
                        ]
                    }
                },
            }
        ),
        encoding="utf-8",
    )
    stamp_path.write_text("stamp-1\nv1\n", encoding="utf-8")
    store.maybe_reload(force=True)
    assert store.rules_enabled() == {"OT-016"}
    assert store.policy()["iec61850"]["mms_ieds"][0]["ied_ip"] == "192.168.10.50"
