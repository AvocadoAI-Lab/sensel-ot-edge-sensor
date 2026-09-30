"""Tests for baseline profile store precedence over detection policy."""

from __future__ import annotations

import json
from pathlib import Path

from src.policy.baseline_profile_store import BaselineProfileStore, observed_to_detection_baseline
from src.policy.detection_policy_store import DetectionPolicyStore


def test_observed_to_detection_baseline_maps_iec61850():
    observed = {
        "iec61850": {
            "mms_ieds": [{"ied_ip": "10.0.0.5", "allowed_mms_clients": ["10.0.0.1"]}],
            "goose_publishers": [],
        }
    }
    out = observed_to_detection_baseline(observed)
    assert out["iec61850"]["mms_ieds"][0]["ied_ip"] == "10.0.0.5"


def test_detection_policy_store_prefers_profile_baseline(tmp_path: Path):
    policy_path = tmp_path / "detection-policy.json"
    stamp_path = tmp_path / "detection-policy.stamp"
    profile_path = tmp_path / "baseline-profile.json"
    profile_stamp = tmp_path / "baseline-profile.stamp"
    fallback = tmp_path / "fallback.json"
    fallback.write_text(json.dumps({"iec61850": {"mms_ieds": []}}), encoding="utf-8")
    policy_path.write_text(
        json.dumps({"rules_enabled": ["OT-001"], "baseline": {"policy_version": "legacy"}}),
        encoding="utf-8",
    )
    stamp_path.write_text("legacy-stamp\n", encoding="utf-8")
    profile_path.write_text(
        json.dumps(
            {
                "profile_id": "p1",
                "observed": {
                    "iec61850": {"mms_ieds": [{"ied_ip": "192.168.10.50", "allowed_mms_clients": []}]}
                },
            }
        ),
        encoding="utf-8",
    )
    profile_stamp.write_text("prof-stamp\n", encoding="utf-8")

    store = DetectionPolicyStore(
        policy_path=policy_path,
        stamp_path=stamp_path,
        fallback_policy_path=fallback,
        baseline_profile_path=profile_path,
        baseline_profile_stamp_path=profile_stamp,
        reload_check_sec=0,
    )
    baseline = store.policy()
    assert baseline["iec61850"]["mms_ieds"][0]["ied_ip"] == "192.168.10.50"
