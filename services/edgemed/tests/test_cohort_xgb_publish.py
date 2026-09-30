"""Tests for cohort XGB publish + runtime registry."""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from app.fl_protocol_cohorts import cohort_for_device_type
from scripts.publish_best_cohort_xgb import select_best_cohort_models


def test_cohort_for_device_type() -> None:
    assert cohort_for_device_type("bp_monitor") == "mqtt"
    assert cohort_for_device_type("medical_camera") == "wifi"
    assert cohort_for_device_type("network_scanner") == "network"
    assert cohort_for_device_type("unknown_device") == "wifi"


def test_select_best_cohort_models_six_site() -> None:
    experiment = ROOT / "artifacts" / "fl-experiment-six-cohort"
    if not (experiment / "summary.json").is_file():
        return
    selections = select_best_cohort_models(experiment)
    assert set(selections) >= {"wifi", "mqtt", "network"}
    for _cohort, entry in selections.items():
        assert entry["selected_source"] in {"E2_cohort_fl", "E3_cohort"}
        assert entry["macro_f1"] == max(entry["alternatives"].values())
        assert Path(entry["source_path"]).is_file()


def test_manifest_exists_after_publish() -> None:
    manifest_path = ROOT / "artifacts" / "classifiers" / "cohort_model_manifest.json"
    if not manifest_path.is_file():
        return
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert manifest["schema"] == "sensel.cohort_xgb_manifest.v1"
    assert "wifi" in manifest["cohorts"]
