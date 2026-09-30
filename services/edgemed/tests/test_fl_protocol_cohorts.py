"""Tests for FL protocol cohort mapping."""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from app.fl_protocol_cohorts import (
    cohort_index,
    group_site_ids_by_cohort,
    resolve_fl_protocol_group,
)


def test_resolve_fl_protocol_group_explicit() -> None:
    assert resolve_fl_protocol_group({"fl_protocol_group": "mqtt"}) == "mqtt"


def test_resolve_fl_protocol_group_from_device_type() -> None:
    assert resolve_fl_protocol_group({"device_type": "bp_monitor"}) == "mqtt"
    assert resolve_fl_protocol_group({"device_type": "medical_camera"}) == "wifi"
    assert resolve_fl_protocol_group({"device_type": "network_scanner"}) == "network"


def test_cohort_for_device_type() -> None:
    from app.fl_protocol_cohorts import cohort_for_device_type

    assert cohort_for_device_type("baby_sensor") == "mqtt"
    assert cohort_for_device_type("network_gateway") == "network"


def test_six_site_cohort_index() -> None:
    splits = ROOT / "artifacts" / "fl-experiment-six" / "splits"
    if not splits.is_dir():
        return
    site_ids = tuple(sorted(path.stem for path in splits.glob("site-*.json")))
    index = cohort_index(site_ids, splits_dir=splits)
    assert index["cohort_count"] >= 2
    groups = group_site_ids_by_cohort(site_ids, splits_dir=splits)
    for site_id in site_ids:
        spec = json.loads((splits / f"{site_id}.json").read_text(encoding="utf-8"))
        cohort = resolve_fl_protocol_group(spec)
        assert site_id in groups[cohort]
