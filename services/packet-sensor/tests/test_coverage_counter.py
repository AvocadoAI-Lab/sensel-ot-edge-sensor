"""Unit tests for the edge coverage counter (pre-aggregation BAS coverage)."""

from __future__ import annotations

import json

from src.coverage.counter import CoverageCounter
from src.coverage.mitre_map import techniques_for
from src.detection.models import SecurityEvent


def _event(rule_id: str, event_type: str = "TEST", severity: str = "medium") -> SecurityEvent:
    return SecurityEvent(
        event_id=f"evt-{rule_id}",
        site_id="site-1",
        sensor_id="sensor-1",
        event_type=event_type,
        severity=severity,
        rule_id=rule_id,
        protocol="passive",
        description="unit test event",
    )


def test_mitre_map_known_and_fallback():
    assert techniques_for("OT-006")[0]["id"] == "T0846"
    assert techniques_for("OT-016")[0]["tactic"] == "Impair Process Control"
    # unknown rule falls back via keyword, then DEFAULT
    assert techniques_for("OT-999", event_type="PORT_SCAN_DETECTED")[0]["id"] == "T0846"
    assert techniques_for("OT-999", event_type="weird")[0]["id"] == "T0840"


def test_counter_tallies_rules_and_techniques(tmp_path):
    counter = CoverageCounter(assets_dir=str(tmp_path), sensor_id="s1", site_id="site-1")
    for _ in range(198):
        counter.record(_event("OT-005"))
    for _ in range(3):
        counter.record(_event("OT-006", event_type="PORT_SCAN"))

    snap = counter.snapshot()
    # raw volume preserved (would collapse to a few rows after CP aggregation)
    assert snap["totals"]["events"] == 201
    assert snap["rules"]["OT-005"]["count"] == 198
    assert snap["rules"]["OT-006"]["count"] == 3
    # OT-005 + OT-006 both map to T0846 → technique count is the union sum
    assert snap["techniques"]["T0846"]["count"] == 201
    assert set(snap["techniques"]["T0846"]["rules"]) == {"OT-005", "OT-006"}
    assert snap["totals"]["rules_hit"] == 2
    assert snap["totals"]["techniques_hit"] == 1


def test_counter_flush_writes_atomic_json(tmp_path):
    counter = CoverageCounter(assets_dir=str(tmp_path), sensor_id="s1")
    counter.record(_event("OT-016", event_type="MMS_WRITE"))
    assert counter.flush() is True
    # clean flush is a no-op
    assert counter.flush() is False

    path = tmp_path / "coverage-counters.json"
    assert path.exists()
    data = json.loads(path.read_text(encoding="utf-8"))
    assert data["schema"] == "ot-edge.coverage.v1"
    assert data["rules"]["OT-016"]["count"] == 1
    # OT-016 maps to two techniques (T0855, T0836)
    assert set(data["techniques"].keys()) == {"T0855", "T0836"}


def test_counter_disabled_is_inert(tmp_path):
    counter = CoverageCounter(assets_dir=str(tmp_path), enabled=False)
    counter.record(_event("OT-005"))
    assert counter.snapshot()["totals"]["events"] == 0
    assert counter.flush(force=True) is False
    assert not (tmp_path / "coverage-counters.json").exists()


def test_counter_ignores_blank_rule(tmp_path):
    counter = CoverageCounter(assets_dir=str(tmp_path))
    counter.record(_event("", event_type="noise"))
    assert counter.snapshot()["totals"]["events"] == 0
