"""SecurityEventTailer — offset tracking and rotation/truncation handling."""

from __future__ import annotations

import json
from pathlib import Path

from service_loader import import_from_service


def _import_tailer():
    events = import_from_service("sensel-edge-agent", "src.upload.events")
    return events.SecurityEventTailer


def _event(n: int) -> str:
    return json.dumps({"event_id": f"evt-{n:05d}", "rule_id": "OT-001"}) + "\n"


def test_tail_reads_new_lines_only(tmp_path: Path) -> None:
    SecurityEventTailer = _import_tailer()
    events = tmp_path / "security-events.jsonl"
    offset = tmp_path / "events.offset"
    events.write_text(_event(1) + _event(2), encoding="utf-8")

    tailer = SecurityEventTailer(str(events), str(offset))
    first = tailer.pending_events()
    assert [e["event_id"] for e in first] == ["evt-00001", "evt-00002"]
    assert tailer.pending_events() == []  # nothing new

    events.write_text(_event(1) + _event(2) + _event(3), encoding="utf-8")
    third = tailer.pending_events()
    assert [e["event_id"] for e in third] == ["evt-00003"]


def test_tail_ignores_trailing_partial_line(tmp_path: Path) -> None:
    SecurityEventTailer = _import_tailer()
    events = tmp_path / "security-events.jsonl"
    offset = tmp_path / "events.offset"
    events.write_text(_event(1) + '{"event_id":"evt-partial"', encoding="utf-8")
    tailer = SecurityEventTailer(str(events), str(offset))
    assert [e["event_id"] for e in tailer.pending_events()] == ["evt-00001"]
    # complete the partial line later
    events.write_text(_event(1) + _event(2), encoding="utf-8")
    assert [e["event_id"] for e in tailer.pending_events()] == ["evt-00002"]


def test_tail_detects_rotation_same_offset(tmp_path: Path) -> None:
    """A rotated file (new first line) must be re-read from the start."""
    SecurityEventTailer = _import_tailer()
    events = tmp_path / "security-events.jsonl"
    offset = tmp_path / "events.offset"
    events.write_text(_event(1) + _event(2), encoding="utf-8")
    tailer = SecurityEventTailer(str(events), str(offset))
    assert len(tailer.pending_events()) == 2

    # Rotate: brand-new content with a different first line.
    events.write_text(_event(9) + _event(10), encoding="utf-8")
    rotated = tailer.pending_events()
    assert [e["event_id"] for e in rotated] == ["evt-00009", "evt-00010"]


def test_tail_handles_truncation(tmp_path: Path) -> None:
    SecurityEventTailer = _import_tailer()
    events = tmp_path / "security-events.jsonl"
    offset = tmp_path / "events.offset"
    events.write_text(_event(1) + _event(2) + _event(3), encoding="utf-8")
    tailer = SecurityEventTailer(str(events), str(offset))
    assert len(tailer.pending_events()) == 3

    events.write_text(_event(7), encoding="utf-8")  # truncated shorter
    out = tailer.pending_events()
    assert [e["event_id"] for e in out] == ["evt-00007"]
