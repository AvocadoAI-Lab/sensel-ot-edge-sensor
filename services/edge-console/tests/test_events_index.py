"""Tests for security-events.jsonl indexing."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from src.events_index import scan_events_stats


def test_scan_events_stats_tail_and_24h(tmp_path: Path) -> None:
    events = tmp_path / "security-events.jsonl"
    now = datetime.now(timezone.utc).replace(microsecond=0).isoformat()
    lines = [
        json.dumps({"rule_id": "OT-016", "timestamp": now, "event_type": "x"}),
        json.dumps({"rule_id": "OT-019", "timestamp": now, "event_type": "y"}),
    ]
    events.write_text("\n".join(lines) + "\n", encoding="utf-8")
    stats = scan_events_stats(events)
    assert stats.events_24h == 2
    assert stats.rule_counts_24h["OT-016"] == 1
    assert len(stats.recent_events) >= 1
