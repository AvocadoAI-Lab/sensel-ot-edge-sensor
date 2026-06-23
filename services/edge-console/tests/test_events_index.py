"""Tests for security-events.jsonl indexing."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from src.events_index import read_merged_jsonl_tail, scan_events_stats


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


def test_read_merged_jsonl_tail_orders_by_timestamp(tmp_path: Path) -> None:
    now = datetime.now(timezone.utc).replace(microsecond=0)
    older = (now.timestamp() - 3600)
    newer = now.isoformat()
    old_iso = datetime.fromtimestamp(older, tz=timezone.utc).replace(microsecond=0).isoformat()

    security = tmp_path / "security-events.jsonl"
    security.write_text(
        json.dumps({"event_id": "evt-ot", "rule_id": "OT-016", "timestamp": old_iso}) + "\n",
        encoding="utf-8",
    )
    suricata = tmp_path / "suricata-events.jsonl"
    suricata.write_text(
        json.dumps({"event_id": "evt-suri", "rule_id": "suricata-1-2000001", "timestamp": newer})
        + "\n",
        encoding="utf-8",
    )

    merged = read_merged_jsonl_tail([security, suricata], limit=10)
    assert len(merged) == 2
    assert merged[0]["event_id"] == "evt-suri"
    assert merged[1]["event_id"] == "evt-ot"
