"""Efficient security-events.jsonl reads with TTL cache."""

from __future__ import annotations

import json
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

_TAIL_RECENT_BYTES = 256 * 1024
_STATS_MAX_BYTES = 2 * 1024 * 1024
_CACHE_TTL_SEC = 30.0


@dataclass(frozen=True)
class EventsStats:
    events_24h: int
    rule_counts_24h: dict[str, int]
    recent_events: list[dict[str, Any]]


_cache: dict[str, Any] = {
    "key": None,
    "stats": None,
    "cached_at": 0.0,
}


def _parse_event_ts(ev: dict[str, Any]) -> float | None:
    ts = ev.get("timestamp") or ev.get("detected_at") or ""
    if not ts:
        return None
    try:
        text = str(ts)
        if text.endswith("Z"):
            text = text.replace("Z", "+00:00")
        return datetime.fromisoformat(text).timestamp()
    except ValueError:
        return None


def _read_tail_bytes(path: Path, max_bytes: int) -> list[str]:
    if not path.is_file():
        return []
    size = path.stat().st_size
    if size <= 0:
        return []
    with path.open("rb") as fh:
        fh.seek(max(0, size - max_bytes))
        chunk = fh.read().decode("utf-8", errors="replace")
    lines = [ln for ln in chunk.splitlines() if ln.strip()]
    if size > max_bytes and lines:
        lines = lines[1:]
    return lines


def _stats_cache_valid(path: Path) -> bool:
    if _cache["stats"] is None:
        return False
    if (time.monotonic() - float(_cache["cached_at"])) > _CACHE_TTL_SEC:
        return False
    try:
        stat = path.stat()
    except OSError:
        return False
    key = (stat.st_mtime_ns, stat.st_size)
    return _cache["key"] == key


def scan_events_stats(path: Path, *, recent_limit: int = 8) -> EventsStats:
    if not path.is_file():
        return EventsStats(0, {}, [])

    if _stats_cache_valid(path):
        return _cache["stats"]

    stat = path.stat()
    cutoff = datetime.now(timezone.utc).timestamp() - 86400
    counts: dict[str, int] = {}
    events_24h = 0
    stale_streak = 0

    for line in _read_tail_bytes(path, _STATS_MAX_BYTES):
        try:
            ev = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(ev, dict):
            continue
        ts = _parse_event_ts(ev)
        if ts is not None:
            if ts >= cutoff:
                events_24h += 1
                stale_streak = 0
                rid = str(ev.get("rule_id") or ev.get("event_class") or "unknown").upper()
                counts[rid] = counts.get(rid, 0) + 1
            else:
                stale_streak += 1
                if stale_streak >= 500:
                    break

    recent: list[dict[str, Any]] = []
    for line in reversed(_read_tail_bytes(path, _TAIL_RECENT_BYTES)):
        try:
            ev = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(ev, dict):
            recent.append(ev)
        if len(recent) >= recent_limit:
            break

    stats = EventsStats(events_24h=events_24h, rule_counts_24h=counts, recent_events=recent)
    _cache["key"] = (stat.st_mtime_ns, stat.st_size)
    _cache["stats"] = stats
    _cache["cached_at"] = time.monotonic()
    return stats


def read_jsonl_tail(path: Path, limit: int = 5) -> list[dict[str, Any]]:
    """Small tail read for non-dashboard endpoints."""
    return scan_events_stats(path, recent_limit=limit).recent_events


def read_merged_jsonl_tail(paths: list[Path], limit: int = 5) -> list[dict[str, Any]]:
    """Merge recent events from multiple JSONL sources, newest first.

    Packet-sensor detections land in ``security-events.jsonl``; Suricata/Snort
    IDS bridges write to separate files. The console presents a unified view.
    """
    if limit <= 0:
        return []
    per_file = min(max(limit * 3, limit), 200)
    combined: list[dict[str, Any]] = []
    for path in paths:
        combined.extend(scan_events_stats(path, recent_limit=per_file).recent_events)
    combined.sort(key=lambda ev: _parse_event_ts(ev) or 0.0, reverse=True)
    seen: set[str] = set()
    out: list[dict[str, Any]] = []
    for ev in combined:
        eid = str(ev.get("event_id") or "").strip()
        if eid:
            if eid in seen:
                continue
            seen.add(eid)
        out.append(ev)
        if len(out) >= limit:
            break
    return out
