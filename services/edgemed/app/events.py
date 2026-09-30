from __future__ import annotations

import json
from pathlib import Path
from typing import Any


class EventStore:
    """Append-only JSONL event persistence for related-event lookup."""

    def __init__(self, path: Path):
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if not self.path.exists():
            self.path.write_text("", encoding="utf-8")

    def save(self, event: dict[str, Any]) -> dict[str, Any]:
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(event, ensure_ascii=True) + "\n")
        return event

    def get(self, event_id: str) -> dict[str, Any] | None:
        for event in self.iter_events():
            if event.get("event_id") == event_id:
                return event
        return None

    def related(
        self,
        *,
        device_id: str | None = None,
        limit: int = 20,
        exclude_event_id: str | None = None,
    ) -> list[dict[str, Any]]:
        matches: list[dict[str, Any]] = []
        for event in self.iter_events():
            if exclude_event_id and event.get("event_id") == exclude_event_id:
                continue
            asset = event.get("asset") or {}
            if device_id is None or asset.get("device_id") == device_id:
                matches.append(event)
        return matches[-max(1, limit):]

    def iter_events(self):
        if not self.path.exists():
            return
        with self.path.open("r", encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                try:
                    payload = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if isinstance(payload, dict):
                    yield payload
