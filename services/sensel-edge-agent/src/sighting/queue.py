"""Persistent JSONL queue for failed sighting ingest attempts."""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class QueuedSighting:
    event_id: str
    payload: dict[str, Any]
    attempts: int = 0
    queued_at: str = field(default_factory=_now_iso)
    next_retry_at: str = field(default_factory=_now_iso)
    last_error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "event_id": self.event_id,
            "payload": self.payload,
            "attempts": self.attempts,
            "queued_at": self.queued_at,
            "next_retry_at": self.next_retry_at,
            "last_error": self.last_error,
        }

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> QueuedSighting | None:
        if not isinstance(raw, dict):
            return None
        payload = raw.get("payload")
        if not isinstance(payload, dict):
            return None
        event_id = str(raw.get("event_id") or payload.get("raw_event", {}).get("event_id") or "")
        if not event_id:
            return None
        return cls(
            event_id=event_id,
            payload=payload,
            attempts=int(raw.get("attempts") or 0),
            queued_at=str(raw.get("queued_at") or _now_iso()),
            next_retry_at=str(raw.get("next_retry_at") or _now_iso()),
            last_error=str(raw.get("last_error")) if raw.get("last_error") else None,
        )


class SightingQueue:
    def __init__(self, path: str) -> None:
        self._path = Path(path)
        self._path.parent.mkdir(parents=True, exist_ok=True)

    @property
    def path(self) -> Path:
        return self._path

    def load_all(self) -> list[QueuedSighting]:
        if not self._path.is_file():
            return []
        items: list[QueuedSighting] = []
        for line in self._path.read_text(encoding="utf-8").splitlines():
            text = line.strip()
            if not text:
                continue
            try:
                raw = json.loads(text)
            except json.JSONDecodeError:
                logger.warning("Skipping malformed sighting queue line")
                continue
            item = QueuedSighting.from_dict(raw)
            if item is not None:
                items.append(item)
        return items

    def rewrite(self, items: list[QueuedSighting]) -> None:
        if not items:
            if self._path.is_file():
                self._path.unlink()
            return
        lines = [json.dumps(item.to_dict(), ensure_ascii=False) for item in items]
        tmp = self._path.with_suffix(".tmp")
        tmp.write_text("\n".join(lines) + "\n", encoding="utf-8")
        tmp.replace(self._path)
        try:
            self._path.chmod(0o600)
        except OSError:
            pass

    def enqueue(self, item: QueuedSighting) -> None:
        existing = self.load_all()
        if any(entry.event_id == item.event_id for entry in existing):
            return
        existing.append(item)
        self.rewrite(existing)

    def remove(self, event_id: str) -> None:
        if not event_id:
            return
        remaining = [item for item in self.load_all() if item.event_id != event_id]
        self.rewrite(remaining)
