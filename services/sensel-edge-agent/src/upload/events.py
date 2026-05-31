"""Tail security-events.jsonl and upload new entries to SenseL."""

from __future__ import annotations

import json
import logging
from pathlib import Path

logger = logging.getLogger(__name__)


class SecurityEventTailer:
    def __init__(self, events_path: str, offset_path: str) -> None:
        self._events_path = Path(events_path)
        self._offset_path = Path(offset_path)
        self._offset_path.parent.mkdir(parents=True, exist_ok=True)
        self._offset = self._load_offset()

    def _load_offset(self) -> int:
        if not self._offset_path.is_file():
            return 0
        try:
            return int(self._offset_path.read_text(encoding="utf-8").strip() or "0")
        except ValueError:
            return 0

    def _save_offset(self) -> None:
        self._offset_path.write_text(str(self._offset), encoding="utf-8")

    def pending_events(self) -> list[dict]:
        if not self._events_path.is_file():
            return []

        data = self._events_path.read_bytes()
        if self._offset > len(data):
            self._offset = 0

        chunk = data[self._offset :]
        if not chunk:
            return []

        lines = chunk.splitlines()
        if not lines:
            return []

        # Preserve trailing partial line until the next read.
        ends_with_newline = data.endswith(b"\n")
        complete_lines = lines if ends_with_newline else lines[:-1]
        events: list[dict] = []
        consumed = 0
        for line in complete_lines:
            consumed += len(line) + 1
            text = line.decode("utf-8", errors="replace").strip()
            if not text:
                continue
            try:
                events.append(json.loads(text))
            except json.JSONDecodeError:
                logger.warning("Skipping malformed security event line")
        self._offset += consumed
        self._save_offset()
        return events
