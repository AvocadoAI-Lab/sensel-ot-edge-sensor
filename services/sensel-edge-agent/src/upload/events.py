"""Tail security-events.jsonl and upload new entries to SenseL.

Tracks a byte offset *plus* a rotation signature (inode + first-line hash) so a
log-rotated or truncated file — even one that ends up the same length — is
detected and re-read from the start instead of silently skipping records.
"""

from __future__ import annotations

import hashlib
import json
import logging
from pathlib import Path

logger = logging.getLogger(__name__)

_HEAD_CAP = 256


class SecurityEventTailer:
    def __init__(self, events_path: str, offset_path: str) -> None:
        self._events_path = Path(events_path)
        self._offset_path = Path(offset_path)
        self._offset_path.parent.mkdir(parents=True, exist_ok=True)
        self._offset, self._ino, self._head = self._load_state()

    def _load_state(self) -> tuple[int, int | None, str]:
        if not self._offset_path.is_file():
            return 0, None, ""
        text = self._offset_path.read_text(encoding="utf-8").strip()
        if not text:
            return 0, None, ""
        try:
            data = json.loads(text)
            if isinstance(data, dict):
                ino = data.get("ino")
                return int(data.get("offset", 0)), int(ino) if ino is not None else None, str(data.get("head", ""))
        except (ValueError, json.JSONDecodeError):
            pass
        # Legacy format: a bare integer offset.
        try:
            return int(text), None, ""
        except ValueError:
            return 0, None, ""

    def _save_state(self) -> None:
        self._offset_path.write_text(
            json.dumps({"offset": self._offset, "ino": self._ino, "head": self._head}),
            encoding="utf-8",
        )

    @staticmethod
    def _head_sig(data: bytes) -> str:
        """Signature of the first line — constant under append, changes on rotate."""
        newline = data.find(b"\n")
        first = data[: newline if newline >= 0 else min(len(data), _HEAD_CAP)]
        return hashlib.sha1(first).hexdigest()

    def pending_events(self) -> list[dict]:
        if not self._events_path.is_file():
            return []

        try:
            ino = getattr(self._events_path.stat(), "st_ino", 0) or 0
        except OSError:
            return []
        data = self._events_path.read_bytes()
        head = self._head_sig(data)

        # Detect rotation/truncation. The first-line/inode check only applies
        # once we have consumed at least one record (offset > 0), so a file
        # whose very first line is still mid-write is not mistaken for a rotate.
        rotated = self._offset > len(data)
        if not rotated and self._offset > 0 and self._head:
            if head != self._head or (self._ino and ino and ino != self._ino):
                rotated = True
        if rotated:
            logger.info("security-events file rotated/truncated; re-reading from start")
            self._offset = 0

        self._ino = ino
        self._head = head

        chunk = data[self._offset :]
        if not chunk:
            self._save_state()
            return []

        lines = chunk.splitlines()
        if not lines:
            self._save_state()
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
        self._save_state()
        return events
