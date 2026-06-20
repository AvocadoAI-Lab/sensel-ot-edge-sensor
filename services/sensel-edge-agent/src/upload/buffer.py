"""Offline upload buffer and retry queue — health + security events."""

from __future__ import annotations

import json
import logging
import sqlite3
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


class UploadBuffer:
    def __init__(self, db_path: str, max_events: int = 1000) -> None:
        self._db_path = Path(db_path)
        self._max_events = max_events
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(self._db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._init_schema()

    def _init_schema(self) -> None:
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS pending_uploads (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                kind TEXT NOT NULL,
                payload TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT (datetime('now'))
            )
            """
        )
        self._conn.commit()

    def enqueue(self, kind: str, payload: dict[str, Any]) -> None:
        self._conn.execute(
            "INSERT INTO pending_uploads (kind, payload) VALUES (?, ?)",
            (kind, json.dumps(payload)),
        )
        count = self._conn.execute("SELECT COUNT(*) FROM pending_uploads").fetchone()[0]
        if count > self._max_events:
            overflow = count - self._max_events
            self._conn.execute(
                """
                DELETE FROM pending_uploads
                WHERE id IN (
                    SELECT id FROM pending_uploads ORDER BY id ASC LIMIT ?
                )
                """,
                (overflow,),
            )
            logger.warning("Upload buffer trimmed %d oldest entries", overflow)
        self._conn.commit()

    def pending(self) -> list[tuple[int, str, dict[str, Any]]]:
        rows = self._conn.execute(
            "SELECT id, kind, payload FROM pending_uploads ORDER BY id ASC"
        ).fetchall()
        return [(row["id"], row["kind"], json.loads(row["payload"])) for row in rows]

    def remove(self, entry_id: int) -> None:
        self._conn.execute("DELETE FROM pending_uploads WHERE id = ?", (entry_id,))
        self._conn.commit()

    def remove_by_event_id(self, event_id: str) -> None:
        if not event_id:
            return
        rows = self._conn.execute(
            "SELECT id, payload FROM pending_uploads WHERE kind = 'event'"
        ).fetchall()
        for row in rows:
            try:
                payload = json.loads(row["payload"])
            except json.JSONDecodeError:
                continue
            if str(payload.get("event_id")) == event_id:
                self.remove(int(row["id"]))

    def close(self) -> None:
        self._conn.close()
