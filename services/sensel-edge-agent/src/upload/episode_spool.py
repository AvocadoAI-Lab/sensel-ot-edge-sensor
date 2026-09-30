"""Durable, deduplicated Trust Episode spool with per-wire acknowledgements."""

from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import Any

@dataclass(frozen=True)
class SpoolEntry:
    id: int
    episode_id: str
    json_envelope: dict[str, Any]
    protobuf_payload: bytes
    trace_id: str
    json_delivered: bool
    protobuf_delivered: bool
    attempts: int


class TrustEpisodeSpool:
    def __init__(self, db_path: str | Path, *, max_episodes: int = 2000) -> None:
        if max_episodes <= 0:
            raise ValueError("max_episodes must be positive")
        self.path = Path(db_path)
        self.max_episodes = max_episodes
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(self.path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=FULL")
        self._init_schema()

    def _init_schema(self) -> None:
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS trust_episode_spool (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                episode_id TEXT NOT NULL UNIQUE,
                json_envelope TEXT NOT NULL,
                protobuf_payload BLOB NOT NULL,
                trace_id TEXT NOT NULL,
                json_delivered INTEGER NOT NULL DEFAULT 0,
                protobuf_delivered INTEGER NOT NULL DEFAULT 0,
                attempts INTEGER NOT NULL DEFAULT 0,
                last_error TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL DEFAULT (datetime('now'))
            )
            """
        )
        self._conn.commit()

    def enqueue(
        self,
        *,
        episode_id: str,
        json_envelope: dict[str, Any],
        protobuf_payload: bytes,
        trace_id: str,
    ) -> bool:
        identity = episode_id.strip()
        if not identity or not protobuf_payload:
            raise ValueError("episode_id and protobuf_payload are required")
        if self._conn.execute(
            "SELECT 1 FROM trust_episode_spool WHERE episode_id = ?",
            (identity,),
        ).fetchone():
            return False
        if self.depth() >= self.max_episodes:
            raise OverflowError(
                f"Trust Episode spool capacity reached ({self.max_episodes})"
            )
        cursor = self._conn.execute(
            """
            INSERT OR IGNORE INTO trust_episode_spool
                (episode_id, json_envelope, protobuf_payload, trace_id)
            VALUES (?, ?, ?, ?)
            """,
            (
                identity,
                json.dumps(
                    json_envelope,
                    ensure_ascii=False,
                    separators=(",", ":"),
                    sort_keys=True,
                ),
                sqlite3.Binary(protobuf_payload),
                trace_id,
            ),
        )
        inserted = cursor.rowcount > 0
        self._conn.commit()
        return inserted

    def pending(self, *, limit: int = 100) -> list[SpoolEntry]:
        rows = self._conn.execute(
            """
            SELECT id, episode_id, json_envelope, protobuf_payload, trace_id,
                   json_delivered, protobuf_delivered, attempts
            FROM trust_episode_spool
            ORDER BY id ASC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
        return [
            SpoolEntry(
                id=int(row["id"]),
                episode_id=str(row["episode_id"]),
                json_envelope=json.loads(row["json_envelope"]),
                protobuf_payload=bytes(row["protobuf_payload"]),
                trace_id=str(row["trace_id"]),
                json_delivered=bool(row["json_delivered"]),
                protobuf_delivered=bool(row["protobuf_delivered"]),
                attempts=int(row["attempts"]),
            )
            for row in rows
        ]

    def acknowledge(self, entry_id: int, channel: str) -> None:
        if channel not in {"json", "protobuf"}:
            raise ValueError("episode spool channel must be json or protobuf")
        column = "json_delivered" if channel == "json" else "protobuf_delivered"
        self._conn.execute(
            f"UPDATE trust_episode_spool SET {column} = 1, last_error = '' WHERE id = ?",
            (entry_id,),
        )
        self._conn.commit()

    def record_failure(self, entry_id: int, error: str) -> None:
        self._conn.execute(
            """
            UPDATE trust_episode_spool
            SET attempts = attempts + 1, last_error = ?
            WHERE id = ?
            """,
            (str(error)[:2048], entry_id),
        )
        self._conn.commit()

    def remove_if_complete(self, entry_id: int, mode: str) -> bool:
        requirements = {
            "json": "json_delivered = 1",
            "protobuf": "protobuf_delivered = 1",
            "dual": "json_delivered = 1 AND protobuf_delivered = 1",
        }
        if mode not in requirements:
            raise ValueError("wire mode must be json, dual, or protobuf")
        cursor = self._conn.execute(
            f"DELETE FROM trust_episode_spool WHERE id = ? AND {requirements[mode]}",
            (entry_id,),
        )
        self._conn.commit()
        return cursor.rowcount > 0

    def depth(self) -> int:
        return int(
            self._conn.execute("SELECT COUNT(*) FROM trust_episode_spool").fetchone()[0]
        )

    def close(self) -> None:
        self._conn.close()
