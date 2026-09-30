"""Crash-safe desired command state and observed report outbox."""

from __future__ import annotations

import base64
import json
import os
import sqlite3
import tempfile
import time
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from google.protobuf.message import DecodeError
from sensel.device.v1 import device_management_pb2


class InvalidDesiredDeviceCommand(ValueError):
    pass


def decode_desired_command(
    payload: bytes,
    *,
    tenant_id: str,
    site_id: str,
    sensor_id: str,
    now: datetime | None = None,
) -> device_management_pb2.DesiredDeviceStateCommand:
    if not payload or len(payload) > 256 * 1024:
        raise InvalidDesiredDeviceCommand("desired command payload is empty or too large")
    message = device_management_pb2.DesiredDeviceStateCommand()
    try:
        message.ParseFromString(payload)
    except DecodeError as exc:
        raise InvalidDesiredDeviceCommand("desired command is not valid protobuf") from exc
    required = {
        "meta.event_id": message.meta.event_id,
        "command_id": message.command_id,
        "asset_id": message.asset_id,
        "desired.config_revision": message.desired.config_revision,
        "desired.sampling_profile": message.desired.sampling_profile,
    }
    missing = [name for name, value in required.items() if not value.strip()]
    if missing:
        raise InvalidDesiredDeviceCommand(
            f"desired command missing required fields: {', '.join(missing)}"
        )
    if message.meta.event_id != message.command_id:
        raise InvalidDesiredDeviceCommand("meta.event_id must equal command_id")
    if not message.meta.HasField("observed_at"):
        raise InvalidDesiredDeviceCommand("desired command requires meta.observed_at")
    expected = (tenant_id, site_id, sensor_id)
    actual = (message.meta.tenant_id, message.meta.site_id, message.meta.sensor_id)
    if actual != expected:
        raise InvalidDesiredDeviceCommand("desired command route does not match this edge")
    if (
        message.desired.lifecycle_state
        == device_management_pb2.DEVICE_LIFECYCLE_STATE_UNSPECIFIED
    ):
        raise InvalidDesiredDeviceCommand("desired lifecycle_state is unspecified")
    if not message.HasField("expires_at"):
        raise InvalidDesiredDeviceCommand("desired command requires expires_at")
    current = now or datetime.now(timezone.utc)
    expiry = message.expires_at.ToDatetime(tzinfo=timezone.utc)
    if expiry <= current:
        raise InvalidDesiredDeviceCommand("desired command has expired")
    if expiry <= message.meta.observed_at.ToDatetime(tzinfo=timezone.utc):
        raise InvalidDesiredDeviceCommand("expires_at must follow meta.observed_at")
    return message


def _atomic_json(path: Path, body: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    handle, temporary = tempfile.mkstemp(
        dir=str(path.parent), prefix=f".{path.name}-", suffix=".tmp"
    )
    try:
        with os.fdopen(handle, "w", encoding="utf-8") as stream:
            json.dump(body, stream, ensure_ascii=False, indent=2, sort_keys=True)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


class DesiredCommandStore:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self._lock = threading.RLock()

    def _load(self) -> dict[str, Any]:
        try:
            body = json.loads(self.path.read_text(encoding="utf-8"))
            return body if isinstance(body, dict) else {"commands": {}}
        except (OSError, json.JSONDecodeError):
            return {"commands": {}}

    def accept(self, command: device_management_pb2.DesiredDeviceStateCommand) -> bool:
        with self._lock:
            body = self._load()
            commands = body.setdefault("commands", {})
            existing = commands.get(command.asset_id)
            if isinstance(existing, dict) and (
                existing.get("command_id") == command.command_id
                or (
                    existing.get("config_revision") == command.desired.config_revision
                    and existing.get("status") == "applied"
                )
            ):
                return False
            issued_at_ns = command.meta.observed_at.ToNanoseconds()
            if isinstance(existing, dict) and issued_at_ns <= int(
                existing.get("issued_at_ns") or 0
            ):
                return False
            commands[command.asset_id] = {
                "command_id": command.command_id,
                "config_revision": command.desired.config_revision,
                "payload": base64.b64encode(command.SerializeToString()).decode("ascii"),
                "status": "pending",
                "issued_at_ns": issued_at_ns,
                "received_at": datetime.now(timezone.utc).isoformat(),
            }
            _atomic_json(self.path, body)
            return True

    def pending(self) -> list[device_management_pb2.DesiredDeviceStateCommand]:
        body = self._load()
        result: list[device_management_pb2.DesiredDeviceStateCommand] = []
        commands = body.get("commands")
        if not isinstance(commands, dict):
            return result
        for asset_id in sorted(commands):
            row = commands[asset_id]
            if not isinstance(row, dict) or row.get("status") not in {"pending", "retry"}:
                continue
            if float(row.get("next_attempt_at") or 0) > time.time():
                continue
            try:
                result.append(
                    device_management_pb2.DesiredDeviceStateCommand.FromString(
                        base64.b64decode(str(row.get("payload") or ""), validate=True)
                    )
                )
            except (ValueError, DecodeError):
                continue
        return result

    def applied(self) -> list[device_management_pb2.DesiredDeviceStateCommand]:
        body = self._load()
        commands = body.get("commands")
        if not isinstance(commands, dict):
            return []
        result: list[device_management_pb2.DesiredDeviceStateCommand] = []
        for asset_id in sorted(commands):
            row = commands[asset_id]
            if not isinstance(row, dict) or row.get("status") != "applied":
                continue
            try:
                result.append(
                    device_management_pb2.DesiredDeviceStateCommand.FromString(
                        base64.b64decode(str(row.get("payload") or ""), validate=True)
                    )
                )
            except (ValueError, DecodeError):
                continue
        return result

    def mark_done(
        self,
        asset_id: str,
        *,
        command_id: str,
        status: str,
        error: str = "",
    ) -> None:
        with self._lock:
            body = self._load()
            commands = body.get("commands")
            if not isinstance(commands, dict) or not isinstance(commands.get(asset_id), dict):
                return
            if commands[asset_id].get("command_id") != command_id:
                return
            commands[asset_id]["status"] = status
            commands[asset_id]["error"] = error[:2048]
            commands[asset_id]["completed_at"] = datetime.now(timezone.utc).isoformat()
            _atomic_json(self.path, body)

    def mark_retry(
        self,
        asset_id: str,
        command_id: str,
        error: str,
        *,
        delay_sec: int = 30,
    ) -> None:
        with self._lock:
            body = self._load()
            commands = body.get("commands")
            if not isinstance(commands, dict) or not isinstance(commands.get(asset_id), dict):
                return
            row = commands[asset_id]
            if row.get("command_id") != command_id:
                return
            row["status"] = "retry"
            row["error"] = error[:2048]
            row["attempts"] = int(row.get("attempts") or 0) + 1
            row["next_attempt_at"] = time.time() + max(1, delay_sec)
            _atomic_json(self.path, body)


@dataclass(frozen=True)
class ObservedOutboxEntry:
    id: int
    report_id: str
    payload: bytes
    trace_id: str


class ObservedReportOutbox:
    def __init__(self, path: str | Path, *, max_reports: int = 2000) -> None:
        self.path = Path(path)
        self.max_reports = max_reports
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._connection = sqlite3.connect(self.path, check_same_thread=False)
        self._connection.execute("PRAGMA journal_mode=WAL")
        self._connection.execute("PRAGMA synchronous=FULL")
        self._connection.execute(
            """
            CREATE TABLE IF NOT EXISTS edgex_observed_outbox (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                report_id TEXT NOT NULL UNIQUE,
                payload BLOB NOT NULL,
                trace_id TEXT NOT NULL,
                attempts INTEGER NOT NULL DEFAULT 0,
                last_error TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL DEFAULT (datetime('now'))
            )
            """
        )
        self._connection.commit()

    def enqueue(self, report: device_management_pb2.ObservedDeviceStateReport) -> bool:
        if self.depth() >= self.max_reports:
            raise OverflowError(f"observed report outbox is full ({self.max_reports})")
        cursor = self._connection.execute(
            """
            INSERT OR IGNORE INTO edgex_observed_outbox
                (report_id, payload, trace_id)
            VALUES (?, ?, ?)
            """,
            (
                report.report_id,
                sqlite3.Binary(report.SerializeToString()),
                report.meta.trace_id or report.report_id,
            ),
        )
        self._connection.commit()
        return cursor.rowcount > 0

    def pending(self, limit: int = 100) -> list[ObservedOutboxEntry]:
        rows = self._connection.execute(
            """
            SELECT id, report_id, payload, trace_id
            FROM edgex_observed_outbox ORDER BY id ASC LIMIT ?
            """,
            (limit,),
        ).fetchall()
        return [
            ObservedOutboxEntry(
                id=int(row[0]),
                report_id=str(row[1]),
                payload=bytes(row[2]),
                trace_id=str(row[3]),
            )
            for row in rows
        ]

    def acknowledge(self, entry_id: int) -> None:
        self._connection.execute(
            "DELETE FROM edgex_observed_outbox WHERE id = ?", (entry_id,)
        )
        self._connection.commit()

    def record_failure(self, entry_id: int, error: str) -> None:
        self._connection.execute(
            """
            UPDATE edgex_observed_outbox
            SET attempts = attempts + 1, last_error = ? WHERE id = ?
            """,
            (error[:2048], entry_id),
        )
        self._connection.commit()

    def depth(self) -> int:
        return int(
            self._connection.execute(
                "SELECT COUNT(*) FROM edgex_observed_outbox"
            ).fetchone()[0]
        )

    def close(self) -> None:
        self._connection.close()
