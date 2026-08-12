"""Persistent JSON/protobuf rollout state with automatic safe rollback."""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


_VALID_MODES = {"json", "dual", "protobuf"}


def _now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


class WireModeController:
    def __init__(
        self,
        configured_mode: str,
        *,
        failure_threshold: int,
        state_path: str | Path,
        reset_rollback: bool = False,
    ) -> None:
        mode = configured_mode.strip().lower()
        if mode not in _VALID_MODES:
            raise ValueError("wire mode must be json, dual, or protobuf")
        if failure_threshold <= 0:
            raise ValueError("protobuf failure threshold must be positive")
        self.configured_mode = mode
        self.failure_threshold = failure_threshold
        self.state_path = Path(state_path)
        self.effective_mode = mode
        self.consecutive_protobuf_failures = 0
        self.rollback_reason = ""
        self.rolled_back_at = ""
        self._load()
        if reset_rollback:
            self.reset()

    def _load(self) -> None:
        if not self.state_path.is_file():
            return
        try:
            state = json.loads(self.state_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return
        if state.get("configured_mode") != self.configured_mode:
            return
        effective = str(state.get("effective_mode") or self.configured_mode)
        if effective not in _VALID_MODES:
            return
        self.effective_mode = effective
        self.consecutive_protobuf_failures = int(
            state.get("consecutive_protobuf_failures") or 0
        )
        self.rollback_reason = str(state.get("rollback_reason") or "")
        self.rolled_back_at = str(state.get("rolled_back_at") or "")

    def _persist(self) -> None:
        self.state_path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.state_path.with_suffix(f"{self.state_path.suffix}.tmp")
        temporary.write_text(
            json.dumps(self.to_dict(), indent=2, sort_keys=True),
            encoding="utf-8",
        )
        os.chmod(temporary, 0o600)
        os.replace(temporary, self.state_path)

    def channels(self) -> tuple[str, ...]:
        if self.effective_mode == "dual":
            return ("json", "protobuf")
        return (self.effective_mode,)

    def record_protobuf_success(self) -> None:
        if self.effective_mode == "json" and self.rollback_reason:
            return
        if self.consecutive_protobuf_failures:
            self.consecutive_protobuf_failures = 0
            self._persist()

    def record_protobuf_failure(self, reason: str) -> bool:
        if self.effective_mode == "json":
            return False
        self.consecutive_protobuf_failures += 1
        rolled_back = self.consecutive_protobuf_failures >= self.failure_threshold
        if rolled_back:
            self.effective_mode = "json"
            self.rollback_reason = str(reason or "protobuf publish failure")
            self.rolled_back_at = _now()
        self._persist()
        return rolled_back

    def reset(self) -> None:
        self.effective_mode = self.configured_mode
        self.consecutive_protobuf_failures = 0
        self.rollback_reason = ""
        self.rolled_back_at = ""
        self._persist()

    def to_dict(self) -> dict[str, Any]:
        return {
            "configured_mode": self.configured_mode,
            "effective_mode": self.effective_mode,
            "consecutive_protobuf_failures": self.consecutive_protobuf_failures,
            "failure_threshold": self.failure_threshold,
            "rollback_reason": self.rollback_reason,
            "rolled_back_at": self.rolled_back_at,
        }
