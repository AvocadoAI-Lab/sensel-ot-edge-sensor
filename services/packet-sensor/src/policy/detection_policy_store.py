"""Hot-reload OT detection policy pushed by edge-agent via MQTT."""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from src.policy.loader import load_policy


class DetectionPolicyStore:
    def __init__(
        self,
        *,
        policy_path: str | Path,
        stamp_path: str | Path,
        fallback_policy_path: str | Path,
        reload_check_sec: float = 5.0,
    ) -> None:
        self._policy_path = Path(policy_path)
        self._stamp_path = Path(stamp_path)
        self._fallback_policy_path = Path(fallback_policy_path)
        self.reload_check_sec = reload_check_sec
        self._last_check = 0.0
        self._last_stamp = ""
        self._artifact: dict[str, Any] = {}
        self._rules_enabled: set[str] = set()
        self._baseline: dict[str, Any] = {}
        self._version = ""
        self.maybe_reload(force=True)

    @property
    def version(self) -> str:
        return self._version

    def maybe_reload(self, *, force: bool = False) -> bool:
        now = time.monotonic()
        if not force and (now - self._last_check) < self.reload_check_sec:
            return False
        self._last_check = now

        stamp = ""
        if self._stamp_path.is_file():
            try:
                stamp = self._stamp_path.read_text(encoding="utf-8").strip()
            except OSError:
                stamp = ""
        if not force and stamp == self._last_stamp and self._artifact:
            return False

        artifact: dict[str, Any] = {}
        if self._policy_path.is_file():
            try:
                raw = json.loads(self._policy_path.read_text(encoding="utf-8"))
                if isinstance(raw, dict):
                    artifact = raw
            except (json.JSONDecodeError, OSError):
                artifact = {}

        changed = stamp != self._last_stamp or artifact != self._artifact
        self._last_stamp = stamp
        self._artifact = artifact
        self._version = str(artifact.get("version") or "")

        rules = artifact.get("rules_enabled")
        if isinstance(rules, list):
            self._rules_enabled = {str(r).strip().upper() for r in rules if str(r).strip()}

        baseline = artifact.get("baseline")
        if isinstance(baseline, dict) and baseline:
            self._baseline = baseline
        else:
            self._baseline = load_policy(self._fallback_policy_path)

        return changed

    def rules_enabled(self) -> set[str]:
        self.maybe_reload()
        return set(self._rules_enabled)

    def policy(self) -> dict[str, Any]:
        self.maybe_reload()
        return dict(self._baseline)
