"""Hot-reload baseline profile artifact pushed by edge-agent via MQTT."""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any


def observed_to_detection_baseline(observed: dict[str, Any]) -> dict[str, Any]:
    """Map sensel.baseline/1 observed block to detector policy baseline shape."""
    if not isinstance(observed, dict) or not observed:
        return {}
    iec = observed.get("iec61850") if isinstance(observed.get("iec61850"), dict) else {}
    thresholds = observed.get("thresholds") if isinstance(observed.get("thresholds"), dict) else {}
    baseline: dict[str, Any] = {
        "policy_version": "baseline-profile",
        "iec61850": {
            "goose_publishers": list(iec.get("goose_publishers") or []),
            "mms_ieds": list(iec.get("mms_ieds") or []),
            "thresholds": dict(iec.get("thresholds") or {}),
        },
    }
    if thresholds:
        baseline["thresholds"] = dict(thresholds)
    modbus = observed.get("modbus_servers")
    if isinstance(modbus, list) and modbus:
        baseline["modbus_servers"] = modbus
    return baseline


class BaselineProfileStore:
    def __init__(
        self,
        *,
        profile_path: str | Path,
        stamp_path: str | Path,
        reload_check_sec: float = 5.0,
    ) -> None:
        self._profile_path = Path(profile_path)
        self._stamp_path = Path(stamp_path)
        self.reload_check_sec = reload_check_sec
        self._last_check = 0.0
        self._last_stamp = ""
        self._artifact: dict[str, Any] = {}
        self._baseline: dict[str, Any] = {}
        self._profile_id = ""
        self._version = ""
        self.maybe_reload(force=True)

    @property
    def profile_id(self) -> str:
        return self._profile_id

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
        if self._profile_path.is_file():
            try:
                raw = json.loads(self._profile_path.read_text(encoding="utf-8"))
                if isinstance(raw, dict):
                    artifact = raw
            except (json.JSONDecodeError, OSError):
                artifact = {}

        changed = stamp != self._last_stamp or artifact != self._artifact
        self._last_stamp = stamp
        self._artifact = artifact
        self._profile_id = str(artifact.get("profile_id") or "")
        self._version = str(artifact.get("version") or "")
        observed = artifact.get("observed") if isinstance(artifact.get("observed"), dict) else {}
        self._baseline = observed_to_detection_baseline(observed) if observed else {}
        return changed

    def baseline(self) -> dict[str, Any]:
        self.maybe_reload()
        return dict(self._baseline)
