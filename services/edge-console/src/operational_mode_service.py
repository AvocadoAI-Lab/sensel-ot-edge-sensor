"""Read operational mode artifact shared with edge-agent / packet-sensor."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

VALID_MODES = frozenset({"listen", "learning", "detect", "idle"})


def _mode_path() -> Path:
    return Path(os.environ.get("OPERATIONAL_MODE_PATH", "/data/agent/operational-mode.json"))


def _session_path() -> Path:
    return Path(os.environ.get("LEARNING_SESSION_PATH", "/data/agent/learning-session.json"))


def _read_json(path: Path) -> dict[str, Any]:
    if not path.is_file():
        return {}
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
        return raw if isinstance(raw, dict) else {}
    except (json.JSONDecodeError, OSError):
        return {}


def _session_kind(mode: str) -> str | None:
    if mode == "listen":
        return "observe"
    if mode == "learning":
        return "learn"
    return None


def read_operational_mode() -> dict[str, Any]:
    artifact = _read_json(_mode_path())
    session = _read_json(_session_path())

    mode = str(artifact.get("mode") or "idle").strip().lower()
    if mode not in VALID_MODES:
        mode = "idle" if not artifact else "listen"

    capture = artifact.get("capture") if isinstance(artifact.get("capture"), dict) else {}
    session_id = artifact.get("session_id") or session.get("session_id")
    session_kind = _session_kind(mode) or session.get("session_kind")
    session_status = session.get("status") if session else None
    interrupt_hint = None
    if session_status in ("interrupted", "aborted"):
        interrupt_hint = session.get("interrupt_reason") or session_status

    return {
        "operational_mode": mode,
        "session_id": session_id,
        "session_kind": session_kind,
        "capture_interface": capture.get("interface") or session.get("capture_interface") or "",
        "baseline_profile_id": artifact.get("baseline_profile_id"),
        "baseline_profile_version": artifact.get("baseline_profile_version"),
        "session_status": session_status,
        "cloud_controlled": bool(artifact.get("source") != "edge_default" or artifact.get("tenant_id")),
        "interrupt_hint": interrupt_hint,
        "updated_at": artifact.get("updated_at") or session.get("updated_at"),
    }
