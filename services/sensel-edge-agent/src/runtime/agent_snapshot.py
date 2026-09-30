"""Persist lightweight runtime state for Edge Console."""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def _runtime_path() -> Path:
    return Path(os.environ.get("AGENT_RUNTIME_PATH", "/app/data/agent-runtime.json"))


def _now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def write_agent_runtime(**fields: Any) -> None:
    path = _runtime_path()
    body: dict[str, Any] = {}
    if path.is_file():
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(raw, dict):
                body = raw
        except (OSError, json.JSONDecodeError):
            body = {}

    for key, value in fields.items():
        if value is not None:
            body[key] = value
    body["updated_at"] = _now_iso()

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(body, indent=2), encoding="utf-8")
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
