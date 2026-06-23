"""Read Suricata IDS rule sync status written by sensel-edge-agent."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any


def _status_path() -> Path:
    return Path(os.environ.get("IDS_RULE_STATUS_PATH", "/data/agent/ids-rule-status.json"))


def read_ids_rule_status() -> dict[str, Any]:
    path = _status_path()
    if not path.is_file():
        return {"loaded": False, "engines": {}, "path": str(path)}
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {"loaded": False, "engines": {}, "path": str(path), "error": "invalid json"}
    engines = raw.get("engines") if isinstance(raw.get("engines"), dict) else {}
    return {
        "loaded": bool(engines),
        "engines": engines,
        "path": str(path),
        "updated_at": raw.get("updated_at"),
    }
