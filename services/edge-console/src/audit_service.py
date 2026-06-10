"""Append-only audit log for console security-sensitive actions."""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional


def _audit_path() -> Path:
    return Path(os.environ.get("EDGE_CONSOLE_AUDIT_LOG", "/data/agent/console-audit.jsonl"))


def log_audit(action: str, detail: Optional[dict[str, Any]] = None, *, actor: str = "console") -> None:
    path = _audit_path()
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        entry = {
            "at": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
            "action": action,
            "actor": actor,
            "detail": detail or {},
        }
        with path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(entry, ensure_ascii=False) + "\n")
    except OSError:
        pass


def read_audit_recent(limit: int = 30) -> list[dict[str, Any]]:
    path = _audit_path()
    if not path.is_file():
        return []
    lines = [ln for ln in path.read_text(encoding="utf-8").splitlines() if ln.strip()]
    out: list[dict[str, Any]] = []
    for line in reversed(lines[-500:]):
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError:
            continue
        if len(out) >= limit:
            break
    return out
