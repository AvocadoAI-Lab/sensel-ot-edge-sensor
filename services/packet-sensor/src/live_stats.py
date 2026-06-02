"""Write capture live stats for Edge Console (shared assets volume)."""

from __future__ import annotations

import json
import os
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def live_stats_path(assets_dir: str | Path | None = None) -> Path:
    base = Path(assets_dir or os.environ.get("ASSETS_DIR", "/app/data/assets"))
    return base / "capture-live.json"


def write_live_stats(payload: dict[str, Any], assets_dir: str | Path | None = None) -> None:
    path = live_stats_path(assets_dir)
    path.parent.mkdir(parents=True, exist_ok=True)
    body = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".capture-live-", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(body)
        os.replace(tmp, path)
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


class LiveStatsTracker:
    """Compute instant packet rate between writes."""

    def __init__(self) -> None:
        self._prev_total = 0
        self._prev_at = time.monotonic()

    def enrich(self, snap: dict[str, Any]) -> dict[str, Any]:
        now = time.monotonic()
        total = int(snap.get("total_packets") or 0)
        delta = max(total - self._prev_total, 0)
        elapsed = max(now - self._prev_at, 0.001)
        out = dict(snap)
        out["instant_rate"] = round(delta / elapsed, 2)
        out["updated_at"] = datetime.now(timezone.utc).isoformat()
        self._prev_total = total
        self._prev_at = now
        return out
