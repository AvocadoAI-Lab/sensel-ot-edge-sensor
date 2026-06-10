"""Write the live observed-baseline snapshot to the shared assets volume.

Edge Console reads this to diff *live* observations against the *active*
baseline (drift detection).
"""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from typing import Any


def live_observed_path(assets_dir: str | Path | None = None) -> Path:
    base = Path(assets_dir or os.environ.get("ASSETS_DIR", "/app/data/assets"))
    return base / "baseline" / "live-observed.json"


def write_live_observed(payload: dict[str, Any], assets_dir: str | Path | None = None) -> None:
    path = live_observed_path(assets_dir)
    path.parent.mkdir(parents=True, exist_ok=True)
    body = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), prefix=".live-observed-", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(body)
        os.replace(tmp, str(path))
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
