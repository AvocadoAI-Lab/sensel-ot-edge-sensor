"""Load baseline policy for detection rules."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def load_policy(path: str | Path) -> dict[str, Any]:
    policy_path = Path(path)
    if not policy_path.is_file():
        return {"iec61850": {"goose_publishers": [], "mms_ieds": [], "thresholds": {}}}
    return json.loads(policy_path.read_text())
