"""Load baseline policy for detection rules (with non-fatal validation)."""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

from src.policy.schema import validate_policy

logger = logging.getLogger(__name__)


def load_policy(path: str | Path, validate: bool = True) -> dict[str, Any]:
    policy_path = Path(path)
    if not policy_path.is_file():
        logger.warning("Policy file not found: %s — using empty baseline", policy_path)
        return {"iec61850": {"goose_publishers": [], "mms_ieds": [], "thresholds": {}}}

    try:
        policy = json.loads(policy_path.read_text())
    except json.JSONDecodeError as exc:
        logger.error("Policy file %s is not valid JSON: %s — using empty baseline", policy_path, exc)
        return {"iec61850": {"goose_publishers": [], "mms_ieds": [], "thresholds": {}}}

    if validate:
        warnings = validate_policy(policy)
        for warning in warnings:
            logger.warning("Policy validation: %s", warning)
        if warnings:
            logger.warning("Policy %s loaded with %d warning(s)", policy_path, len(warnings))

    return policy
