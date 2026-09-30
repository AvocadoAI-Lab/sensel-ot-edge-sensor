"""Attach operational/baseline/policy context to security events before northbound publish."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def _read_json(path: Path) -> dict[str, Any]:
    if not path.is_file():
        return {}
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
        return raw if isinstance(raw, dict) else {}
    except (json.JSONDecodeError, OSError):
        return {}


def enrich_security_event(
    event: dict[str, Any],
    *,
    operational_mode_path: str | Path,
    detection_policy_path: str | Path,
    baseline_profile_path: str | Path,
) -> dict[str, Any]:
    """Merge FR-8 context fields into the event payload."""
    out = dict(event)
    op = _read_json(Path(operational_mode_path))
    policy = _read_json(Path(detection_policy_path))
    profile = _read_json(Path(baseline_profile_path))

    mode = str(op.get("mode") or "listen")
    baseline_profile_id = op.get("baseline_profile_id") or profile.get("profile_id")
    baseline_profile_version = op.get("baseline_profile_version") or profile.get("version")
    detection_policy_version = str(policy.get("version") or "")

    ctx = out.get("context") if isinstance(out.get("context"), dict) else {}
    merged_ctx = {
        **ctx,
        "operational_mode": mode,
        "baseline_profile_id": baseline_profile_id,
        "baseline_profile_version": baseline_profile_version,
        "detection_policy_version": detection_policy_version or None,
    }
    out["context"] = {k: v for k, v in merged_ctx.items() if v is not None}
    if baseline_profile_id:
        out["baseline_profile_id"] = baseline_profile_id
    if baseline_profile_version:
        out["baseline_profile_version"] = baseline_profile_version
    if detection_policy_version:
        out["detection_policy_version"] = detection_policy_version
    out["operational_mode"] = mode
    return out
