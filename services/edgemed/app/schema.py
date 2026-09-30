from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = ROOT / "app" / "schemas" / "security_event_v0_1.json"

DETECTOR_OWNED_PATHS = (
    ("detection", "baseline"),
    ("detection", "known_attack"),
    ("detection", "anomaly"),
    ("detection", "anomalies"),
    ("detection", "status"),
    ("detection", "disagreement"),
    ("evidence",),
)


def load_event_schema() -> dict[str, Any]:
    return json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))


def validate_security_event(event: dict[str, Any]) -> list[str]:
    """Lightweight structural validator (no external jsonschema dependency)."""
    errors: list[str] = []
    schema = load_event_schema()
    for key in schema.get("required", []):
        if key not in event:
            errors.append(f"missing required field: {key}")

    if event.get("schema_version") != "0.1":
        errors.append("schema_version must be '0.1'")

    asset = event.get("asset")
    if not isinstance(asset, dict):
        errors.append("asset must be an object")
    else:
        for key in ("device_id", "device_type", "operating_state"):
            if key not in asset:
                errors.append(f"asset missing {key}")

    detection = event.get("detection")
    if not isinstance(detection, dict):
        errors.append("detection must be an object")
    else:
        status = detection.get("status")
        if status not in {"ok", "partial_detection", "unavailable"}:
            errors.append("detection.status invalid")

    assessment = event.get("assessment")
    if not isinstance(assessment, dict):
        errors.append("assessment must be an object")
    else:
        for key in ("verdict", "severity", "severity_source", "summary", "generation_status"):
            if key not in assessment:
                errors.append(f"assessment missing {key}")
        if assessment.get("generation_status") not in {
            "generated",
            "template_fallback",
            "enrichment_unavailable",
        }:
            errors.append("assessment.generation_status invalid")

    response = event.get("response")
    if not isinstance(response, dict):
        errors.append("response must be an object")
    else:
        if response.get("mode") != "advisory_only":
            errors.append("response.mode must be advisory_only")
        if "human_approval_required" not in response:
            errors.append("response.human_approval_required missing")

    if not isinstance(event.get("evidence"), list):
        errors.append("evidence must be a list")

    return errors


def assert_valid_event(event: dict[str, Any]) -> dict[str, Any]:
    errors = validate_security_event(event)
    if errors:
        raise ValueError("; ".join(errors))
    return event


def detector_owned_snapshot(event: dict[str, Any]) -> dict[str, Any]:
    return {
        "detection": copy.deepcopy(event.get("detection")),
        "evidence": copy.deepcopy(event.get("evidence")),
    }


def assert_detector_fields_unchanged(before: dict[str, Any], after: dict[str, Any]) -> None:
    left = detector_owned_snapshot(before)
    right = detector_owned_snapshot(after)
    if left != right:
        raise ValueError("Detector-owned fields were mutated by a non-detector component")
