from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml


ROOT = Path(__file__).resolve().parents[1]
POLICY_PATH = ROOT / "config" / "security_policy.yaml"
AUDIT_PATH = ROOT / "artifacts" / "events" / "audit.jsonl"

PROHIBITED_ACTION_RE = re.compile(
    r"\b(isolate|block|shutdown|firewall[- ]?write|packet injection|active scan|"
    r"credential dump|exploit|rm -rf|sudo|drop table|wipe)\b",
    re.IGNORECASE,
)
INSTRUCTION_INJECTION_RE = re.compile(
    r"(ignore (all )?(previous|prior) instructions|system prompt|you are now|"
    r"reveal (your )?hidden prompt|tool call:|</?script>)",
    re.IGNORECASE,
)


def load_security_policy(path: Path | None = None) -> dict[str, Any]:
    return yaml.safe_load((path or POLICY_PATH).read_text(encoding="utf-8")) or {}


def validate_score_input(payload: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    features = payload.get("features")
    if not isinstance(features, dict) or not features:
        errors.append("features must be a non-empty object")
    else:
        for key, value in features.items():
            if not isinstance(key, str) or not key.strip():
                errors.append("feature names must be non-empty strings")
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                errors.append(f"feature {key!r} must be numeric")
            elif value != value or value in (float("inf"), float("-inf")):
                errors.append(f"feature {key!r} must be finite")
    for field in ("device_id", "device_type", "operating_state"):
        value = payload.get(field)
        if value is not None and (not isinstance(value, str) or not value.strip()):
            errors.append(f"{field} must be a non-empty string when provided")
        if isinstance(value, str) and INSTRUCTION_INJECTION_RE.search(value):
            errors.append(f"{field} contains instruction-like content")
    return errors


def find_prohibited_actions(*texts: str) -> list[str]:
    hits: list[str] = []
    for text in texts:
        if not text:
            continue
        for match in PROHIBITED_ACTION_RE.finditer(str(text)):
            hits.append(match.group(0).lower())
    return sorted(set(hits))


def find_instruction_injection(*texts: str) -> list[str]:
    hits: list[str] = []
    for text in texts:
        if not text:
            continue
        for match in INSTRUCTION_INJECTION_RE.finditer(str(text)):
            hits.append(match.group(0))
    return hits


def sanitize_untrusted_text(text: str) -> str:
    """Treat logs/docs as data: neutralize common imperative wrappers."""
    cleaned = INSTRUCTION_INJECTION_RE.sub("[untrusted-instruction-redacted]", text)
    return cleaned


def enforce_advisory_response(event: dict[str, Any], policy: dict[str, Any] | None = None) -> dict[str, Any]:
    policy = policy or load_security_policy()
    response = dict(event.get("response") or {})
    response["mode"] = "advisory_only"
    response["human_approval_required"] = bool(
        (policy.get("response") or {}).get("human_approval_required", True)
    )
    actions = []
    for action in response.get("recommended_actions") or []:
        if find_prohibited_actions(str(action)):
            continue
        actions.append(action)
    response["recommended_actions"] = actions
    summary = (event.get("assessment") or {}).get("summary", "")
    if find_prohibited_actions(summary):
        assessment = dict(event.get("assessment") or {})
        assessment["summary"] = (
            "Advisory summary replaced after prohibited-action filter; detector evidence unchanged."
        )
        assessment["generation_status"] = "template_fallback"
        event = {**event, "assessment": assessment}
    return {**event, "response": response}


def write_audit_event(kind: str, payload: dict[str, Any], path: Path | None = None) -> None:
    target = path or AUDIT_PATH
    target.parent.mkdir(parents=True, exist_ok=True)
    record = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "kind": kind,
        **payload,
    }
    with target.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(record, ensure_ascii=True) + "\n")
