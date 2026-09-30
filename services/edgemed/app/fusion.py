from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

from .schema import assert_valid_event


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_POLICY_PATH = ROOT / "config" / "severity_policy.yaml"


def load_severity_policy(path: Path | None = None) -> dict[str, Any]:
    return yaml.safe_load((path or DEFAULT_POLICY_PATH).read_text(encoding="utf-8")) or {}


def _severity_rank(policy: dict[str, Any], severity: str) -> int:
    order = policy.get("severity_order", ["low", "medium", "high", "critical"])
    try:
        return order.index(severity)
    except ValueError:
        return 0


def _bump_severity(policy: dict[str, Any], severity: str, steps: int) -> str:
    order = policy.get("severity_order", ["low", "medium", "high", "critical"])
    index = min(len(order) - 1, max(0, _severity_rank(policy, severity) + steps))
    return order[index]


def _known_signal(known_attack: dict[str, Any] | None, policy: dict[str, Any]) -> str:
    if not known_attack:
        return "unavailable"
    probability = float(known_attack.get("probability", 0.0))
    high = float(policy["known_attack"]["high_probability"])
    medium = float(policy["known_attack"]["medium_probability"])
    if probability >= high:
        return "high"
    if probability >= medium:
        return "medium"
    return "low"


def _baseline_signal(baseline: dict[str, Any] | None, policy: dict[str, Any]) -> str:
    if not baseline:
        return "unavailable"
    if baseline.get("compliant", True) and not baseline.get("violations"):
        return "low"
    score = float(baseline.get("score", 0.0))
    baseline_policy = policy.get("baseline") or {}
    high = float(baseline_policy.get("high_score", 0.85))
    medium = float(baseline_policy.get("medium_score", 0.65))
    if score >= high:
        return "high"
    if score >= medium:
        return "medium"
    return "low"


def _anomaly_signal(anomaly: dict[str, Any] | None, policy: dict[str, Any]) -> str:
    if not anomaly:
        return "unavailable"
    score = float(anomaly.get("score", 0.0))
    threshold = anomaly.get("threshold")
    if threshold is not None and score >= float(threshold):
        high = float(policy["anomaly"]["high_score"])
        if score >= high:
            return "high"
        return "medium"
    high = float(policy["anomaly"]["high_score"])
    medium = float(policy["anomaly"]["medium_score"])
    if score >= high:
        return "high"
    if score >= medium:
        return "medium"
    return "low"


def _has_disagreement(
    known_attack: dict[str, Any] | None,
    anomaly: dict[str, Any] | None,
    policy: dict[str, Any],
) -> bool:
    if not known_attack or not anomaly:
        return False
    positive = float(policy["disagreement"]["strong_positive"])
    negative = float(policy["disagreement"]["strong_negative"])
    known_p = float(known_attack.get("probability", 0.0))
    anomaly_s = float(anomaly.get("score", 0.0))
    return (
        (known_p >= positive and anomaly_s <= negative)
        or (anomaly_s >= positive and known_p <= negative)
    )


def _pick_primary_anomaly(
    anomaly: dict[str, Any] | None,
    anomalies: dict[str, dict[str, Any] | None] | None,
) -> dict[str, Any] | None:
    """Prefer explicit anomaly; otherwise choose the highest-scoring available detector."""
    if anomaly is not None and anomaly.get("score") is not None:
        return anomaly
    candidates = [
        item
        for item in (anomalies or {}).values()
        if item and item.get("score") is not None
    ]
    if not candidates:
        return anomaly if anomaly and anomaly.get("score") is not None else None
    return max(candidates, key=lambda item: float(item.get("score", 0.0)))


def _evidence_items(
    *,
    baseline: dict[str, Any] | None,
    known_attack: dict[str, Any] | None,
    anomaly: dict[str, Any] | None,
    anomalies: dict[str, dict[str, Any] | None] | None,
    feature_evidence: list[dict[str, Any]] | None,
) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    index = 1
    for row in feature_evidence or []:
        items.append({
            "evidence_id": f"ev_{index}",
            "feature": row.get("feature", "unknown_feature"),
            "observed": row.get("observed", row.get("importance", row.get("abs_coef"))),
            "baseline": row.get("baseline"),
            "source": row.get("source", "detector:features"),
        })
        index += 1
    if baseline:
        items.append({
            "evidence_id": f"ev_{index}",
            "feature": "baseline_violations",
            "observed": baseline.get("violations") or [],
            "baseline": baseline.get("profile_id"),
            "source": f"detector:{baseline.get('model_version', 'baseline-profile')}",
        })
        index += 1
        if baseline.get("score") is not None:
            items.append({
                "evidence_id": f"ev_{index}",
                "feature": "baseline_score",
                "observed": baseline.get("score"),
                "baseline": 0.0,
                "source": f"detector:{baseline.get('model_version', 'baseline-profile')}",
            })
            index += 1
    if known_attack:
        items.append({
            "evidence_id": f"ev_{index}",
            "feature": "known_attack_probability",
            "observed": known_attack.get("probability"),
            "baseline": None,
            "source": f"detector:{known_attack.get('model_version', 'known-attack')}",
        })
        index += 1
        if known_attack.get("category"):
            items.append({
                "evidence_id": f"ev_{index}",
                "feature": "known_attack_category",
                "observed": known_attack.get("category"),
                "baseline": None,
                "source": f"detector:{known_attack.get('model_version', 'known-attack')}",
            })
            index += 1
    anomaly_rows = []
    if anomalies:
        for name, payload in anomalies.items():
            if payload:
                anomaly_rows.append((name, payload))
    elif anomaly:
        anomaly_rows.append((anomaly.get("detector", "anomaly"), anomaly))
    for name, payload in anomaly_rows:
        if payload.get("score") is None and payload.get("status") == "warming":
            items.append({
                "evidence_id": f"ev_{index}",
                "feature": f"anomaly_status:{name}",
                "observed": f"warming:{payload.get('ticks', 0)}/{payload.get('seq_len', '?')}",
                "baseline": payload.get("threshold"),
                "source": f"detector:{payload.get('model_version', name)}",
            })
        else:
            items.append({
                "evidence_id": f"ev_{index}",
                "feature": f"anomaly_score:{name}",
                "observed": payload.get("score"),
                "baseline": payload.get("threshold"),
                "source": f"detector:{payload.get('model_version', name)}",
            })
        index += 1
    return items


def _taxonomy_for(verdict: str, known_attack: dict[str, Any] | None) -> str:
    if known_attack:
        category = str(known_attack.get("category") or "").strip()
        if category and category.casefold() not in {"benign", "attack", "unknown", ""}:
            return category
        if known_attack.get("task") == "category" and category.casefold() == "benign":
            if verdict == "baseline":
                return "baseline_traffic"
    if verdict in {"anomalous", "suspected_attack", "known_attack_suspected", "policy_violation_suspected"}:
        return "network_behavior_anomaly"
    return "baseline_traffic"


def _available_detector_count(*statuses: str) -> int:
    return sum(status != "unavailable" for status in statuses)


def fuse_detections(
    *,
    device_id: str,
    device_type: str,
    operating_state: str,
    criticality: str = "unknown",
    session_id: str | None = None,
    baseline: dict[str, Any] | None = None,
    known_attack: dict[str, Any] | None = None,
    anomaly: dict[str, Any] | None = None,
    anomalies: dict[str, dict[str, Any] | None] | None = None,
    feature_evidence: list[dict[str, Any]] | None = None,
    policy: dict[str, Any] | None = None,
    persist_reason: str | None = None,
) -> dict[str, Any]:
    """Merge detector outputs into a schema v0.1 security event.

    SLM/RAG components must not rewrite detector-owned fields produced here.
    """
    policy = policy or load_severity_policy()
    anomaly = _pick_primary_anomaly(anomaly, anomalies)
    if _available_detector_count(
        _baseline_signal(baseline, policy),
        _known_signal(known_attack, policy),
        _anomaly_signal(anomaly, policy),
    ) == 0:
        raise ValueError("All detectors unavailable; refusing to invent a verdict")

    baseline_status = _baseline_signal(baseline, policy)
    known_status = _known_signal(known_attack, policy)
    anomaly_status = _anomaly_signal(anomaly, policy)
    available = _available_detector_count(baseline_status, known_status, anomaly_status)
    if available < 3:
        detection_status = "partial_detection"
    else:
        detection_status = "ok"

    disagreement = _has_disagreement(known_attack, anomaly, policy)

    ranks = []
    for status in (baseline_status, known_status, anomaly_status):
        if status != "unavailable":
            ranks.append(_severity_rank(policy, status))
    severity = policy.get("severity_order", ["low", "medium", "high"])[max(ranks) if ranks else 0]
    boost = int(policy.get("criticality_boost", {}).get(criticality, 0))
    severity = _bump_severity(policy, severity, boost)

    positive = {status for status in (baseline_status, known_status, anomaly_status) if status in {"high", "medium"}}
    if len(positive) >= 2:
        verdict = "suspected_attack"
    elif known_status in {"high", "medium"}:
        verdict = "known_attack_suspected"
    elif anomaly_status in {"high", "medium"}:
        verdict = "anomalous"
    elif baseline_status in {"high", "medium"}:
        verdict = "policy_violation_suspected"
    else:
        verdict = "baseline"

    evidence = _evidence_items(
        baseline=baseline,
        known_attack=known_attack,
        anomaly=anomaly,
        anomalies=anomalies,
        feature_evidence=feature_evidence,
    )
    template = policy.get("fallback_summary_template", "{verdict}")
    summary = " ".join(template.format(
        device_type=device_type,
        verdict=verdict,
        policy_id=policy.get("policy_id", "fusion-policy"),
        baseline_status=baseline_status,
        known_status=known_status,
        anomaly_status=anomaly_status,
    ).split())

    event_key = json.dumps(
        {
            "device_id": device_id,
            "baseline": baseline,
            "known_attack": known_attack,
            "anomaly": anomaly,
            "verdict": verdict,
            "severity": severity,
        },
        sort_keys=True,
        default=str,
    ).encode()
    event = {
        "schema_version": "0.1",
        "event_id": "evt_" + hashlib.sha256(event_key).hexdigest()[:16],
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "asset": {
            "device_id": device_id,
            "device_type": device_type,
            "operating_state": operating_state,
            "criticality": criticality or "unknown",
            "session_id": session_id,
        },
        "detection": {
            "status": detection_status,
            "disagreement": disagreement,
            "baseline": baseline,
            "known_attack": known_attack,
            "anomaly": anomaly,
            "anomalies": anomalies or {
                (anomaly or {}).get("detector", "anomaly"): anomaly
            } if anomaly else None,
            "fallback_reason": persist_reason,
        },
        "evidence": evidence,
        "enrichment": {
            "status": "unavailable",
            "retrieval_intents": [],
            "sources": [],
        },
        "assessment": {
            "verdict": verdict,
            "severity": severity,
            "severity_source": policy.get("policy_id", "fusion-policy-0.1"),
            "summary": summary,
            "summary_source": "template_fallback",
            "evidence_ids": [item["evidence_id"] for item in evidence],
            "taxonomy": _taxonomy_for(verdict, known_attack),
            "generation_status": "template_fallback",
        },
        "response": {
            "mode": "advisory_only",
            "human_approval_required": bool(policy.get("human_approval_required", True)),
            "recommended_actions": [
                "verify_device_state",
                "review_evidence_window",
                "preserve_flow_metadata",
            ] if verdict != "baseline" else [],
        },
    }
    return assert_valid_event(event)


def template_fallback_event(
    *,
    device_id: str,
    device_type: str,
    operating_state: str,
    reason: str,
    known_attack: dict[str, Any] | None = None,
    anomaly: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return fuse_detections(
        device_id=device_id,
        device_type=device_type,
        operating_state=operating_state,
        known_attack=known_attack,
        anomaly=anomaly,
        persist_reason=reason,
    )
