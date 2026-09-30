"""Backward-compatible mapping between Edge event dictionaries and protobuf v1."""

from __future__ import annotations

import json
from collections.abc import Mapping
from datetime import datetime, timezone
from typing import Any

from sensel.common.v1 import common_pb2
from sensel.security.v1 import security_event_pb2


_SEVERITY_BY_NAME = {
    "info": security_event_pb2.SECURITY_SEVERITY_INFO,
    "low": security_event_pb2.SECURITY_SEVERITY_LOW,
    "medium": security_event_pb2.SECURITY_SEVERITY_MEDIUM,
    "high": security_event_pb2.SECURITY_SEVERITY_HIGH,
    "critical": security_event_pb2.SECURITY_SEVERITY_CRITICAL,
}


def _parse_timestamp(value: Any) -> datetime:
    if isinstance(value, datetime):
        parsed = value
    else:
        raw = str(value or "").strip()
        if not raw:
            return datetime.now(timezone.utc)
        if raw.endswith("Z"):
            raw = f"{raw[:-1]}+00:00"
        try:
            parsed = datetime.fromisoformat(raw)
        except ValueError as exc:
            raise ValueError(f"invalid security event timestamp: {value!r}") from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _set_evidence_value(attribute: common_pb2.EvidenceAttribute, value: Any) -> None:
    if isinstance(value, bool):
        attribute.bool_value = value
    elif isinstance(value, int):
        attribute.int_value = value
    elif isinstance(value, float):
        attribute.double_value = value
    elif isinstance(value, bytes):
        attribute.bytes_value = value
    elif isinstance(value, str):
        attribute.string_value = value
    elif value is None:
        attribute.json_value = "null"
    else:
        attribute.json_value = json.dumps(
            value,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        )


def _evidence_to_dict(message: security_event_pb2.SecurityEvent) -> dict[str, Any]:
    evidence: dict[str, Any] = {}
    for attribute in message.evidence:
        value_kind = attribute.WhichOneof("value")
        if value_kind is None:
            evidence[attribute.key] = None
        elif value_kind == "json_value":
            evidence[attribute.key] = json.loads(attribute.json_value)
        else:
            evidence[attribute.key] = getattr(attribute, value_kind)
    return evidence


def security_event_from_mapping(
    event: Mapping[str, Any],
    *,
    tenant_id: str,
    site_id: str,
    sensor_id: str,
    producer_version: str,
    trace_id: str = "",
) -> security_event_pb2.SecurityEvent:
    """Build a protobuf event without changing the current JSON publisher."""

    event_id = str(event.get("event_id") or "").strip()
    if not event_id:
        raise ValueError("security event requires event_id")
    event_type = str(event.get("event_type") or "").strip()
    if not event_type:
        raise ValueError("security event requires event_type")
    if not tenant_id.strip() or not site_id.strip() or not sensor_id.strip():
        raise ValueError("security event requires tenant_id, site_id, and sensor_id")

    message = security_event_pb2.SecurityEvent(
        asset_id=str(event.get("asset_id") or ""),
        rule_id=str(event.get("rule_id") or ""),
        event_type=event_type,
        severity=_SEVERITY_BY_NAME.get(
            str(event.get("severity") or "").strip().lower(),
            security_event_pb2.SECURITY_SEVERITY_UNSPECIFIED,
        ),
        protocol=str(event.get("protocol") or ""),
        src_ip=str(event.get("src_ip") or ""),
        dst_ip=str(event.get("dst_ip") or ""),
        description=str(event.get("description") or ""),
        evidence_ref=str(event.get("evidence_ref") or ""),
        feature_contract_id=str(event.get("feature_contract_id") or ""),
    )
    message.meta.event_id = event_id
    message.meta.tenant_id = tenant_id.strip()
    message.meta.site_id = site_id.strip()
    message.meta.sensor_id = sensor_id.strip()
    message.meta.sequence = int(event.get("sequence") or 0)
    message.meta.trace_id = trace_id or str(event.get("mqtt_trace_id") or "")
    message.meta.producer.type = "sensel-ot-edge-sensor"
    message.meta.producer.version = producer_version
    message.meta.observed_at.FromDatetime(_parse_timestamp(event.get("timestamp")))

    if event.get("risk_score") is not None:
        risk_score = float(event["risk_score"])
        if not 0 <= risk_score <= 100:
            raise ValueError("security event risk_score must be between 0 and 100")
        message.risk_score = risk_score
    if event.get("dst_port") is not None:
        dst_port = int(event["dst_port"])
        if not 0 <= dst_port <= 65535:
            raise ValueError("security event dst_port must be between 0 and 65535")
        message.dst_port = dst_port

    raw_evidence = event.get("evidence") or {}
    if not isinstance(raw_evidence, Mapping):
        raise ValueError("security event evidence must be an object")
    for key in sorted(raw_evidence):
        attribute = message.evidence.add(key=str(key))
        _set_evidence_value(attribute, raw_evidence[key])

    for raw_score in event.get("inference_scores") or []:
        if not isinstance(raw_score, Mapping):
            raise ValueError("each inference score must be an object")
        score = message.inference_scores.add(
            model_id=str(raw_score.get("model_id") or ""),
            model_version=str(raw_score.get("model_version") or ""),
            score=float(raw_score.get("score") or 0),
            label=str(raw_score.get("label") or ""),
            feature_contract_id=str(raw_score.get("feature_contract_id") or ""),
        )
        if raw_score.get("calibrated_score") is not None:
            score.calibrated_score = float(raw_score["calibrated_score"])

    raw_fusion = event.get("fusion")
    if raw_fusion is not None:
        if not isinstance(raw_fusion, Mapping):
            raise ValueError("security event fusion must be an object")
        message.fusion.policy_version = str(raw_fusion.get("policy_version") or "")
        message.fusion.score = float(raw_fusion.get("score") or 0)
        message.fusion.decision = str(raw_fusion.get("decision") or "")
        message.fusion.severity = str(raw_fusion.get("severity") or "")
        message.fusion.input_ids.extend(
            str(item) for item in (raw_fusion.get("input_ids") or [])
        )
        if raw_fusion.get("threshold") is not None:
            message.fusion.threshold = float(raw_fusion["threshold"])

    return message


def encode_security_event(event: Mapping[str, Any], **identity: Any) -> bytes:
    """Encode an existing Edge event dictionary as deterministic protobuf bytes."""

    return security_event_from_mapping(event, **identity).SerializeToString(deterministic=True)


def security_event_to_mapping(message: security_event_pb2.SecurityEvent) -> dict[str, Any]:
    """Return the legacy Edge dictionary shape for compatibility and tests."""

    severity_name = security_event_pb2.SecuritySeverity.Name(message.severity)
    event: dict[str, Any] = {
        "event_id": message.meta.event_id,
        "tenant_id": message.meta.tenant_id,
        "site_id": message.meta.site_id,
        "sensor_id": message.meta.sensor_id,
        "event_type": message.event_type,
        "severity": severity_name.removeprefix("SECURITY_SEVERITY_").lower(),
        "rule_id": message.rule_id,
        "protocol": message.protocol,
        "description": message.description,
        "timestamp": message.meta.observed_at.ToDatetime(tzinfo=timezone.utc).isoformat(),
        "asset_id": message.asset_id,
        "src_ip": message.src_ip,
        "dst_ip": message.dst_ip,
        "evidence": _evidence_to_dict(message),
        "evidence_ref": message.evidence_ref,
        "feature_contract_id": message.feature_contract_id,
    }
    if message.HasField("risk_score"):
        event["risk_score"] = message.risk_score
    if message.HasField("dst_port"):
        event["dst_port"] = message.dst_port
    if message.inference_scores:
        event["inference_scores"] = [
            {
                "model_id": score.model_id,
                "model_version": score.model_version,
                "score": score.score,
                "calibrated_score": (
                    score.calibrated_score if score.HasField("calibrated_score") else None
                ),
                "label": score.label,
                "feature_contract_id": score.feature_contract_id,
            }
            for score in message.inference_scores
        ]
    if message.HasField("fusion"):
        event["fusion"] = {
            "policy_version": message.fusion.policy_version,
            "score": message.fusion.score,
            "threshold": (
                message.fusion.threshold if message.fusion.HasField("threshold") else None
            ),
            "decision": message.fusion.decision,
            "severity": message.fusion.severity,
            "input_ids": list(message.fusion.input_ids),
        }
    return event


def decode_security_event(payload: bytes) -> dict[str, Any]:
    """Decode protobuf bytes into the legacy Edge dictionary shape."""

    message = security_event_pb2.SecurityEvent()
    message.ParseFromString(payload)
    return security_event_to_mapping(message)
