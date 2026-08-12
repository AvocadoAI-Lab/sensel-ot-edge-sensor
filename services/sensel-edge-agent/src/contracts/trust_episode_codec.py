"""Mapping between Edge Trust Episode dictionaries and protobuf v1."""

from __future__ import annotations

import json
from collections.abc import Iterable, Mapping
from datetime import datetime, timezone
from typing import Any

from sensel.common.v1 import common_pb2
from sensel.episode.v1 import trust_episode_pb2


def _parse_timestamp(value: Any, field_name: str) -> datetime:
    if isinstance(value, datetime):
        parsed = value
    else:
        raw = str(value or "").strip()
        if not raw:
            raise ValueError(f"Trust Episode requires {field_name}")
        if raw.endswith("Z"):
            raw = f"{raw[:-1]}+00:00"
        try:
            parsed = datetime.fromisoformat(raw)
        except ValueError as exc:
            raise ValueError(f"invalid Trust Episode {field_name}: {value!r}") from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _set_attribute_value(attribute: common_pb2.EvidenceAttribute, value: Any) -> None:
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


def _add_attributes(
    target: Any,
    values: Mapping[str, Any] | None,
) -> None:
    if values is not None and not isinstance(values, Mapping):
        raise ValueError("Trust Episode typed attributes must be an object")
    for key in sorted(values or {}):
        attribute = target.add(key=str(key))
        _set_attribute_value(attribute, values[key])


def _attributes_to_dict(
    attributes: Iterable[common_pb2.EvidenceAttribute],
) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for attribute in attributes:
        value_kind = attribute.WhichOneof("value")
        if value_kind is None:
            result[attribute.key] = None
        elif value_kind == "json_value":
            result[attribute.key] = json.loads(attribute.json_value)
        else:
            result[attribute.key] = getattr(attribute, value_kind)
    return result


def trust_episode_from_mapping(
    episode: Mapping[str, Any],
) -> trust_episode_pb2.TrustEpisode:
    required = (
        "episode_id",
        "asset_id",
        "tenant_id",
        "site_id",
        "sensor_id",
        "producer_version",
    )
    missing = [name for name in required if not str(episode.get(name) or "").strip()]
    if missing:
        raise ValueError(f"Trust Episode requires: {', '.join(missing)}")

    started_at = _parse_timestamp(episode.get("started_at"), "started_at")
    ended_at = _parse_timestamp(episode.get("ended_at"), "ended_at")
    observed_at = _parse_timestamp(episode.get("observed_at"), "observed_at")
    if ended_at < started_at:
        raise ValueError("Trust Episode ended_at must not precede started_at")

    episode_id = str(episode["episode_id"]).strip()
    message = trust_episode_pb2.TrustEpisode(
        episode_id=episode_id,
        asset_id=str(episode["asset_id"]).strip(),
        ai_analysis_ref=str(episode.get("ai_analysis_ref") or ""),
    )
    message.meta.event_id = episode_id
    message.meta.tenant_id = str(episode["tenant_id"]).strip()
    message.meta.site_id = str(episode["site_id"]).strip()
    message.meta.sensor_id = str(episode["sensor_id"]).strip()
    message.meta.observed_at.FromDatetime(observed_at)
    message.meta.sequence = int(episode.get("sequence") or 0)
    message.meta.trace_id = str(episode.get("trace_id") or "")
    message.meta.producer.type = "sensel-ot-edge-sensor"
    message.meta.producer.version = str(episode["producer_version"]).strip()
    message.started_at.FromDatetime(started_at)
    message.ended_at.FromDatetime(ended_at)

    identity = episode.get("asset_identity") or {}
    if not isinstance(identity, Mapping):
        raise ValueError("Trust Episode asset_identity must be an object")
    message.asset_identity.manufacturer = str(identity.get("manufacturer") or "")
    message.asset_identity.product_family = str(identity.get("product_family") or "")
    message.asset_identity.model = str(identity.get("model") or "")
    message.asset_identity.firmware_version = str(identity.get("firmware_version") or "")
    message.asset_identity.serial_number = str(identity.get("serial_number") or "")
    identity_confidence = float(identity.get("confidence") or 0)
    if not 0 <= identity_confidence <= 1:
        raise ValueError("Trust Episode identity confidence must be between 0 and 1")
    message.asset_identity.confidence = identity_confidence
    _add_attributes(message.asset_identity.attributes, identity.get("attributes"))

    features = episode.get("features") or {}
    if not isinstance(features, Mapping):
        raise ValueError("Trust Episode features must be an object")
    feature_contract_id = str(features.get("feature_contract_id") or "").strip()
    if not feature_contract_id:
        raise ValueError("Trust Episode features requires feature_contract_id")
    message.features.feature_contract_id = feature_contract_id
    message.features.sequence_length = int(features.get("sequence_length") or 0)
    message.features.sequence_ref = str(features.get("sequence_ref") or "")
    message.features.latest_values.extend(
        float(item) for item in (features.get("latest_values") or [])
    )

    raw_detections = episode.get("detections") or []
    if not raw_detections:
        raise ValueError("Trust Episode requires at least one detection")
    for raw in raw_detections:
        if not isinstance(raw, Mapping):
            raise ValueError("Trust Episode detections must be objects")
        engine_id = str(raw.get("engine_id") or "").strip()
        if not engine_id:
            raise ValueError("Trust Episode detection requires engine_id")
        available = raw.get("available", True)
        if not isinstance(available, bool):
            raise ValueError("Trust Episode detection available must be boolean")
        score = float(raw.get("score") or 0)
        if available and not 0 <= score <= 1:
            raise ValueError("Trust Episode detection score must be between 0 and 1")
        detection = message.detections.add(
            engine_id=engine_id,
            model_version=str(raw.get("model_version") or ""),
            score=score,
            label=str(raw.get("label") or ""),
            rule_id=str(raw.get("rule_id") or ""),
            feature_contract_id=str(raw.get("feature_contract_id") or ""),
            available=available,
            error=str(raw.get("error") or ""),
        )
        _add_attributes(detection.attributes, raw.get("attributes"))

    fusion = episode.get("fusion") or {}
    if not isinstance(fusion, Mapping):
        raise ValueError("Trust Episode fusion must be an object")
    policy_version = str(fusion.get("policy_version") or "").strip()
    decision = str(fusion.get("decision") or "").strip()
    severity = str(fusion.get("severity") or "").strip()
    if not policy_version or not decision or not severity:
        raise ValueError(
            "Trust Episode fusion requires policy_version, decision, and severity"
        )
    fusion_score = float(fusion.get("score") or 0)
    if not 0 <= fusion_score <= 1:
        raise ValueError("Trust Episode fusion score must be between 0 and 1")
    input_ids = [str(item) for item in fusion.get("input_ids") or []]
    available_ids = [item.engine_id for item in message.detections if item.available]
    if input_ids != available_ids:
        raise ValueError(
            "Trust Episode fusion input_ids must match available detection order"
        )
    message.fusion.policy_version = policy_version
    message.fusion.score = fusion_score
    message.fusion.decision = decision
    message.fusion.severity = severity
    message.fusion.input_ids.extend(input_ids)
    if fusion.get("threshold") is not None:
        threshold = float(fusion["threshold"])
        if not 0 <= threshold <= 1:
            raise ValueError("Trust Episode fusion threshold must be between 0 and 1")
        message.fusion.threshold = threshold

    for raw in episode.get("evidence") or []:
        if not isinstance(raw, Mapping):
            raise ValueError("Trust Episode evidence entries must be objects")
        message.evidence.add(
            uri=str(raw.get("uri") or ""),
            sha256=str(raw.get("sha256") or ""),
            media_type=str(raw.get("media_type") or ""),
            retention_class=str(raw.get("retention_class") or ""),
        )
    supply_chain = episode.get("supply_chain")
    if supply_chain is not None and not isinstance(supply_chain, Mapping):
        raise ValueError("Trust Episode supply_chain must be an object")
    _add_attributes(message.supply_chain, supply_chain)

    policy = episode.get("policy") or {}
    if not isinstance(policy, Mapping):
        raise ValueError("Trust Episode policy must be an object")
    message.policy.policy_id = str(policy.get("policy_id") or "")
    message.policy.policy_version = str(policy.get("policy_version") or "")
    message.policy.operational_mode = str(policy.get("operational_mode") or "")
    _add_attributes(message.policy.attributes, policy.get("attributes"))
    return message


def encode_trust_episode(episode: Mapping[str, Any]) -> bytes:
    return trust_episode_from_mapping(episode).SerializeToString(deterministic=True)


def trust_episode_to_mapping(
    message: trust_episode_pb2.TrustEpisode,
) -> dict[str, Any]:
    return {
        "episode_id": message.episode_id,
        "asset_id": message.asset_id,
        "tenant_id": message.meta.tenant_id,
        "site_id": message.meta.site_id,
        "sensor_id": message.meta.sensor_id,
        "observed_at": message.meta.observed_at.ToDatetime(
            tzinfo=timezone.utc
        ).isoformat(),
        "started_at": message.started_at.ToDatetime(tzinfo=timezone.utc).isoformat(),
        "ended_at": message.ended_at.ToDatetime(tzinfo=timezone.utc).isoformat(),
        "sequence": message.meta.sequence,
        "trace_id": message.meta.trace_id,
        "producer_version": message.meta.producer.version,
        "asset_identity": {
            "manufacturer": message.asset_identity.manufacturer,
            "product_family": message.asset_identity.product_family,
            "model": message.asset_identity.model,
            "firmware_version": message.asset_identity.firmware_version,
            "serial_number": message.asset_identity.serial_number,
            "confidence": message.asset_identity.confidence,
            "attributes": _attributes_to_dict(message.asset_identity.attributes),
        },
        "features": {
            "feature_contract_id": message.features.feature_contract_id,
            "sequence_length": message.features.sequence_length,
            "sequence_ref": message.features.sequence_ref,
            "latest_values": list(message.features.latest_values),
        },
        "detections": [
            {
                "engine_id": detection.engine_id,
                "model_version": detection.model_version,
                "score": detection.score,
                "label": detection.label,
                "rule_id": detection.rule_id,
                "feature_contract_id": detection.feature_contract_id,
                "available": detection.available,
                "error": detection.error,
                "attributes": _attributes_to_dict(detection.attributes),
            }
            for detection in message.detections
        ],
        "fusion": {
            "policy_version": message.fusion.policy_version,
            "score": message.fusion.score,
            "threshold": (
                message.fusion.threshold if message.fusion.HasField("threshold") else None
            ),
            "decision": message.fusion.decision,
            "severity": message.fusion.severity,
            "input_ids": list(message.fusion.input_ids),
        },
        "evidence": [
            {
                "uri": item.uri,
                "sha256": item.sha256,
                "media_type": item.media_type,
                "retention_class": item.retention_class,
            }
            for item in message.evidence
        ],
        "supply_chain": _attributes_to_dict(message.supply_chain),
        "policy": {
            "policy_id": message.policy.policy_id,
            "policy_version": message.policy.policy_version,
            "operational_mode": message.policy.operational_mode,
            "attributes": _attributes_to_dict(message.policy.attributes),
        },
        "ai_analysis_ref": message.ai_analysis_ref,
    }


def decode_trust_episode(payload: bytes) -> dict[str, Any]:
    message = trust_episode_pb2.TrustEpisode()
    message.ParseFromString(payload)
    return trust_episode_to_mapping(message)


def trust_episode_to_envelope(
    message: trust_episode_pb2.TrustEpisode,
) -> dict[str, Any]:
    """Return the canonical JSON twin used for dual-publish parity checks."""

    episode = trust_episode_to_mapping(message)
    payload = {
        key: value
        for key, value in episode.items()
        if key
        not in {
            "tenant_id",
            "site_id",
            "sensor_id",
            "observed_at",
            "sequence",
            "trace_id",
            "producer_version",
        }
    }
    return {
        "schema_version": "sensel.episode.v1",
        "message_type": "trust_episode",
        "event_id": message.episode_id,
        "tenant_id": message.meta.tenant_id,
        "site_id": message.meta.site_id,
        "sensor_id": message.meta.sensor_id,
        "observed_at": episode["observed_at"],
        "sequence": message.meta.sequence,
        "trace_id": message.meta.trace_id,
        "producer": {
            "type": message.meta.producer.type,
            "version": message.meta.producer.version,
        },
        "severity": message.fusion.severity,
        "dedup_key": f"{message.meta.tenant_id}:{message.episode_id}",
        "payload": payload,
    }
