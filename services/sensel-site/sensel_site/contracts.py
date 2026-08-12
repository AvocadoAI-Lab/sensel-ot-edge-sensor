"""Strict protobuf MQTT ingress validation for Site Trust Episodes."""

from __future__ import annotations

import hashlib
import math
import re
from dataclasses import dataclass
from datetime import timezone

from google.protobuf.message import DecodeError
from sensel.episode.v1 import trust_episode_pb2

TRUST_EPISODE_CONTENT_TYPE = "application/x-protobuf; message=sensel.episode.v1.TrustEpisode"
_SEGMENT = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
_SHA256_REF = re.compile(r"^sha256:[0-9a-f]{64}$")


class InvalidSitePublish(ValueError):
    pass


@dataclass(frozen=True)
class EpisodeReceipt:
    tenant_id: str
    site_id: str
    sensor_id: str
    episode_id: str
    asset_id: str
    observed_at: str
    started_at: str
    ended_at: str
    feature_contract_id: str
    sequence_ref: str
    sequence_length: int
    feature_values: tuple[float, ...]
    fusion_decision: str
    fusion_score: float
    fusion_severity: str
    policy_version: str
    trace_id: str
    producer_version: str
    payload_sha256: str
    protobuf_payload: bytes


def parse_episode_topic(topic: str) -> tuple[str, str, str]:
    parts = topic.split("/")
    if len(parts) != 6 or parts[0] != "sensel" or parts[4:] != ["episode", "v1"]:
        raise InvalidSitePublish("unsupported Site MQTT topic")
    tenant_id, site_id, sensor_id = parts[1:4]
    if not all(_SEGMENT.fullmatch(value) for value in (tenant_id, site_id, sensor_id)):
        raise InvalidSitePublish("invalid Site MQTT topic identity")
    return tenant_id, site_id, sensor_id


def decode_episode_publish(
    *,
    topic: str,
    payload: bytes,
    content_type: str,
    payload_format_indicator: int,
    expected_tenant_id: str,
    expected_site_id: str,
    max_payload_bytes: int,
    qos: int = 1,
) -> EpisodeReceipt:
    if qos != 1:
        raise InvalidSitePublish("Trust Episodes require MQTT QoS 1")
    if content_type != TRUST_EPISODE_CONTENT_TYPE:
        raise InvalidSitePublish("unexpected Trust Episode Content Type")
    if payload_format_indicator != 0:
        raise InvalidSitePublish("protobuf MQTT payload format indicator must be 0")
    if not payload or len(payload) > max_payload_bytes:
        raise InvalidSitePublish("Trust Episode payload size is invalid")
    tenant_id, site_id, sensor_id = parse_episode_topic(topic)
    if (tenant_id, site_id) != (expected_tenant_id, expected_site_id):
        raise InvalidSitePublish("MQTT topic is outside this Site scope")

    message = trust_episode_pb2.TrustEpisode()
    try:
        message.ParseFromString(payload)
    except DecodeError as exc:
        raise InvalidSitePublish("invalid Trust Episode protobuf") from exc
    if not message.IsInitialized():
        raise InvalidSitePublish("incomplete Trust Episode protobuf")
    if (message.meta.tenant_id, message.meta.site_id, message.meta.sensor_id) != (
        tenant_id,
        site_id,
        sensor_id,
    ):
        raise InvalidSitePublish("protobuf identity does not match MQTT topic")
    if not message.episode_id or message.meta.event_id != message.episode_id:
        raise InvalidSitePublish("Trust Episode event identity is invalid")
    if len(message.episode_id) > 512 or len(message.asset_id) > 512:
        raise InvalidSitePublish("Trust Episode identity is too long")
    if not message.asset_id or not message.features.feature_contract_id:
        raise InvalidSitePublish("Trust Episode asset/feature contract is required")
    if not _SHA256_REF.fullmatch(message.features.sequence_ref):
        raise InvalidSitePublish("Trust Episode sequence reference must be SHA-256")
    if not message.features.latest_values:
        raise InvalidSitePublish("Trust Episode contains no feature vector")
    if any(not math.isfinite(value) for value in message.features.latest_values):
        raise InvalidSitePublish("Trust Episode feature vector must be finite")
    if message.features.sequence_length <= 0:
        raise InvalidSitePublish("Trust Episode sequence length must be positive")
    if (
        not message.meta.observed_at.ByteSize()
        or not message.started_at.ByteSize()
        or not message.ended_at.ByteSize()
    ):
        raise InvalidSitePublish("Trust Episode time range is required")
    try:
        observed_at = message.meta.observed_at.ToDatetime(tzinfo=timezone.utc)
        started_at = message.started_at.ToDatetime(tzinfo=timezone.utc)
        ended_at = message.ended_at.ToDatetime(tzinfo=timezone.utc)
    except (OverflowError, ValueError) as exc:
        raise InvalidSitePublish("Trust Episode timestamp is invalid") from exc
    if ended_at < started_at:
        raise InvalidSitePublish("Trust Episode time range is inverted")
    if (
        not message.fusion.policy_version
        or not message.fusion.decision
        or not message.fusion.severity
    ):
        raise InvalidSitePublish("Trust Episode deterministic fusion result is required")
    if not math.isfinite(message.fusion.score) or not 0 <= message.fusion.score <= 1:
        raise InvalidSitePublish("Trust Episode fusion score is invalid")
    if not message.meta.producer.version:
        raise InvalidSitePublish("Trust Episode producer version is required")
    if not message.detections:
        raise InvalidSitePublish("Trust Episode requires detection provenance")
    engine_ids = [item.engine_id for item in message.detections]
    if any(not _SEGMENT.fullmatch(engine_id) for engine_id in engine_ids):
        raise InvalidSitePublish("Trust Episode detection engine identity is invalid")
    if len(set(engine_ids)) != len(engine_ids):
        raise InvalidSitePublish("Trust Episode detection engine identities must be unique")
    if any(
        not math.isfinite(item.score)
        or (item.available and not 0 <= item.score <= 1)
        for item in message.detections
    ):
        raise InvalidSitePublish("Trust Episode detection score is invalid")
    available_ids = [item.engine_id for item in message.detections if item.available]
    if list(message.fusion.input_ids) != available_ids:
        raise InvalidSitePublish("Trust Episode fusion inputs do not match detections")

    return EpisodeReceipt(
        tenant_id=tenant_id,
        site_id=site_id,
        sensor_id=sensor_id,
        episode_id=message.episode_id,
        asset_id=message.asset_id,
        observed_at=observed_at.isoformat(),
        started_at=started_at.isoformat(),
        ended_at=ended_at.isoformat(),
        feature_contract_id=message.features.feature_contract_id,
        sequence_ref=message.features.sequence_ref,
        sequence_length=message.features.sequence_length,
        feature_values=tuple(message.features.latest_values),
        fusion_decision=message.fusion.decision,
        fusion_score=message.fusion.score,
        fusion_severity=message.fusion.severity,
        policy_version=message.fusion.policy_version,
        trace_id=message.meta.trace_id,
        producer_version=message.meta.producer.version,
        payload_sha256="sha256:" + hashlib.sha256(payload).hexdigest(),
        protobuf_payload=bytes(payload),
    )
