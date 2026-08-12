"""Durable Trust Episode tailing, protobuf encoding, and wire publishing."""

from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from src.config.settings import SensorIdentity
from src.contracts.trust_episode_codec import (
    trust_episode_from_mapping,
    trust_episode_to_envelope,
)
from src.northbound.mqtt import NorthboundMqttClient
from src.northbound.wire_mode import WireModeController
from src.upload.episode_spool import TrustEpisodeSpool

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class EpisodeRecord:
    end_offset: int
    episode: dict[str, Any] | None


class TrustEpisodeTailer:
    """Tail complete JSONL records and checkpoint only after durable enqueue."""

    def __init__(self, events_path: str | Path, offset_path: str | Path) -> None:
        self.events_path = Path(events_path)
        self.offset_path = Path(offset_path)
        self.offset_path.parent.mkdir(parents=True, exist_ok=True)
        self.offset = self._load_offset()

    def _load_offset(self) -> int:
        if not self.offset_path.is_file():
            return 0
        try:
            return max(0, int(self.offset_path.read_text(encoding="utf-8").strip() or "0"))
        except (OSError, ValueError):
            return 0

    def records(self, *, limit: int = 100) -> list[EpisodeRecord]:
        if limit <= 0 or not self.events_path.is_file():
            return []
        data = self.events_path.read_bytes()
        if self.offset > len(data):
            # Packet-sensor output was rotated or truncated.
            self.offset = 0
        records: list[EpisodeRecord] = []
        cursor = self.offset
        for line in data[self.offset :].splitlines(keepends=True):
            if not line.endswith((b"\n", b"\r")):
                break
            cursor += len(line)
            try:
                value = json.loads(line.decode("utf-8").strip())
                if not isinstance(value, dict):
                    raise ValueError("Trust Episode line is not an object")
                records.append(EpisodeRecord(end_offset=cursor, episode=value))
            except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
                logger.warning("Skipping malformed Trust Episode line at offset=%s", cursor)
                records.append(EpisodeRecord(end_offset=cursor, episode=None))
            if len(records) >= limit:
                break
        return records

    def acknowledge(self, end_offset: int) -> None:
        if end_offset < self.offset:
            return
        temporary = self.offset_path.with_suffix(f"{self.offset_path.suffix}.tmp")
        temporary.write_text(str(end_offset), encoding="utf-8")
        os.replace(temporary, self.offset_path)
        self.offset = end_offset


def _canonical_message(
    episode: dict[str, Any],
    *,
    tenant_id: str,
    sensor: SensorIdentity,
):
    canonical = dict(episode)
    canonical["tenant_id"] = tenant_id.strip()
    canonical["site_id"] = sensor.site_id.strip()
    canonical["sensor_id"] = sensor.id.strip()
    canonical["producer_version"] = sensor.software_version.strip()
    if not canonical.get("trace_id"):
        canonical["trace_id"] = str(canonical.get("episode_id") or "")
    return trust_episode_from_mapping(canonical)


def enqueue_pending_episodes(
    tailer: TrustEpisodeTailer,
    spool: TrustEpisodeSpool,
    *,
    tenant_id: str,
    sensor: SensorIdentity,
    limit: int = 100,
) -> int:
    """Encode and durably enqueue records before advancing the JSONL offset."""

    enqueued = 0
    for record in tailer.records(limit=limit):
        if record.episode is None:
            tailer.acknowledge(record.end_offset)
            continue
        try:
            message = _canonical_message(
                record.episode,
                tenant_id=tenant_id,
                sensor=sensor,
            )
            inserted = spool.enqueue(
                episode_id=message.episode_id,
                json_envelope=trust_episode_to_envelope(message),
                protobuf_payload=message.SerializeToString(deterministic=True),
                trace_id=message.meta.trace_id,
            )
        except Exception:
            # Do not advance: configuration/schema failures must be recoverable
            # rather than silently dropping a security episode.
            logger.exception("Trust Episode encoding/enqueue failed")
            break
        tailer.acknowledge(record.end_offset)
        if inserted:
            enqueued += 1
    return enqueued


def drain_episode_spool(
    spool: TrustEpisodeSpool,
    mqtt: NorthboundMqttClient,
    wire: WireModeController,
    *,
    limit: int = 100,
) -> int:
    """Publish pending episodes and compact entries satisfied by effective mode."""

    if not mqtt.enabled or not mqtt.connected:
        return 0
    delivered = 0
    for entry in spool.pending(limit=limit):
        channels = wire.channels()
        if "json" in channels and not entry.json_delivered:
            if mqtt.publish_trust_episode_json(entry.json_envelope):
                spool.acknowledge(entry.id, "json")
            else:
                spool.record_failure(entry.id, "JSON MQTT publish failed")

        if "protobuf" in channels and not entry.protobuf_delivered:
            if mqtt.publish_trust_episode_protobuf(
                entry.protobuf_payload,
                trace_id=entry.trace_id,
            ):
                spool.acknowledge(entry.id, "protobuf")
                wire.record_protobuf_success()
            else:
                reason = "protobuf MQTT publish failed"
                spool.record_failure(entry.id, reason)
                if wire.record_protobuf_failure(reason):
                    logger.error(
                        "Protobuf publish rollback activated; effective wire mode is JSON"
                    )

        if spool.remove_if_complete(entry.id, wire.effective_mode):
            delivered += 1
    return delivered
