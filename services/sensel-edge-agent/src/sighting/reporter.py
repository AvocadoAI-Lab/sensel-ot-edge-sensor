"""Report OT-019 CTI observations to SenseL SMB sightings ingest."""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import httpx

from src.config.settings import AppConfig
from src.sighting.queue import QueuedSighting, SightingQueue
from src.upload.events import SecurityEventTailer

logger = logging.getLogger(__name__)

CTI_EVENT_TYPE = "CTI_IOC_OBSERVED"
CTI_RULE_ID = "OT-019"
SNORT_EVENT_TYPE = "SNORT_ALERT"
SURICATA_EVENT_TYPE = "SURICATA_ALERT"
# Map external-engine event types to the engine label used in sighting output.
EXTERNAL_ENGINE_EVENT_TYPES = {
    SNORT_EVENT_TYPE: "snort",
    SURICATA_EVENT_TYPE: "suricata",
}


@dataclass(frozen=True)
class SightingIngestResult:
    ok: bool
    status_code: int
    sighting_id: str | None = None
    matched: bool | None = None
    error: str | None = None


def _as_confidence(value: Any, fallback: int = 80) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return fallback


def build_sighting_ingest_payload(event: dict[str, Any], config: AppConfig) -> dict[str, Any] | None:
    """Map a security event to an SMB sightings ingest body.

    Handles three CTI sources:
    - OT-019 passive IoC matches from the packet-sensor (``CTI_IOC_OBSERVED``).
    - Snort 3 / Suricata alerts whose SID falls in the configured CTI rule range
      (``SNORT_ALERT`` / ``SURICATA_ALERT`` + the matching engine's sighting flag).
    Returns ``None`` for everything else.
    """
    event_type = str(event.get("event_type") or "")
    if event_type == CTI_EVENT_TYPE:
        return _build_ot019_payload(event, config)
    if event_type in EXTERNAL_ENGINE_EVENT_TYPES:
        return _build_external_cti_payload(event, config, EXTERNAL_ENGINE_EVENT_TYPES[event_type])
    return None


def _build_ot019_payload(event: dict[str, Any], config: AppConfig) -> dict[str, Any] | None:
    """Map OT-019 security event to SMB sightings ingest body."""
    if str(event.get("rule_id") or "") != CTI_RULE_ID:
        return None

    evidence = event.get("evidence") if isinstance(event.get("evidence"), dict) else {}
    ioc_type = str(evidence.get("ioc_type") or "ipv4").lower()
    ioc_value = str(evidence.get("ioc_value") or "").strip()
    if not ioc_value:
        return None

    confidence = evidence.get("confidence")
    if confidence is None:
        confidence = event.get("risk_score", 80)
    try:
        confidence_int = int(confidence)
    except (TypeError, ValueError):
        confidence_int = 80

    severity = event.get("risk_score", confidence_int)
    try:
        severity_int = int(severity)
    except (TypeError, ValueError):
        severity_int = confidence_int

    raw_event = {
        "event_id": str(event.get("event_id") or ""),
        "event_type": "cti_ioc_observed",
        "timestamp": event.get("timestamp"),
        "sensor_id": config.sensor.id,
        "site_id": config.sensor.site_id,
        "ioc_type": ioc_type,
        "ioc_value": ioc_value,
        "intel_item_id": evidence.get("intel_item_id"),
        "artifact_version": evidence.get("artifact_version"),
        "direction": evidence.get("direction"),
        "mirror_passive": evidence.get("mirror_passive", True),
        "description": event.get("description") or "SenseL OT Edge passive IoC match on mirror",
        "src_ip": event.get("src_ip"),
        "dst_ip": event.get("dst_ip"),
        "dst_port": event.get("dst_port"),
        "protocol": event.get("protocol"),
        "asset_name": config.sensor.id,
    }

    return {
        "source_system": config.sighting_report.source_system,
        "raw_event": raw_event,
        "defaults": {
            "source_event_type": CTI_EVENT_TYPE,
            "confidence": max(0, min(100, confidence_int)),
            "severity": max(0, min(100, severity_int)),
        },
    }


def _build_external_cti_payload(
    event: dict[str, Any], config: AppConfig, engine: str
) -> dict[str, Any] | None:
    """Map a CTI-origin Snort/Suricata alert to an SMB sightings ingest body.

    Only alerts whose SID falls in the configured CTI range are treated as
    sightings (a generic engine detection is not a CTI hit). The observed
    external IP becomes the IoC value. The CTI SID range is shared across
    engines; each engine has its own enable flag.
    """
    sr = config.sighting_report
    engine_enabled = {
        "snort": sr.snort_sighting_enabled,
        "suricata": sr.suricata_sighting_enabled,
    }.get(engine, False)
    if not engine_enabled or sr.snort_cti_sid_max <= 0:
        return None

    evidence = event.get("evidence") if isinstance(event.get("evidence"), dict) else {}
    try:
        sid = int(evidence.get("sid"))
    except (TypeError, ValueError):
        return None
    if not (sr.snort_cti_sid_min <= sid <= sr.snort_cti_sid_max):
        return None

    dst_ip = str(event.get("dst_ip") or "").strip()
    src_ip = str(event.get("src_ip") or "").strip()
    if dst_ip:
        ioc_value, matched_field = dst_ip, "dst_ip"
    elif src_ip:
        ioc_value, matched_field = src_ip, "src_ip"
    else:
        return None

    confidence_int = _as_confidence(event.get("risk_score"), 80)

    raw_event = {
        "event_id": str(event.get("event_id") or ""),
        "event_type": f"{engine}_cti_observed",
        "timestamp": event.get("timestamp"),
        "sensor_id": config.sensor.id,
        "site_id": config.sensor.site_id,
        "ioc_type": "ipv4",
        "ioc_value": ioc_value,
        "matched_field": matched_field,
        "engine": engine,
        "rule_id": event.get("rule_id"),
        "sid": sid,
        "gid": evidence.get("gid"),
        "classtype": evidence.get("classtype") or evidence.get("category"),
        "description": event.get("description") or f"SenseL NDR Edge {engine} CTI rule hit",
        "src_ip": src_ip or None,
        "dst_ip": dst_ip or None,
        "dst_port": event.get("dst_port"),
        "protocol": event.get("protocol"),
        "asset_name": config.sensor.id,
    }

    return {
        "source_system": config.sighting_report.source_system,
        "raw_event": raw_event,
        "defaults": {
            "source_event_type": f"{engine.upper()}_CTI_OBSERVED",
            "confidence": max(0, min(100, confidence_int)),
            "severity": max(0, min(100, confidence_int)),
        },
    }


class SightingReporter:
    def __init__(self, config: AppConfig) -> None:
        self._config = config
        self._base = config.sensel.api_url.rstrip("/")
        self._ingest_path = config.sighting_report.ingest_path
        self._api_key = (config.sighting_report.smb_intel_api_key or "").strip()
        self._queue = SightingQueue(config.sighting_report.queue_path)
        self._tailer = SecurityEventTailer(
            config.sensel.events.watch_path,
            config.sighting_report.events_offset_path,
        )
        # Extra sources: CTI-origin external-engine alerts (only when enabled).
        self._external_tailers: list[SecurityEventTailer] = []
        if config.sighting_report.snort_sighting_enabled:
            self._external_tailers.append(
                SecurityEventTailer(
                    config.sensel.events.snort_watch_path,
                    config.sighting_report.snort_events_offset_path,
                )
            )
        if config.sighting_report.suricata_sighting_enabled:
            self._external_tailers.append(
                SecurityEventTailer(
                    config.sensel.events.suricata_watch_path,
                    config.sighting_report.suricata_events_offset_path,
                )
            )
        self._last_flush_monotonic = 0.0

    @property
    def enabled(self) -> bool:
        return self._config.sighting_report.enabled and bool(self._api_key)

    def _ingest_url(self) -> str:
        path = self._ingest_path
        if not path.startswith("/"):
            path = f"/{path}"
        return f"{self._base}{path}"

    def _headers(self) -> dict[str, str]:
        return {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "X-API-Key": self._api_key,
        }

    def post_ingest(self, payload: dict[str, Any]) -> SightingIngestResult:
        try:
            with httpx.Client(timeout=20.0, verify=self._config.sensel.verify_tls) as client:
                response = client.post(
                    self._ingest_url(),
                    headers=self._headers(),
                    json=payload,
                )
        except httpx.HTTPError as exc:
            return SightingIngestResult(ok=False, status_code=0, error=str(exc))

        if response.status_code >= 400:
            detail = response.text[:300]
            return SightingIngestResult(
                ok=False,
                status_code=response.status_code,
                error=detail or f"HTTP {response.status_code}",
            )

        sighting_id = None
        matched = None
        try:
            body = response.json()
            sighting = body.get("sighting") if isinstance(body, dict) else None
            if isinstance(sighting, dict):
                sighting_id = str(sighting.get("sighting_id") or "") or None
            correlation = body.get("correlation") if isinstance(body, dict) else None
            if isinstance(correlation, dict):
                matched = correlation.get("matched")
        except ValueError:
            pass

        return SightingIngestResult(
            ok=True,
            status_code=response.status_code,
            sighting_id=sighting_id,
            matched=matched,
        )

    def _backoff_sec(self, attempts: int) -> int:
        base = self._config.sighting_report.backoff_base_sec
        maximum = self._config.sighting_report.backoff_max_sec
        delay = min(maximum, base * (2 ** max(attempts - 1, 0)))
        return int(delay)

    def _schedule_retry(self, item: QueuedSighting, error: str) -> QueuedSighting:
        attempts = item.attempts + 1
        delay = self._backoff_sec(attempts)
        retry_at = datetime.now(timezone.utc).timestamp() + delay
        return QueuedSighting(
            event_id=item.event_id,
            payload=item.payload,
            attempts=attempts,
            queued_at=item.queued_at,
            next_retry_at=datetime.fromtimestamp(retry_at, tz=timezone.utc).isoformat(),
            last_error=error[:500],
        )

    def _retry_due(self, item: QueuedSighting) -> bool:
        text = item.next_retry_at or ""
        try:
            if text.endswith("Z"):
                text = text.replace("Z", "+00:00")
            due = datetime.fromisoformat(text)
            if due.tzinfo is None:
                due = due.replace(tzinfo=timezone.utc)
            return due.timestamp() <= datetime.now(timezone.utc).timestamp()
        except ValueError:
            return True

    def _submit(self, payload: dict[str, Any], *, event_id: str) -> bool:
        result = self.post_ingest(payload)
        if result.ok:
            logger.info(
                "Sighting ingested event=%s sighting_id=%s matched=%s",
                event_id,
                result.sighting_id,
                result.matched,
            )
            self._queue.remove(event_id)
            return True

        logger.warning(
            "Sighting ingest failed event=%s status=%s error=%s",
            event_id,
            result.status_code,
            result.error,
        )
        existing = next((item for item in self._queue.load_all() if item.event_id == event_id), None)
        if existing and existing.attempts >= self._config.sighting_report.max_attempts:
            logger.error(
                "Sighting ingest dropped event=%s after %d attempts",
                event_id,
                existing.attempts,
            )
            self._queue.remove(event_id)
            return False

        item = existing or QueuedSighting(event_id=event_id, payload=payload)
        updated = self._schedule_retry(item, result.error or "unknown error")
        if updated.attempts >= self._config.sighting_report.max_attempts:
            logger.error(
                "Sighting ingest dropped event=%s after %d attempts",
                event_id,
                updated.attempts,
            )
            self._queue.remove(event_id)
            return False
        self._queue.rewrite(
            [
                *(entry for entry in self._queue.load_all() if entry.event_id != event_id),
                updated,
            ]
        )
        return False

    def process_new_events(self) -> int:
        if not self.enabled:
            return 0

        submitted = 0
        tailers = [self._tailer, *self._external_tailers]
        for tailer in tailers:
            for event in tailer.pending_events():
                payload = build_sighting_ingest_payload(event, self._config)
                if payload is None:
                    continue
                event_id = str(event.get("event_id") or payload["raw_event"].get("event_id") or "")
                if not event_id:
                    continue
                if self._submit(payload, event_id=event_id):
                    submitted += 1
        return submitted

    def flush_queue(self) -> int:
        if not self.enabled:
            return 0

        pending = self._queue.load_all()
        if not pending:
            return 0

        flushed = 0
        remaining: list[QueuedSighting] = []
        for item in pending:
            if item.attempts >= self._config.sighting_report.max_attempts:
                logger.error(
                    "Sighting queue dropping event=%s after %d attempts",
                    item.event_id,
                    item.attempts,
                )
                continue
            if not self._retry_due(item):
                remaining.append(item)
                continue

            result = self.post_ingest(item.payload)
            if result.ok:
                logger.info(
                    "Sighting queue flushed event=%s sighting_id=%s matched=%s",
                    item.event_id,
                    result.sighting_id,
                    result.matched,
                )
                flushed += 1
                continue

            updated = self._schedule_retry(item, result.error or "unknown error")
            if updated.attempts >= self._config.sighting_report.max_attempts:
                logger.error(
                    "Sighting queue dropping event=%s after %d attempts",
                    item.event_id,
                    updated.attempts,
                )
                continue
            remaining.append(updated)

        self._queue.rewrite(remaining)
        return flushed

    def run_cycle(self, *, force_flush: bool = False) -> None:
        if not self.enabled:
            return

        self.process_new_events()

        now = time.monotonic()
        interval = self._config.sighting_report.interval_sec
        if force_flush or (now - self._last_flush_monotonic) >= interval:
            self.flush_queue()
            self._last_flush_monotonic = now
