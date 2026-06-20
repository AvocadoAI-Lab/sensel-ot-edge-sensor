"""Configurable Suricata EVE record selector + non-alert NDR mapping.

v0.1 of the bridge only forwarded ``event_type == "alert"`` records. For NDR
visibility we want to *optionally* surface ``http/dns/tls/flow`` records too, but
those can be extremely high volume, so the selector must be opt-in and bounded:

- **event-type allowlist** — ``SURICATA_EVE_EVENT_TYPES=alert,http`` (default ``alert``).
- **sampling** — keep 1-in-N per type, e.g. ``SURICATA_EVE_SAMPLE=flow:100``.
- **rate limit** — at most N per 60s window per type, e.g.
  ``SURICATA_EVE_RATE_LIMIT=flow:300,http:600``.
- **allowlist** — only keep non-alert records whose ``app_proto``/``proto`` is in
  ``SURICATA_EVE_PROTO_ALLOWLIST=http,modbus`` (alerts are always high-signal and
  bypass the proto allowlist).

Alerts are never sampled/dropped unless a limit is *explicitly* configured for the
``alert`` type, so the safe default stays "alert-only, never throttled".
"""

from __future__ import annotations

import os
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Callable, Iterable

from src.detection.models import SecurityEvent
from src.detection.external_engine.suricata_source import (
    SuricataEveMapper,
    _coerce_port,
    parse_eve_timestamp,
)

ALERT_RECORD_TYPE = "alert"

# Suricata EVE event_type -> normalized SenseL NDR event_type label.
NON_ALERT_EVENT_TYPE_MAP: dict[str, str] = {
    "http": "NDR_HTTP_OBSERVED",
    "dns": "NDR_DNS_OBSERVED",
    "tls": "NDR_TLS_OBSERVED",
    "flow": "NDR_FLOW_OBSERVED",
}

SUPPORTED_EVENT_TYPES = (ALERT_RECORD_TYPE, *NON_ALERT_EVENT_TYPE_MAP.keys())

# Observational (non-alert) records are low severity by default.
_NON_ALERT_SEVERITY = "info"
_NON_ALERT_RISK = 20


def _parse_csv(value: str | None) -> tuple[str, ...]:
    if not value:
        return ()
    return tuple(part.strip().lower() for part in value.split(",") if part.strip())


def _parse_int_map(value: str | None) -> dict[str, int]:
    """Parse ``type:int,type:int`` into a mapping, ignoring malformed entries."""
    out: dict[str, int] = {}
    for part in _parse_csv(value):
        if ":" not in part:
            continue
        key, _, raw = part.partition(":")
        try:
            num = int(raw)
        except ValueError:
            continue
        if key and num > 0:
            out[key] = num
    return out


@dataclass
class EveSelectorConfig:
    """Bounded selector configuration (PRD EDGE-1.2 / EDGE-1.3)."""

    event_types: tuple[str, ...] = (ALERT_RECORD_TYPE,)
    sample_rates: dict[str, int] = field(default_factory=dict)
    rate_limit_per_min: dict[str, int] = field(default_factory=dict)
    proto_allowlist: tuple[str, ...] = ()

    @classmethod
    def from_env(cls, env: dict[str, str] | None = None) -> "EveSelectorConfig":
        env = env if env is not None else dict(os.environ)
        types = _parse_csv(env.get("SURICATA_EVE_EVENT_TYPES")) or (ALERT_RECORD_TYPE,)
        # Drop unknown types but always keep alert reachable.
        types = tuple(t for t in types if t in SUPPORTED_EVENT_TYPES) or (ALERT_RECORD_TYPE,)
        return cls(
            event_types=types,
            sample_rates=_parse_int_map(env.get("SURICATA_EVE_SAMPLE")),
            rate_limit_per_min=_parse_int_map(env.get("SURICATA_EVE_RATE_LIMIT")),
            proto_allowlist=_parse_csv(env.get("SURICATA_EVE_PROTO_ALLOWLIST")),
        )


class EveSelector:
    """Decides whether a single EVE record should be bridged."""

    def __init__(
        self,
        config: EveSelectorConfig | None = None,
        *,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._cfg = config or EveSelectorConfig()
        self._clock = clock
        self._seen_counts: dict[str, int] = {}
        self._window_start: dict[str, float] = {}
        self._window_count: dict[str, int] = {}

    @property
    def event_types(self) -> tuple[str, ...]:
        return self._cfg.event_types

    def _proto_of(self, record: dict) -> str:
        return str(record.get("app_proto") or record.get("proto") or "").lower()

    def should_emit(self, record: dict) -> bool:
        event_type = str(record.get("event_type") or "").lower()
        if event_type not in self._cfg.event_types:
            return False
        is_alert = event_type == ALERT_RECORD_TYPE

        # Proto allowlist only constrains observational records; alerts bypass it.
        if not is_alert and self._cfg.proto_allowlist:
            if self._proto_of(record) not in self._cfg.proto_allowlist:
                return False

        # Deterministic 1-in-N sampling per type.
        sample_n = self._cfg.sample_rates.get(event_type)
        if sample_n and sample_n > 1:
            count = self._seen_counts.get(event_type, 0)
            self._seen_counts[event_type] = count + 1
            if count % sample_n != 0:
                return False

        # Fixed 60s-window rate limit per type.
        limit = self._cfg.rate_limit_per_min.get(event_type)
        if limit:
            now = self._clock()
            start = self._window_start.get(event_type)
            if start is None or (now - start) >= 60.0:
                self._window_start[event_type] = now
                self._window_count[event_type] = 0
            if self._window_count[event_type] >= limit:
                return False
            self._window_count[event_type] += 1

        return True


class EveRecordMapper:
    """Map any selected EVE record (alert or observational) to a ``SecurityEvent``."""

    def __init__(self, site_id: str, sensor_id: str) -> None:
        self._site_id = site_id
        self._sensor_id = sensor_id
        self._alert_mapper = SuricataEveMapper(site_id, sensor_id)
        self._seq = 0

    def _next_event_id(self, infix: str) -> str:
        self._seq += 1
        day = datetime.now(timezone.utc).strftime("%Y%m%d")
        return f"evt-{day}-suricata-{infix}-{self._seq:05d}"

    def map(self, record: dict) -> SecurityEvent | None:
        event_type = str(record.get("event_type") or "").lower()
        if event_type == ALERT_RECORD_TYPE:
            return self._alert_mapper.map(record)
        label = NON_ALERT_EVENT_TYPE_MAP.get(event_type)
        if label is None:
            return None
        return self._map_non_alert(record, event_type, label)

    def _map_non_alert(self, record: dict, event_type: str, label: str) -> SecurityEvent:
        dest_ip = str(record.get("dest_ip") or "")
        app_proto = str(record.get("app_proto") or "").lower()
        proto = str(record.get("proto") or "ip").lower()
        flow_id = record.get("flow_id")
        return SecurityEvent(
            event_id=self._next_event_id(event_type),
            site_id=self._site_id,
            sensor_id=self._sensor_id,
            event_type=label,
            severity=_NON_ALERT_SEVERITY,
            rule_id=f"suricata-eve-{event_type}",
            protocol=app_proto or proto,
            description=_describe_non_alert(record, event_type),
            src_ip=str(record.get("src_ip") or ""),
            dst_ip=dest_ip,
            dst_port=_coerce_port(record.get("dest_port")),
            risk_score=_NON_ALERT_RISK,
            target_ip=dest_ip,
            raw_ref=f"suricata:eve:flow_id={flow_id}" if flow_id is not None else "",
            evidence={
                "engine": "suricata",
                "eve_event_type": event_type,
                "app_proto": app_proto or None,
                "flow_id": flow_id,
                "src_port": record.get("src_port"),
                "raw_event": record,
            },
            timestamp=parse_eve_timestamp(record.get("timestamp")),
        )


def _describe_non_alert(record: dict, event_type: str) -> str:
    if event_type == "http":
        http = record.get("http") if isinstance(record.get("http"), dict) else {}
        host = http.get("hostname") or http.get("http_host") or ""
        url = http.get("url") or ""
        method = http.get("http_method") or ""
        summary = " ".join(part for part in (method, host, url) if part).strip()
        return f"HTTP {summary}".strip() if summary else "HTTP observed"
    if event_type == "dns":
        dns = record.get("dns") if isinstance(record.get("dns"), dict) else {}
        rrname = dns.get("rrname") or (dns.get("query") or [{}])[0].get("rrname") if isinstance(dns.get("query"), list) else dns.get("rrname")
        return f"DNS {rrname}".strip() if rrname else "DNS observed"
    if event_type == "tls":
        tls = record.get("tls") if isinstance(record.get("tls"), dict) else {}
        sni = tls.get("sni") or tls.get("subject") or ""
        return f"TLS {sni}".strip() if sni else "TLS observed"
    if event_type == "flow":
        proto = str(record.get("proto") or "").upper()
        app = str(record.get("app_proto") or "").lower()
        label = f"{proto}/{app}".strip("/") if (proto or app) else "flow"
        return f"Flow {label}".strip()
    return f"{event_type} observed"


def map_eve_records(
    records: Iterable[dict],
    *,
    mapper: EveRecordMapper,
    selector: EveSelector,
) -> list[SecurityEvent]:
    out: list[SecurityEvent] = []
    for record in records:
        if not selector.should_emit(record):
            continue
        event = mapper.map(record)
        if event is not None:
            out.append(event)
    return out
