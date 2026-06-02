"""CTI IoC matching on mirror traffic (OT-019)."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from datetime import datetime, timezone

from src.detection.models import SecurityEvent, utc_now_iso
from src.policy.ioc_cache import IocCacheStore, IocEntry


RULE_ID = "OT-019"
EVENT_TYPE = "CTI_IOC_OBSERVED"
SEVERITY = "high"
DESCRIPTION = "CTI blacklist IPv4 observed on mirror (passive)"


@dataclass
class IocMatcher:
    site_id: str
    sensor_id: str
    cache: IocCacheStore
    policy: dict
    rules_enabled: set[str] = field(default_factory=set)
    cooldown_sec: int = 300
    _event_seq: int = 0
    _last_alert: dict[str, float] = field(default_factory=dict)

    def _enabled(self) -> bool:
        return not self.rules_enabled or RULE_ID in self.rules_enabled

    def _next_event_id(self) -> str:
        self._event_seq += 1
        day = datetime.now(timezone.utc).strftime("%Y%m%d")
        return f"evt-{day}-ioc-{self._event_seq:05d}"

    def _global_allowlist_ips(self) -> set[str]:
        values = self.policy.get("global_allowlists", {}).get("ip", [])
        return {str(v) for v in values}

    def _cooldown_key(self, ioc_value: str, direction: str) -> str:
        return f"{ioc_value}:{direction}"

    def _cooldown_active(self, key: str) -> bool:
        last = self._last_alert.get(key)
        if last is None:
            return False
        return (time.monotonic() - last) < self.cooldown_sec

    def _mark_alert(self, key: str) -> None:
        self._last_alert[key] = time.monotonic()

    def _build_event(
        self,
        *,
        matched_ip: str,
        direction: str,
        entry: IocEntry,
        src_ip: str,
        dst_ip: str,
        dst_port: int | None,
        protocol: str | None,
    ) -> SecurityEvent:
        confidence = entry.confidence if entry.confidence is not None else 80
        return SecurityEvent(
            event_id=self._next_event_id(),
            site_id=self.site_id,
            sensor_id=self.sensor_id,
            event_type=EVENT_TYPE,
            severity=SEVERITY,
            rule_id=RULE_ID,
            protocol=protocol or "ip",
            description=DESCRIPTION,
            src_ip=src_ip or "",
            dst_ip=dst_ip or "",
            dst_port=dst_port,
            risk_score=min(95, max(70, int(confidence))),
            evidence={
                "ioc_type": "ipv4",
                "ioc_value": matched_ip,
                "intel_item_id": entry.item_id,
                "artifact_version": self.cache.artifact_version,
                "intel_tenant_id": self.cache.tenant_id,
                "direction": direction,
                "mirror_passive": True,
            },
            timestamp=utc_now_iso(),
        )

    def evaluate(
        self,
        *,
        src_ip: str | None,
        dst_ip: str | None,
        dst_port: int | None = None,
        protocol: str | None = None,
    ) -> list[SecurityEvent]:
        if not self._enabled():
            return []

        allowlist = self._global_allowlist_ips()
        events: list[SecurityEvent] = []

        for direction, ip in (("src", src_ip), ("dst", dst_ip)):
            if not ip or ip in allowlist:
                continue
            entry = self.cache.lookup_ipv4(ip)
            if entry is None:
                continue
            key = self._cooldown_key(ip, direction)
            if self._cooldown_active(key):
                continue
            self._mark_alert(key)
            events.append(
                self._build_event(
                    matched_ip=ip,
                    direction=direction,
                    entry=entry,
                    src_ip=src_ip or "",
                    dst_ip=dst_ip or "",
                    dst_port=dst_port,
                    protocol=protocol,
                )
            )
        return events
