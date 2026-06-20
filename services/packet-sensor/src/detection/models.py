"""Shared security event model for MVP and IEC 61850 detectors."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


@dataclass
class SecurityEvent:
    event_id: str
    site_id: str
    sensor_id: str
    event_type: str
    severity: str
    rule_id: str
    protocol: str
    description: str
    asset_id: str = ""
    src_ip: str = ""
    dst_ip: str = ""
    dst_port: int | None = None
    risk_score: int = 70
    evidence: dict = field(default_factory=dict)
    evidence_ref: str = ""
    # NDR/OT normalized correlation fields (PRD EDGE-1.4). ``target_ip`` is the
    # correlation-normalized target (usually the destination / protected OT
    # asset); ``raw_ref`` points at the source record (PCAP / EVE offset / index).
    target_ip: str = ""
    raw_ref: str = ""
    timestamp: str = field(default_factory=utc_now_iso)

    def to_dict(self) -> dict:
        payload = {
            "event_id": self.event_id,
            "site_id": self.site_id,
            "sensor_id": self.sensor_id,
            "event_type": self.event_type,
            "severity": self.severity,
            "rule_id": self.rule_id,
            "protocol": self.protocol,
            "description": self.description,
            "timestamp": self.timestamp,
            "risk_score": self.risk_score,
            "evidence": self.evidence,
        }
        if self.asset_id:
            payload["asset_id"] = self.asset_id
        if self.src_ip:
            payload["src_ip"] = self.src_ip
        if self.dst_ip:
            payload["dst_ip"] = self.dst_ip
        if self.dst_port is not None:
            payload["dst_port"] = self.dst_port
        if self.evidence_ref:
            payload["evidence_ref"] = self.evidence_ref
        if self.target_ip:
            payload["target_ip"] = self.target_ip
        if self.raw_ref:
            payload["raw_ref"] = self.raw_ref
        return payload
