"""Map engine ``SecurityEvent`` dicts to the normalized northbound NDR contract.

The packet-sensor and external-engine bridges emit engine-shaped events
(``src_ip``/``dst_ip``/``timestamp``...). The platform (guacamole-ai) and the
correlation plane consume the *normalized* NDR contract (PRD section 6.1):
``source_ip``/``destination_ip``/``target_ip``/``observed_at`` with an explicit
``engine`` and canonical ``protocol`` family. This module is the single mapping
point so every northbound consumer reads one shape.
"""

from __future__ import annotations

from typing import Any

NDR_SCHEMA_VERSION = "ndr_event.normalized.v1"

# Engine ``event_type`` -> NDR engine label.
_EVENT_TYPE_ENGINE = {
    "SURICATA_ALERT": "suricata",
    "NDR_HTTP_OBSERVED": "suricata",
    "NDR_DNS_OBSERVED": "suricata",
    "NDR_TLS_OBSERVED": "suricata",
    "NDR_FLOW_OBSERVED": "suricata",
    "SNORT_ALERT": "snort",
    "WAZUH_ALERT": "wazuh",
}

# Canonical protocol family normalization for ``same_protocol`` correlation.
_PROTOCOL_FAMILY = {
    "modbus": "modbus-tcp",
    "modbus-tcp": "modbus-tcp",
    "modbustcp": "modbus-tcp",
    "mms": "iec61850-mms",
    "iec61850": "iec61850",
    "goose": "iec61850-goose",
    "opcua": "opcua",
    "opc-ua": "opcua",
    "http": "http",
    "http2": "http",
    "https": "http",
    "dns": "dns",
    "tls": "tls",
    "ssl": "tls",
    "tcp": "tcp",
    "udp": "udp",
    "icmp": "icmp",
    "edgex": "edgex",
    "mqtt": "mqtt",
}


def canonical_protocol(*candidates: Any) -> str | None:
    """Return the canonical protocol family from the first usable candidate."""
    for candidate in candidates:
        if not candidate:
            continue
        key = str(candidate).strip().lower()
        if not key:
            continue
        return _PROTOCOL_FAMILY.get(key, key)
    return None


def derive_engine(event_type: str, evidence: dict[str, Any] | None = None) -> str:
    engine = (evidence or {}).get("engine")
    if engine:
        return str(engine).lower()
    return _EVENT_TYPE_ENGINE.get(str(event_type), "suricata")


def normalize_ndr_event(
    engine_event: dict[str, Any],
    *,
    tenant_id: str,
    workspace_id: str,
    engine: str | None = None,
) -> dict[str, Any]:
    """Convert an engine ``SecurityEvent`` dict into the normalized NDR contract.

    ``tenant_id``/``workspace_id`` are supplied at the ingest boundary (the edge
    learns ``tenant_id`` at registration; the platform resolves ``workspace_id``).
    """
    evidence = engine_event.get("evidence") if isinstance(engine_event.get("evidence"), dict) else {}
    event_type = str(engine_event.get("event_type") or "")
    resolved_engine = engine or derive_engine(event_type, evidence)
    sensor_id = str(engine_event.get("sensor_id") or "")
    source_event_id = str(engine_event.get("event_id") or "")

    dst_ip = str(engine_event.get("dst_ip") or "") or None
    target_ip = str(engine_event.get("target_ip") or "") or dst_ip or ""

    src_port = evidence.get("src_port")
    try:
        src_port = int(src_port) if src_port not in (None, "") else None
    except (TypeError, ValueError):
        src_port = None

    normalized: dict[str, Any] = {
        "schema_version": NDR_SCHEMA_VERSION,
        # Globally unique: sensor + engine + engine-local event id (PRD 6.1).
        "event_id": f"{sensor_id}:{resolved_engine}:{source_event_id}",
        "tenant_id": tenant_id,
        "workspace_id": workspace_id,
        "site_id": str(engine_event.get("site_id") or ""),
        "sensor_id": sensor_id,
        "engine": resolved_engine,
        "event_type": event_type,
        "rule_id": engine_event.get("rule_id") or None,
        "severity": str(engine_event.get("severity") or "medium"),
        "risk_score": engine_event.get("risk_score", 0),
        "source_ip": str(engine_event.get("src_ip") or "") or None,
        "source_port": src_port,
        "destination_ip": dst_ip,
        "destination_port": engine_event.get("dst_port"),
        "target_ip": target_ip,
        "protocol": canonical_protocol(evidence.get("app_proto"), engine_event.get("protocol")),
        "observed_at": str(engine_event.get("timestamp") or ""),
        "raw_ref": engine_event.get("raw_ref") or None,
        "evidence": evidence,
    }
    return normalized
