"""Edge Purdue / asset role classifier with IT protocol hints (PRD §5.6)."""

from __future__ import annotations

import hashlib
from typing import Any, Mapping

from src.topology.protocol_hints import DNS_SERVER_MIN_CLIENTS, LDAP_SERVER_MIN_CLIENTS, merge_hints


def _asset_id(tenant_id: str, sensor_id: str, key: str) -> str:
    raw = f"{tenant_id}|{sensor_id}|{key}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def _conduit_id(src: str, dst: str, protocol: str) -> str:
    raw = f"{src}|{dst}|{protocol}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def _is_rfc1918(ip: str) -> bool:
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    try:
        octets = [int(p) for p in parts]
    except ValueError:
        return False
    if octets[0] == 10:
        return True
    if octets[0] == 172 and 16 <= octets[1] <= 31:
        return True
    if octets[0] == 192 and octets[1] == 168:
        return True
    return False


def _external_entity_id(ip: str) -> str:
    return f"ext:{ip}"


def _touch_asset(
    assets: dict[str, dict[str, Any]],
    *,
    tenant_id: str,
    sensor_id: str,
    ip: str,
    asset_type: str = "unknown",
    purdue_level: str | None = None,
    protocols: list[str] | None = None,
    protocol_hints: list[str] | None = None,
    os_family: str | None = None,
    confidence: float = 0.4,
    evidence: list[str] | None = None,
) -> str:
    key = f"ip:{ip}"
    aid = _asset_id(tenant_id, sensor_id, key)
    row = assets.get(aid)
    if row is None:
        row = {
            "schema": "sensel.ot_topology.asset.v1",
            "asset_id": aid,
            "tenant_id": tenant_id,
            "sensor_id": sensor_id,
            "ip": ip,
            "asset_type": asset_type,
            "purdue_level": purdue_level,
            "protocols": protocols or [],
            "protocol_hints": protocol_hints or [],
            "os_family": os_family,
            "confidence": confidence,
            "evidence_sources": evidence or [],
        }
        assets[aid] = row
        return aid

    if purdue_level and (row.get("purdue_level") in (None, "unknown") or confidence > float(row.get("confidence") or 0)):
        row["purdue_level"] = purdue_level
    if asset_type != "unknown":
        row["asset_type"] = asset_type
    row["protocols"] = merge_hints(row.get("protocols"), protocols or [])
    row["protocol_hints"] = merge_hints(row.get("protocol_hints"), protocol_hints or [])
    if os_family:
        row["os_family"] = os_family
    row["confidence"] = max(float(row.get("confidence") or 0), confidence)
    ev = list(row.get("evidence_sources") or [])
    for tag in evidence or []:
        if tag not in ev:
            ev.append(tag)
    row["evidence_sources"] = ev
    return aid


def build_observed_topology(
    observed: Mapping[str, Any],
    *,
    tenant_id: str,
    sensor_id: str,
    port_hints: Mapping[str, Mapping[str, Any]] | None = None,
) -> dict[str, Any]:
    """Build sensel.ot_topology.snapshot.v1 from baseline observed block."""
    assets_by_id: dict[str, dict[str, Any]] = {}
    conduits: list[dict[str, Any]] = []
    external_entities: list[dict[str, Any]] = []
    external_by_ip: dict[str, dict[str, Any]] = {}

    modbus_servers = observed.get("modbus_servers")
    if isinstance(modbus_servers, list):
        for row in modbus_servers:
            if not isinstance(row, Mapping):
                continue
            ip = str(row.get("server_ip") or "").strip()
            if not ip:
                continue
            plc_id = _touch_asset(
                assets_by_id,
                tenant_id=tenant_id,
                sensor_id=sensor_id,
                ip=ip,
                asset_type="plc",
                purdue_level="L1",
                protocols=["modbus-tcp"],
                confidence=0.85,
                evidence=["modbus_role", "baseline_profile"],
            )
            for client in row.get("allowed_clients") or []:
                cip = str(client or "").strip()
                if not cip:
                    continue
                hints = _hints_for_ip(port_hints, cip)
                is_windows_hmi = bool({"smb", "rdp"} & set(hints))
                hmi_id = _touch_asset(
                    assets_by_id,
                    tenant_id=tenant_id,
                    sensor_id=sensor_id,
                    ip=cip,
                    asset_type="hmi" if is_windows_hmi else "hmi",
                    purdue_level="L2",
                    protocols=["modbus-tcp"],
                    protocol_hints=hints,
                    os_family="windows" if is_windows_hmi else None,
                    confidence=0.78 if is_windows_hmi else 0.75,
                    evidence=["modbus_role", "baseline_profile"]
                    + (["it_protocol_fingerprint"] if is_windows_hmi else []),
                )
                conduits.append(
                    {
                        "schema": "sensel.ot_topology.conduit.v1",
                        "conduit_id": _conduit_id(hmi_id, plc_id, "modbus-tcp"),
                        "tenant_id": tenant_id,
                        "sensor_id": sensor_id,
                        "src_asset_id": hmi_id,
                        "dst_ref": {"kind": "asset", "id": plc_id},
                        "src_level": "L2",
                        "dst_level": "L1",
                        "protocol": "modbus-tcp",
                        "baseline_status": "known",
                        "policy_status": "allowed",
                    }
                )

    iec = observed.get("iec61850")
    if isinstance(iec, Mapping):
        mms_ieds = iec.get("mms_ieds")
        if isinstance(mms_ieds, list):
            for row in mms_ieds:
                if not isinstance(row, Mapping):
                    continue
                ip = str(row.get("ied_ip") or "").strip()
                if not ip:
                    continue
                _touch_asset(
                    assets_by_id,
                    tenant_id=tenant_id,
                    sensor_id=sensor_id,
                    ip=ip,
                    asset_type="ied",
                    purdue_level="L1",
                    protocols=["iec61850-mms"],
                    confidence=0.8,
                    evidence=["mms_role", "baseline_profile"],
                )

    if isinstance(port_hints, Mapping):
        for ip, meta in port_hints.items():
            if not isinstance(meta, Mapping):
                continue
            hints = [str(h) for h in (meta.get("hints") or []) if str(h).strip()]
            if not hints:
                continue
            ldap_clients = int(meta.get("ldap_clients") or 0)
            dns_clients = int(meta.get("dns_clients") or 0)
            ldap_client_ips = [str(c) for c in (meta.get("ldap_client_ips") or []) if str(c).strip()]
            dns_client_ips = [str(c) for c in (meta.get("dns_client_ips") or []) if str(c).strip()]
            has_windows = bool({"smb", "rdp", "msrpc", "netbios"} & set(hints))
            server_id: str | None = None
            if ldap_clients >= LDAP_SERVER_MIN_CLIENTS or ("ldap" in hints and meta.get("ldap_server")):
                server_id = _touch_asset(
                    assets_by_id,
                    tenant_id=tenant_id,
                    sensor_id=sensor_id,
                    ip=str(ip),
                    asset_type="ad_server",
                    purdue_level="L4",
                    protocols=["ldap"],
                    protocol_hints=hints,
                    confidence=0.75,
                    evidence=["it_protocol_fingerprint", "ldap_server_role"],
                )
                for cip in ldap_client_ips:
                    client_id = _touch_asset(
                        assets_by_id,
                        tenant_id=tenant_id,
                        sensor_id=sensor_id,
                        ip=cip,
                        asset_type="hmi",
                        purdue_level="L2",
                        protocol_hints=_hints_for_ip(port_hints, cip),
                        confidence=0.7,
                        evidence=["it_protocol_fingerprint"],
                    )
                    conduits.append(
                        {
                            "schema": "sensel.ot_topology.conduit.v1",
                            "conduit_id": _conduit_id(client_id, server_id, "ldap"),
                            "tenant_id": tenant_id,
                            "sensor_id": sensor_id,
                            "src_asset_id": client_id,
                            "dst_ref": {"kind": "asset", "id": server_id},
                            "src_level": "L2",
                            "dst_level": "L4",
                            "protocol": "ldap",
                            "baseline_status": "known",
                            "policy_status": "allowed",
                        }
                    )
            elif dns_clients >= DNS_SERVER_MIN_CLIENTS or ("dns" in hints and meta.get("dns_server")):
                server_id = _touch_asset(
                    assets_by_id,
                    tenant_id=tenant_id,
                    sensor_id=sensor_id,
                    ip=str(ip),
                    asset_type="dns_server",
                    purdue_level="L4",
                    protocols=["dns"],
                    protocol_hints=hints,
                    confidence=0.75,
                    evidence=["it_protocol_fingerprint"],
                )
                for cip in dns_client_ips:
                    client_id = _touch_asset(
                        assets_by_id,
                        tenant_id=tenant_id,
                        sensor_id=sensor_id,
                        ip=cip,
                        asset_type="hmi",
                        purdue_level="L2",
                        protocol_hints=_hints_for_ip(port_hints, cip),
                        confidence=0.7,
                        evidence=["it_protocol_fingerprint"],
                    )
                    conduits.append(
                        {
                            "schema": "sensel.ot_topology.conduit.v1",
                            "conduit_id": _conduit_id(client_id, server_id, "dns"),
                            "tenant_id": tenant_id,
                            "sensor_id": sensor_id,
                            "src_asset_id": client_id,
                            "dst_ref": {"kind": "asset", "id": server_id},
                            "src_level": "L2",
                            "dst_level": "L4",
                            "protocol": "dns",
                            "baseline_status": "known",
                            "policy_status": "allowed",
                        }
                    )
            elif has_windows:
                _touch_asset(
                    assets_by_id,
                    tenant_id=tenant_id,
                    sensor_id=sensor_id,
                    ip=str(ip),
                    asset_type="hmi",
                    purdue_level="L2",
                    protocol_hints=hints,
                    os_family="windows",
                    confidence=0.78,
                    evidence=["it_protocol_fingerprint"],
                )

    comm_pairs = observed.get("comm_pairs")
    if isinstance(comm_pairs, list):
        for pair in comm_pairs:
            if not isinstance(pair, Mapping):
                continue
            src = str(pair.get("src") or "").strip()
            dst = str(pair.get("dst") or "").strip()
            if not src or not dst:
                continue
            src_id = _touch_asset(
                assets_by_id, tenant_id=tenant_id, sensor_id=sensor_id, ip=src, confidence=0.4, evidence=["baseline_profile"]
            )
            if not _is_rfc1918(dst):
                ext = external_by_ip.get(dst)
                if ext is None:
                    ext = {
                        "schema": "sensel.ot_topology.external_entity.v1",
                        "entity_id": _external_entity_id(dst),
                        "tenant_id": tenant_id,
                        "ip": dst,
                        "service_category": "dns" if dst in ("8.8.8.8", "1.1.1.1") else "unknown",
                        "seen_from_assets": [],
                        "confidence": 0.65,
                        "evidence_sources": ["comm_pair", "egress_ip"],
                    }
                    external_by_ip[dst] = ext
                    external_entities.append(ext)
                seen = list(ext.get("seen_from_assets") or [])
                if src_id not in seen:
                    seen.append(src_id)
                ext["seen_from_assets"] = seen
                conduits.append(
                    {
                        "schema": "sensel.ot_topology.conduit.v1",
                        "conduit_id": _conduit_id(src_id, ext["entity_id"], "egress"),
                        "tenant_id": tenant_id,
                        "sensor_id": sensor_id,
                        "src_asset_id": src_id,
                        "dst_ref": {"kind": "external", "id": ext["entity_id"]},
                        "src_level": str(assets_by_id.get(src_id, {}).get("purdue_level") or "L2"),
                        "dst_level": "EXTERNAL",
                        "protocol": "unknown",
                        "baseline_status": "unknown",
                        "policy_status": "review",
                    }
                )
                continue
            dst_id = _touch_asset(
                assets_by_id, tenant_id=tenant_id, sensor_id=sensor_id, ip=dst, confidence=0.4, evidence=["baseline_profile"]
            )
            conduits.append(
                {
                    "schema": "sensel.ot_topology.conduit.v1",
                    "conduit_id": _conduit_id(src_id, dst_id, "unknown"),
                    "tenant_id": tenant_id,
                    "sensor_id": sensor_id,
                    "src_asset_id": src_id,
                    "dst_ref": {"kind": "asset", "id": dst_id},
                    "protocol": "unknown",
                    "baseline_status": "known",
                    "policy_status": "review",
                }
            )

    zone_counts: dict[str, int] = {}
    for asset in assets_by_id.values():
        lvl = str(asset.get("purdue_level") or "unknown")
        zone_counts[lvl] = zone_counts.get(lvl, 0) + 1

    return {
        "schema": "sensel.ot_topology.snapshot.v1",
        "tenant_id": tenant_id,
        "sensor_id": sensor_id,
        "assets": list(assets_by_id.values()),
        "conduits": conduits,
        "external_entities": external_entities,
        "zone_counts": zone_counts,
    }


def _hints_for_ip(port_hints: Mapping[str, Mapping[str, Any]] | None, ip: str) -> list[str]:
    if not port_hints or ip not in port_hints:
        return []
    meta = port_hints.get(ip)
    if not isinstance(meta, Mapping):
        return []
    return [str(h) for h in (meta.get("hints") or []) if str(h).strip()]
