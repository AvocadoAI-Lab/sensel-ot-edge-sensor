"""Merge EdgeX managed devices with mirror passive asset discovery."""

from __future__ import annotations

import re
from typing import Any

from src.config_store import ConfigStore
from src.edgex_service import list_devices
from src.traffic_service import read_live_traffic


def _host_from_endpoint(endpoint: str) -> str:
    ep = (endpoint or "").strip()
    if not ep or ep == "—":
        return ""
    if "://" in ep:
        m = re.match(r"^[^:]+://([^:/]+)", ep)
        return m.group(1) if m else ""
    if ":" in ep:
        return ep.rsplit(":", 1)[0]
    return ep


def build_ip_device_map(devices: list[dict[str, Any]]) -> dict[str, str]:
    mapping: dict[str, str] = {}
    for d in devices:
        name = d.get("name") or ""
        if not name:
            continue
        host = _host_from_endpoint(str(d.get("endpoint") or ""))
        if host:
            mapping[host] = name
    return mapping


def enrich_event(event: dict[str, Any], ip_map: dict[str, str]) -> dict[str, Any]:
    out = dict(event)
    src = str(out.get("src_ip") or "").strip()
    dst = str(out.get("dst_ip") or "").strip()
    matched = ip_map.get(src) or ip_map.get(dst) or ""
    out["matched_device"] = matched
    if matched:
        out["asset_label"] = matched
        out["asset_source"] = "edgex"
    elif src:
        out["asset_label"] = src
        out["asset_source"] = "mirror"
    elif out.get("asset_id"):
        out["asset_label"] = str(out.get("asset_id"))
        out["asset_source"] = "event"
    else:
        out["asset_label"] = "—"
        out["asset_source"] = "unknown"
    return out


def enrich_events(events: list[dict[str, Any]], ip_map: dict[str, str]) -> list[dict[str, Any]]:
    return [enrich_event(e, ip_map) for e in events]


def build_discovery(store: ConfigStore) -> dict[str, Any]:
    device_payload = list_devices(enrich_telemetry=False)
    devices = device_payload.get("devices") or []
    ip_map = build_ip_device_map(devices)

    traffic = read_live_traffic(store)
    top_ips = traffic.get("top_ips") or []
    seen_ips: set[str] = set()

    assets: list[dict[str, Any]] = []
    for row in top_ips:
        ip = str(row.get("ip") or "").strip()
        if not ip or ip in seen_ips:
            continue
        seen_ips.add(ip)
        managed = ip in ip_map
        assets.append(
            {
                "ip": ip,
                "packets": row.get("count", 0),
                "edgex_device": ip_map.get(ip),
                "source": "edgex" if managed else "mirror_only",
                "label": ip_map.get(ip) or ip,
            }
        )

    for d in devices:
        host = _host_from_endpoint(str(d.get("endpoint") or ""))
        if host and host not in seen_ips:
            seen_ips.add(host)
            assets.append(
                {
                    "ip": host,
                    "packets": None,
                    "edgex_device": d.get("name"),
                    "source": "edgex",
                    "label": d.get("name"),
                    "protocol": d.get("protocol"),
                    "operating_state": d.get("operatingState"),
                }
            )

    mirror_only = sum(1 for a in assets if a.get("source") == "mirror_only")
    edgex_managed = sum(1 for a in assets if a.get("source") == "edgex")

    return {
        "assets": assets,
        "edgex_device_count": len(devices),
        "mirror_only_count": mirror_only,
        "edgex_managed_count": edgex_managed,
        "traffic_live": traffic.get("live") is True,
        "ip_device_map": ip_map,
    }
