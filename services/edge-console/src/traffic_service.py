"""Read live mirror capture stats written by packet-sensor."""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from src.config_store import ConfigStore


def _live_stats_path() -> Path:
    assets = Path(os.environ.get("ASSETS_DIR", "/data/assets"))
    return assets / "capture-live.json"


def read_live_traffic(store: ConfigStore | None = None) -> dict[str, Any]:
    path = _live_stats_path()
    config = store.load() if store is not None else None
    capture_interface = (
        (config.capture_interface if config else None)
        or os.environ.get("CAPTURE_INTERFACE", "")
    )
    capture_bpf = (config.capture_bpf_filter if config else None) or ""

    if not path.is_file():
        return {
            "live": False,
            "stale": True,
            "message": "Packet Sensor 尚未寫入即時統計（請確認 sensel-packet-sensor 正在執行）",
            "capture_interface": capture_interface,
            "capture_bpf": capture_bpf,
        }

    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        return {
            "live": False,
            "stale": True,
            "message": f"無法讀取即時統計：{exc}",
            "capture_interface": capture_interface,
            "capture_bpf": capture_bpf,
        }

    updated_at = str(data.get("updated_at") or "")
    age_sec: float | None = None
    stale = True
    if updated_at:
        try:
            ts = updated_at.replace("Z", "+00:00")
            dt = datetime.fromisoformat(ts)
            age_sec = max(0.0, datetime.now(timezone.utc).timestamp() - dt.timestamp())
            stale = age_sec > 5.0
        except ValueError:
            pass

    return {
        "live": not stale,
        "stale": stale,
        "age_sec": round(age_sec, 1) if age_sec is not None else None,
        "updated_at": updated_at,
        "capture_interface": data.get("capture_interface") or capture_interface,
        "capture_bpf": data.get("capture_bpf") or capture_bpf,
        "capture_backend": data.get("capture_backend"),
        "sensor_id": data.get("sensor_id"),
        "site_id": data.get("site_id"),
        "metrics": {
            "instant_rate": data.get("instant_rate", 0),
            "packet_rate": data.get("packet_rate", 0),
            "total_packets": data.get("total_packets", 0),
            "window_packets": data.get("window_packets", 0),
            "ipv4_packets": data.get("ipv4_packets", 0),
            "ipv6_packets": data.get("ipv6_packets", 0),
            "unique_macs": data.get("unique_macs", 0),
            "unique_ips": data.get("unique_ips", 0),
            "goose_messages": data.get("goose_messages", 0),
            "mms_writes": data.get("mms_writes", 0),
            "mms_reads": data.get("mms_reads", 0),
            "mms_sessions": data.get("mms_sessions", 0),
            "ioc_entries": data.get("ioc_entries", 0),
            "elapsed_sec": data.get("elapsed_sec", 0),
            "idle_sec": data.get("idle_sec"),
        },
        "top_macs": data.get("top_macs") or [],
        "top_ips": data.get("top_ips") or [],
        "recent_packets": data.get("recent_packets") or [],
    }
