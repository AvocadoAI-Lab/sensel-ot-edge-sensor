"""FR-11: CPU, memory, disk, capture stats, service status."""

from __future__ import annotations

import os
from datetime import datetime, timezone

import httpx
import psutil

from src.config.settings import AppConfig


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _probe_edgex_core_data() -> str:
    url = os.environ.get("EDGEX_CORE_DATA_URL", "http://edgex-core-data:59880")
    try:
        response = httpx.get(f"{url.rstrip('/')}/api/v3/ping", timeout=3.0)
        if response.status_code == 200:
            return "healthy"
        return f"http_{response.status_code}"
    except Exception:
        return "unreachable"


def collect_health(config: AppConfig) -> dict:
    cpu = psutil.cpu_percent(interval=0.1)
    mem = psutil.virtual_memory().percent
    disk = psutil.disk_usage("/").percent

    return {
        "sensor_id": config.sensor.id,
        "site_id": config.sensor.site_id,
        "cpu_usage": round(cpu, 2),
        "memory_usage": round(mem, 2),
        "disk_usage": round(disk, 2),
        "packet_rate": 0,
        "dropped_packets": 0,
        "edgex_status": _probe_edgex_core_data(),
        "agent_status": "running",
        "policy_version": "",
        "timestamp": _utc_now_iso(),
    }
