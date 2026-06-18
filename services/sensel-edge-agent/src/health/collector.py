"""FR-11: CPU, memory, disk, capture stats, service status."""

from __future__ import annotations

import os
import time
from datetime import datetime, timezone
from pathlib import Path

import httpx
import psutil

from src.config.settings import AppConfig

# If the Snort events file has not been touched within this many seconds we
# report the engine as "stale" rather than "running".
_SNORT_STALE_AFTER_SEC = 300


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _probe_snort_engine(config: AppConfig) -> dict:
    """Best-effort Snort 3 status from the shared snort-events.jsonl freshness.

    The edge-agent cannot see the Snort process directly (separate container),
    so it infers liveness from the bridge output file the agent already tails.
    Returns name/status so the DMS dashboard can surface engine health.
    """
    watch_path = config.sensel.events.snort_watch_path
    status = "absent"
    last_event_age_sec: float | None = None
    try:
        path = Path(watch_path)
        if path.is_file():
            age = time.time() - path.stat().st_mtime
            last_event_age_sec = round(age, 1)
            status = "running" if age <= _SNORT_STALE_AFTER_SEC else "stale"
    except Exception:
        status = "unknown"
    return {
        "name": "snort",
        "status": status,
        "last_event_age_sec": last_event_age_sec,
    }


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
        "engine": _probe_snort_engine(config),
        "policy_version": "",
        "timestamp": _utc_now_iso(),
    }
