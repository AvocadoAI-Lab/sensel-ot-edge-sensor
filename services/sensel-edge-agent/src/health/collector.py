"""FR-11: CPU, memory, disk, capture stats, service status."""

from __future__ import annotations

import os
import json
from datetime import datetime, timezone
from pathlib import Path

import httpx
import psutil

from src.config.settings import AppConfig
from src.health.engines import probe_engines


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _primary_engine(engines: list[dict]) -> dict:
    """Pick the engine to report in the legacy ``engine`` health field.

    Prefer an active engine (running/stale), else a configured one, else the
    first probed engine. Kept for backward compatibility with the DMS health
    schema which expects a single ``engine`` object (FR-008).
    """
    for eng in engines:
        if eng.get("active"):
            return eng
    for eng in engines:
        if eng.get("configured"):
            return eng
    return engines[0] if engines else {"name": "snort", "status": "absent"}


def _probe_edgex_core_data() -> str:
    url = os.environ.get("EDGEX_CORE_DATA_URL", "http://edgex-core-data:59880")
    try:
        response = httpx.get(f"{url.rstrip('/')}/api/v3/ping", timeout=3.0)
        if response.status_code == 200:
            return "healthy"
        return f"http_{response.status_code}"
    except Exception:
        return "unreachable"


def _disk_alert_threshold_pct() -> float:
    raw = (os.environ.get("DISK_ALERT_THRESHOLD_PCT") or "85").strip()
    try:
        return max(1.0, min(float(raw), 99.0))
    except ValueError:
        return 85.0


def _model_inference_status(config: AppConfig) -> dict:
    default_path = (
        Path(config.sensel.episodes.watch_path).parent / "model-runtime.json"
    )
    path = Path(os.environ.get("MODEL_RUNTIME_STATUS_PATH", str(default_path)))
    if not path.is_file():
        return {"enabled": False, "status": "not_reported", "models": []}
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {"enabled": False, "status": "invalid", "models": []}
    if not isinstance(value, dict):
        return {"enabled": False, "status": "invalid", "models": []}
    value["status"] = "reported"
    return value


def collect_health(config: AppConfig) -> dict:
    cpu = psutil.cpu_percent(interval=0.1)
    mem = psutil.virtual_memory().percent
    disk_usage = psutil.disk_usage("/")
    disk = disk_usage.percent
    disk_threshold = _disk_alert_threshold_pct()
    disk_alert_active = disk >= disk_threshold

    engines = probe_engines(config)

    return {
        "sensor_id": config.sensor.id,
        "site_id": config.sensor.site_id,
        "cpu_usage": round(cpu, 2),
        "memory_usage": round(mem, 2),
        "disk_usage": round(disk, 2),
        "disk_free_gb": round(disk_usage.free / (1024**3), 2),
        "disk_total_gb": round(disk_usage.total / (1024**3), 2),
        "disk_alert_threshold_pct": disk_threshold,
        "disk_alert_active": disk_alert_active,
        "packet_rate": 0,
        "dropped_packets": 0,
        "edgex_status": _probe_edgex_core_data(),
        "agent_status": "running",
        # Legacy single-engine field (DMS dashboard, FR-008).
        "engine": _primary_engine(engines),
        # Full per-engine status incl. Snort and Suricata.
        "engines": engines,
        "model_inference": _model_inference_status(config),
        "policy_version": "",
        "timestamp": _utc_now_iso(),
    }
