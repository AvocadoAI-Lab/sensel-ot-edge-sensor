"""Aggregate edge appliance status for dashboard cards."""

from __future__ import annotations

import json
import os
import socket
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from src.config_store import ConfigStore, PlatformConfig


def _read_jsonl_tail(path: Path, limit: int = 5) -> list[dict[str, Any]]:
    if not path.is_file():
        return []
    lines = [ln for ln in path.read_text(encoding="utf-8").splitlines() if ln.strip()]
    events: list[dict[str, Any]] = []
    for line in reversed(lines[-500:]):
        try:
            events.append(json.loads(line))
        except json.JSONDecodeError:
            continue
        if len(events) >= limit:
            break
    return events


def _tcp_reachable(host: str, port: int, timeout: float = 2.0) -> bool:
    if not host:
        return False
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def build_status(store: ConfigStore) -> dict[str, Any]:
    config = store.load()
    assets_dir = Path(os.environ.get("ASSETS_DIR", "/data/assets"))
    events_path = assets_dir / "security-events.jsonl"

    recent = _read_jsonl_tail(events_path, limit=8)
    events_24h = 0
    if events_path.is_file():
        cutoff = datetime.now(timezone.utc).timestamp() - 86400
        for line in events_path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            try:
                ev = json.loads(line)
            except json.JSONDecodeError:
                continue
            ts = ev.get("timestamp") or ev.get("detected_at") or ""
            try:
                if ts.endswith("Z"):
                    ts = ts.replace("Z", "+00:00")
                dt = datetime.fromisoformat(ts)
                if dt.timestamp() >= cutoff:
                    events_24h += 1
            except ValueError:
                pass

    mqtt_ok = _tcp_reachable(config.mqtt_host, config.mqtt_port) if config.mqtt_enabled else None
    sensel_ok = False
    if config.sensel_api_url:
        try:
            from src.sensel_api import ping_sensel

            ping_sensel(config)
            sensel_ok = True
        except Exception:
            sensel_ok = False

    return {
        "configured": config.configured,
        "sensor_id": config.sensor_id,
        "site_id": config.site_id,
        "tenant_id": config.last_register_tenant_id or config.mqtt_tenant_id,
        "cards": {
            "sensel": {
                "label": "SenseL Platform",
                "ok": sensel_ok,
                "detail": config.sensel_api_url or "未設定",
            },
            "registration": {
                "label": "感測器註冊",
                "ok": config.last_register_ok is True,
                "detail": config.last_register_tenant_id or config.last_register_error or "尚未註冊",
            },
            "mqtt": {
                "label": "北向 MQTT",
                "ok": mqtt_ok,
                "detail": f"{config.mqtt_host}:{config.mqtt_port}" if config.mqtt_enabled else "已停用",
            },
            "capture": {
                "label": "事件擷取",
                "ok": events_path.is_file(),
                "detail": f"24h {events_24h} 筆" if events_path.is_file() else "等待首筆事件",
            },
        },
        "metrics": {
            "events_24h": events_24h,
            "recent_events": recent,
        },
        "last_register_at": config.last_register_at,
    }
