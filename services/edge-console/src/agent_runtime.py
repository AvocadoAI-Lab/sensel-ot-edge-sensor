"""Read edge-agent runtime snapshot written to shared data volume."""

from __future__ import annotations

import json
import os
import time
from pathlib import Path
from typing import Any


def _runtime_path() -> Path:
    return Path(
        os.environ.get(
            "AGENT_RUNTIME_PATH",
            "/data/agent/agent-runtime.json",
        )
    )


def load_agent_runtime() -> dict[str, Any]:
    path = _runtime_path()
    if not path.is_file():
        return {}
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return raw if isinstance(raw, dict) else {}


def northbound_mqtt_ok(
    config_mqtt_enabled: bool,
    mqtt_host: str,
    mqtt_port: int,
    runtime: dict[str, Any],
    *,
    stale_sec: float = 120.0,
) -> tuple[bool, str]:
    if not config_mqtt_enabled:
        return False, "北向 MQTT 已停用"

    tenant = str(runtime.get("tenant_id") or "").strip()
    connected = bool(runtime.get("mqtt_connected"))
    last_publish = str(runtime.get("last_mqtt_publish_at") or "").strip()
    updated_at = str(runtime.get("updated_at") or "").strip()

    detail_parts = []
    if mqtt_host:
        detail_parts.append(f"{mqtt_host}:{mqtt_port}")
    if tenant:
        detail_parts.append(f"tenant {tenant}")
    if last_publish:
        detail_parts.append(f"publish {last_publish}")

    now = time.time()
    fresh = False
    if updated_at:
        try:
            text = updated_at.replace("Z", "+00:00")
            from datetime import datetime

            ts = datetime.fromisoformat(text).timestamp()
            fresh = (now - ts) <= stale_sec
        except ValueError:
            fresh = False

    if connected and fresh:
        return True, " · ".join(detail_parts) or "已連線"
    if connected:
        return True, (" · ".join(detail_parts) or "已連線") + " (heartbeat 過期)"
    if tenant and last_publish:
        return False, " · ".join(detail_parts) + " · 等待重連"
    return False, (" · ".join(detail_parts) or "未連線") + " · 等待 agent"
