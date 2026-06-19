"""Aggregate edge appliance status for dashboard cards."""

from __future__ import annotations

import os
import time
from pathlib import Path
from typing import Any

from src.agent_runtime import load_agent_runtime, northbound_mqtt_ok
from src.config_store import ConfigStore, PlatformConfig
from src.events_index import scan_events_stats
from src.operational_mode_service import read_operational_mode
from src.traffic_service import read_live_traffic

_PING_CACHE_TTL_SEC = 30.0
_ping_cache: dict[str, Any] = {"at": 0.0, "ok": False, "url": ""}


def _cached_sensel_ping(config: PlatformConfig) -> bool:
    url = (config.sensel_api_url or "").strip()
    if not url:
        return False
    now = time.monotonic()
    if (
        _ping_cache["url"] == url
        and (now - float(_ping_cache["at"])) < _PING_CACHE_TTL_SEC
    ):
        return bool(_ping_cache["ok"])
    ok = False
    try:
        from src.sensel_api import ping_sensel

        ping_sensel(config)
        ok = True
    except Exception:
        ok = False
    _ping_cache["url"] = url
    _ping_cache["ok"] = ok
    _ping_cache["at"] = now
    return ok


def _baseline_stats() -> dict[str, Any]:
    policy_dir = Path(os.environ.get("POLICY_DIR", "/data/config/policy"))
    baseline_path = policy_dir / "baseline.json"
    if not baseline_path.is_file():
        alt = Path("/app/config/policy/baseline.json")
        baseline_path = alt if alt.is_file() else baseline_path
    if not baseline_path.is_file():
        return {"loaded": False, "assets": 0, "comm_pairs": 0}
    try:
        import json

        data = json.loads(baseline_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {"loaded": False, "assets": 0, "comm_pairs": 0}
    assets = data.get("assets") or data.get("devices") or []
    pairs = data.get("comm_pairs") or data.get("communication_pairs") or []
    return {
        "loaded": True,
        "assets": len(assets) if isinstance(assets, list) else 0,
        "comm_pairs": len(pairs) if isinstance(pairs, list) else 0,
    }


def _policy_gauge(
    config: PlatformConfig,
    baseline: dict[str, Any],
    events_24h: int,
    traffic: dict[str, Any],
    *,
    mqtt_ok: bool,
) -> dict[str, Any]:
    score = 0
    factors: list[str] = []
    if baseline.get("loaded"):
        score += 35
        factors.append("baseline")
    if config.last_register_ok is True:
        score += 30
        factors.append("registered")
    elif config.configured:
        score += 10
        factors.append("configured")
    if traffic.get("live"):
        score += 20
        factors.append("telemetry")
    m = traffic.get("metrics") or {}
    if int(m.get("ioc_entries") or 0) > 0:
        score += 10
        factors.append("ioc")
    if mqtt_ok and config.mqtt_enabled:
        score += 5
        factors.append("mqtt")
    if events_24h > 50:
        score = max(0, score - 10)
        factors.append("high_events")
    percent = min(100, score)
    return {
        "percent": percent,
        "factors": factors,
        "label": "合規" if percent >= 85 else "部分就緒" if percent >= 50 else "待設定",
    }


def _safe_mqtt_credentials(raw: Any) -> dict[str, Any]:
    """Project the agent's MQTT credential status, never leaking a password."""
    if not isinstance(raw, dict):
        return {"landed": False}
    return {
        "landed": bool(raw.get("landed")),
        "username": raw.get("username"),
        "host": raw.get("host"),
        "port": raw.get("port"),
        "tenant_id": raw.get("tenant_id"),
        "acl_version": raw.get("acl_version"),
    }


def _engines_view(raw: Any) -> list[dict[str, Any]]:
    """Normalize the agent's engines summary list for the dashboard/wizard."""
    if not isinstance(raw, list):
        return []
    out: list[dict[str, Any]] = []
    for eng in raw:
        if not isinstance(eng, dict):
            continue
        out.append(
            {
                "name": eng.get("name"),
                "configured": bool(eng.get("configured")),
                "status": eng.get("status") or "unknown",
                "active": bool(eng.get("active")),
                "rule_version": eng.get("rule_version") or "unknown",
                "rules_enabled_count": eng.get("rules_enabled_count"),
                "rules_last_update": eng.get("rules_last_update"),
                "last_event_age_sec": eng.get("last_event_age_sec"),
            }
        )
    return out


def build_status(store: ConfigStore) -> dict[str, Any]:
    config = store.load()
    assets_dir = Path(os.environ.get("ASSETS_DIR", "/data/assets"))
    events_path = assets_dir / "security-events.jsonl"

    stats = scan_events_stats(events_path, recent_limit=8)
    runtime = load_agent_runtime()
    mqtt_ok, mqtt_detail = northbound_mqtt_ok(
        config.mqtt_enabled,
        config.mqtt_host,
        config.mqtt_port,
        runtime,
    )
    sensel_ok = _cached_sensel_ping(config)
    top_rules = sorted(stats.rule_counts_24h.items(), key=lambda x: -x[1])[:5]
    baseline = _baseline_stats()
    traffic = read_live_traffic(store)
    tm = traffic.get("metrics") or {}
    policy = _policy_gauge(
        config,
        baseline,
        stats.events_24h,
        traffic,
        mqtt_ok=mqtt_ok,
    )

    tenant_id = (
        config.last_register_tenant_id
        or config.mqtt_tenant_id
        or str(runtime.get("tenant_id") or "")
    )
    operational = read_operational_mode()

    return {
        "configured": config.configured,
        "sensor_id": config.sensor_id,
        "site_id": config.site_id,
        "tenant_id": tenant_id,
        "operational_mode": operational,
        "cards": {
            "sensel": {
                "label": "SenseL Platform",
                "ok": sensel_ok,
                "detail": config.sensel_api_url or "未設定",
            },
            "registration": {
                "label": "感測器註冊",
                "ok": config.last_register_ok is True or bool(runtime.get("registered")),
                "detail": config.last_register_tenant_id
                or config.last_register_error
                or runtime.get("last_error")
                or "尚未註冊",
            },
            "mqtt": {
                "label": "北向 MQTT",
                "ok": mqtt_ok if config.mqtt_enabled else None,
                "detail": mqtt_detail if config.mqtt_enabled else "已停用",
            },
            "capture": {
                "label": "事件擷取",
                "ok": events_path.is_file(),
                "detail": f"24h {stats.events_24h} 筆" if events_path.is_file() else "等待首筆事件",
            },
            "baseline": {
                "label": "Baseline",
                "ok": baseline.get("loaded") is True,
                "detail": (
                    f"{baseline.get('assets', 0)} 資產 · {baseline.get('comm_pairs', 0)} comm pairs"
                    if baseline.get("loaded")
                    else "未載入"
                ),
            },
        },
        "northbound": {
            "mqtt_connected": bool(runtime.get("mqtt_connected")),
            "last_mqtt_publish_at": runtime.get("last_mqtt_publish_at"),
            "agent_updated_at": runtime.get("updated_at"),
            "registered": bool(runtime.get("registered")),
            "last_error": runtime.get("last_error"),
            # Non-secret status of Control-Plane auto-provisioned MQTT
            # credentials (whether they've landed on this appliance).
            "mqtt_credentials": _safe_mqtt_credentials(runtime.get("mqtt_credentials")),
        },
        "metrics": {
            "events_24h": stats.events_24h,
            "recent_events": stats.recent_events,
            "rule_counts_24h": stats.rule_counts_24h,
            "top_rules_24h": top_rules,
            "baseline": baseline,
            "capture_interface": config.capture_interface or os.environ.get("CAPTURE_INTERFACE", ""),
            "capture_bpf": config.capture_bpf_filter or "",
            "policy_gauge": policy,
            "telemetry": {
                "live": traffic.get("live") is True,
                "instant_rate": tm.get("instant_rate", 0),
                "unique_ips": tm.get("unique_ips", 0),
                "unique_macs": tm.get("unique_macs", 0),
                "goose_messages": tm.get("goose_messages", 0),
                "ioc_entries": tm.get("ioc_entries", 0),
            },
            # IDS engine (Snort/Suricata) liveness + rule package status,
            # written by the edge-agent health loop into agent-runtime.json.
            "engines": _engines_view(runtime.get("engines")),
        },
        "last_register_at": config.last_register_at or runtime.get("last_register_at"),
    }
