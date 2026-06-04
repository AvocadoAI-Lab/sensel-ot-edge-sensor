"""Lab traffic control — start/stop GOOSE/MMS publishers and packet-sensor via Docker."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path
from typing import Any

from src.config_store import ConfigStore
from src.edgex_service import _docker_status
from src.traffic_service import read_live_traffic

_TARGETS: dict[str, str] = {
    "goose": "LAB_GOOSE_CONTAINER",
    "mms": "LAB_MMS_CONTAINER",
    "capture": "PACKET_SENSOR_CONTAINER",
}

_DEFAULT_CONTAINERS = {
    "goose": "sensel-goose-publisher",
    "mms": "sensel-mms-publisher",
    "capture": "sensel-packet-sensor",
}

_PUBLISHER_META: dict[str, dict[str, str]] = {
    "goose": {"label": "GOOSE 模擬", "summary": "APPID 1000 · eth0"},
    "mms": {"label": "MMS 模擬", "summary": "TCP:102 · 192.168.10.88→50"},
}

_PRESETS: dict[str, dict[str, Any]] = {
    "lab_only": {"action": "start", "targets": ["goose", "mms"], "stop": ["capture"]},
    "mirror_only": {"action": "stop", "targets": ["goose", "mms"], "start": ["capture"]},
    "all_on": {"action": "start", "targets": ["goose", "mms", "capture"]},
    "all_off": {"action": "stop", "targets": ["goose", "mms", "capture"]},
}

_PRESET_LABELS = [
    {"id": "lab_only", "label": "僅 Lab 模擬（停擷取）"},
    {"id": "mirror_only", "label": "僅 Mirror 擷取（停模擬）"},
    {"id": "all_on", "label": "全部開始"},
    {"id": "all_off", "label": "全部暫停"},
]


def _env_enabled() -> bool:
    return os.environ.get("LAB_TRAFFIC_CONTROL_ENABLED", "").lower() in ("1", "true", "yes")


def docker_control_enabled() -> bool:
    return os.environ.get("EDGE_CONSOLE_DOCKER_RESTART", "true").lower() in ("1", "true", "yes")


def _container_name(target: str) -> str:
    env_key = _TARGETS.get(target, "")
    default = _DEFAULT_CONTAINERS.get(target, "")
    return os.environ.get(env_key, default) if env_key else default


def _container_exists(container: str) -> bool:
    ds = _docker_status(container)
    return ds.get("status") not in ("missing", "unknown", None) or ds.get("running") is not None


def lab_traffic_available() -> bool:
    if _env_enabled():
        return True
    return _container_exists(_container_name("goose")) or _container_exists(_container_name("mms"))


def _docker_start(container: str) -> tuple[bool, str]:
    ds = _docker_status(container)
    if ds.get("status") == "missing":
        return False, f"容器不存在：{container}"
    if ds.get("running"):
        return True, "already running"
    try:
        subprocess.run(
            ["docker", "start", container],
            check=True,
            capture_output=True,
            text=True,
            timeout=60,
        )
        return True, "started"
    except subprocess.CalledProcessError as exc:
        return False, (exc.stderr or exc.stdout or str(exc))[:300]
    except FileNotFoundError:
        return False, "docker CLI not available"


def _docker_stop(container: str) -> tuple[bool, str]:
    ds = _docker_status(container)
    if ds.get("status") == "missing":
        return False, f"容器不存在：{container}"
    if not ds.get("running"):
        return True, "already stopped"
    try:
        subprocess.run(
            ["docker", "stop", container],
            check=True,
            capture_output=True,
            text=True,
            timeout=60,
        )
        return True, "stopped"
    except subprocess.CalledProcessError as exc:
        return False, (exc.stderr or exc.stdout or str(exc))[:300]
    except FileNotFoundError:
        return False, "docker CLI not available"


def _docker_restart(container: str) -> tuple[bool, str]:
    if not Path("/var/run/docker.sock").exists():
        return False, "Docker socket not mounted"
    try:
        subprocess.run(
            ["docker", "restart", container],
            check=True,
            capture_output=True,
            text=True,
            timeout=90,
        )
        return True, "restarted"
    except subprocess.CalledProcessError as exc:
        return False, (exc.stderr or exc.stdout or str(exc))[:300]
    except FileNotFoundError:
        return False, "docker CLI not available"


def _resolve_preset(preset: str) -> tuple[str, list[str], list[str]]:
    spec = _PRESETS.get(preset)
    if not spec:
        raise ValueError(f"Unknown preset: {preset}")
    action = str(spec["action"])
    start_targets = list(spec.get("start") or [])
    stop_targets = list(spec.get("stop") or [])
    if action == "start":
        start_targets = list(spec.get("targets") or [])
    elif action == "stop":
        stop_targets = list(spec.get("targets") or [])
    return preset, start_targets, stop_targets


def apply_lab_traffic_action(
    *,
    action: str | None = None,
    targets: list[str] | None = None,
    preset: str | None = None,
) -> dict[str, Any]:
    if not docker_control_enabled():
        return {"ok": False, "error": "Docker control disabled (EDGE_CONSOLE_DOCKER_RESTART)"}
    if not Path("/var/run/docker.sock").exists():
        return {"ok": False, "error": "Docker socket not mounted"}

    start_list: list[str] = []
    stop_list: list[str] = []
    restart_list: list[str] = []
    preset_id: str | None = None

    if preset:
        preset_id, start_list, stop_list = _resolve_preset(preset)
    else:
        act = (action or "").strip().lower()
        tgt = [t for t in (targets or []) if t in _TARGETS]
        if act not in ("start", "stop", "restart"):
            raise ValueError(f"Unknown action: {action}")
        if not tgt:
            raise ValueError("targets required")
        if act == "start":
            start_list = tgt
        elif act == "stop":
            stop_list = tgt
        else:
            restart_list = [t for t in tgt if t == "capture"]
            stop_list = [t for t in tgt if t != "capture"]
            if stop_list:
                raise ValueError("restart only supported for capture")

    results: list[dict[str, Any]] = []

    for target in stop_list:
        container = _container_name(target)
        ok, msg = _docker_stop(container)
        results.append({"target": target, "container": container, "ok": ok, "message": msg})

    for target in start_list:
        container = _container_name(target)
        ok, msg = _docker_start(container)
        results.append({"target": target, "container": container, "ok": ok, "message": msg})

    for target in restart_list:
        container = _container_name(target)
        ok, msg = _docker_restart(container)
        results.append({"target": target, "container": container, "ok": ok, "message": msg})

    all_ok = all(r.get("ok") for r in results) if results else False
    return {"ok": all_ok, "preset": preset_id, "results": results}


def _publisher_row(target_id: str) -> dict[str, Any]:
    container = _container_name(target_id)
    ds = _docker_status(container)
    meta = _PUBLISHER_META.get(target_id, {})
    status = ds.get("status") or "unknown"
    return {
        "id": target_id,
        "container": container,
        "label": meta.get("label", target_id),
        "status": status,
        "running": ds.get("running") is True,
        "summary": meta.get("summary", ""),
        "exists": status != "missing",
    }


def build_lab_traffic_status(store: ConfigStore | None = None) -> dict[str, Any]:
    available = lab_traffic_available()
    ctrl = docker_control_enabled() and Path("/var/run/docker.sock").exists()
    traffic = read_live_traffic(store)
    capture_container = _container_name("capture")
    capture_ds = _docker_status(capture_container)

    cfg_iface = ""
    cfg_bpf = ""
    if store is not None:
        cfg = store.load()
        cfg_iface = cfg.capture_interface or ""
        cfg_bpf = cfg.capture_bpf_filter or ""

    return {
        "enabled": available,
        "mode": "lab" if available else "production",
        "message": "Lab 61850 publishers detected" if available else "Lab traffic control not available",
        "docker_control_enabled": ctrl,
        "capture": {
            "id": "capture",
            "container": capture_container,
            "label": "被動擷取",
            "status": capture_ds.get("status") or "unknown",
            "running": capture_ds.get("running") is True,
            "interface": traffic.get("capture_interface") or cfg_iface,
            "bpf_filter": traffic.get("capture_bpf") or cfg_bpf,
            "live": traffic.get("live") is True,
            "instant_rate": (traffic.get("metrics") or {}).get("instant_rate"),
            "age_sec": traffic.get("age_sec"),
        },
        "publishers": [_publisher_row("goose"), _publisher_row("mms")],
        "presets": _PRESET_LABELS,
    }
