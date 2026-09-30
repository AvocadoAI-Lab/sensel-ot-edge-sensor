"""EdgeX platform proxy — core-metadata / core-data + local config fallback."""

from __future__ import annotations

import os
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

import httpx

_DEFAULT_DATA = "http://edgex-core-data:59880"
_DEFAULT_METADATA = "http://edgex-core-metadata:59881"

# Lab stack services (container_name → display)
_EDGEX_SERVICES: list[dict[str, Any]] = [
    {"id": "core-keeper", "label": "Core Keeper", "container": "edgex-core-keeper", "port": 59890, "ping_path": "/api/v3/ping"},
    {"id": "core-metadata", "label": "Core Metadata", "container": "edgex-core-metadata", "port": 59881, "ping_url_env": "EDGEX_CORE_METADATA_URL"},
    {"id": "core-data", "label": "Core Data", "container": "edgex-core-data", "port": 59880, "ping_url_env": "EDGEX_CORE_DATA_URL"},
    {"id": "device-modbus", "label": "Device Modbus", "container": "edgex-device-modbus", "port": 59901},
    {"id": "device-mqtt", "label": "Device MQTT", "container": "edgex-device-mqtt", "port": 59982},
    {"id": "device-opc-ua", "label": "Device OPC UA", "container": "edgex-device-opc-ua", "port": 59997, "optional": True},
    {"id": "device-s7", "label": "Device S7", "container": "edgex-device-s7", "port": 59994, "optional": True},
    {"id": "mqtt-broker", "label": "EdgeX MQTT Bus", "container": "edgex-mqtt-broker", "port": 1883},
    {"id": "modbus-simulator", "label": "Modbus Simulator (Lab)", "container": "edgex-modbus-simulator", "port": 1502, "optional": True},
]

_RESTARTABLE = {
    "edgex-device-modbus",
    "edgex-device-mqtt",
    "edgex-device-opc-ua",
    "edgex-device-s7",
    "edgex-core-data",
    "edgex-core-metadata",
}

# SenseL edge-stack / NDR containers are not part of the curated EdgeX list;
# they are discovered live (see _discover_extra_containers) so any enabled
# overlay (Suricata, Snort, lab publishers, …) shows up in Edge Runtime. This
# map only supplies friendly labels — unknown containers fall back to the name.
_SENSEL_LABELS: dict[str, str] = {
    "sensel-edge-agent": "SenseL Edge Agent",
    "sensel-packet-sensor": "Packet Sensor",
    "sensel-edge-console": "Edge Console",
    "sensel-events-viewer": "Events Viewer",
    "sensel-suricata": "Suricata IDS",
    "sensel-snort": "Snort IDS",
    "sensel-local-mqtt": "Local MQTT Bus",
    "sensel-vpn-client": "VPN Client",
    "sensel-mock-api": "Mock SenseL API (Lab)",
    "sensel-goose-publisher": "GOOSE Publisher (Lab)",
    "sensel-mms-publisher": "MMS Publisher (Lab)",
    "sensel-it-traffic-publisher": "IT Traffic Publisher (Lab)",
    "sensel-scenario-runner": "Scenario Runner (Lab)",
}

# A discovered container is included when its name matches one of these — keeps
# the view scoped to this edge stack (won't pull in unrelated host containers).
def _is_sensel_container(name: str) -> bool:
    n = name or ""
    return n.startswith("sensel-") or "suricata" in n or "snort" in n


# Any EdgeX/SenseL edge-stack container may be inspected for logs/restart.
_CONTROLLABLE_RE = re.compile(r"^(edgex-|sensel-)|suricata|snort")


def _container_allowed(container: str) -> bool:
    return bool(_CONTROLLABLE_RE.search(container or ""))

_PROTOCOL_MATRIX: list[dict[str, Any]] = [
    {"id": "modbus", "label": "Modbus TCP", "driver": "device-modbus", "phase": 1},
    {"id": "mqtt", "label": "MQTT", "driver": "device-mqtt", "phase": 1},
    {"id": "opcua", "label": "OPC UA", "driver": "device-opc-ua", "phase": 2},
    {"id": "s7", "label": "S7 / ISO-on-TCP", "driver": "device-s7", "phase": 2},
    {"id": "iec61850", "label": "GOOSE / MMS (Mirror)", "driver": "packet-sensor", "phase": 1},
]


def _data_url() -> str:
    return os.environ.get("EDGEX_CORE_DATA_URL", _DEFAULT_DATA).rstrip("/")


def _metadata_url() -> str:
    return os.environ.get("EDGEX_CORE_METADATA_URL", _DEFAULT_METADATA).rstrip("/")


def _devices_config_dir() -> Path:
    return Path(os.environ.get("EDGEX_DEVICES_DIR", "/config/edgex/devices"))


def _unwrap_list(payload: Any, *keys: str) -> list[Any]:
    if isinstance(payload, list):
        return payload
    if isinstance(payload, dict):
        for key in keys:
            val = payload.get(key)
            if isinstance(val, list):
                return val
        # EdgeX single resource wrapper
        for key in ("device", "event", "reading"):
            val = payload.get(key)
            if val is not None:
                return [val] if isinstance(val, dict) else (val if isinstance(val, list) else [])
    return []


def _ping_service(base_url: str, path: str = "/api/v3/ping", timeout: float = 3.0) -> dict[str, Any]:
    url = f"{base_url.rstrip('/')}{path}"
    try:
        started = datetime.now(timezone.utc)
        resp = httpx.get(url, timeout=timeout)
        elapsed_ms = int((datetime.now(timezone.utc) - started).total_seconds() * 1000)
        ok = resp.status_code == 200
        return {"ok": ok, "status_code": resp.status_code, "latency_ms": elapsed_ms, "url": url}
    except Exception as exc:
        return {"ok": False, "status_code": None, "latency_ms": None, "url": url, "error": str(exc)[:200]}


def _docker_status(container: str) -> dict[str, Any]:
    if not Path("/var/run/docker.sock").exists():
        return {"container": container, "status": "unknown", "running": None}
    try:
        # One inspect for state, start time, health and image (cheap).
        fmt = "{{.State.Status}}|{{.State.StartedAt}}|{{if .State.Health}}{{.State.Health.Status}}{{else}}{{end}}|{{.Config.Image}}"
        proc = subprocess.run(
            ["docker", "inspect", "-f", fmt, container],
            capture_output=True,
            text=True,
            timeout=8,
        )
        if proc.returncode != 0:
            return {"container": container, "status": "missing", "running": None}
        parts = (proc.stdout.strip().split("|") + ["", "", "", ""])[:4]
        status, started_at, health, image = parts
        return {
            "container": container,
            "status": status or "missing",
            "running": status == "running",
            "started_at": started_at or None,
            "health": health or None,
            "image": image or None,
        }
    except Exception as exc:
        return {"container": container, "status": "error", "running": False, "error": str(exc)[:120]}


# ---- docker stats (CPU/Mem) — one batched call, short-cached ----------------
_STATS_CACHE: dict[str, Any] = {"at": 0.0, "data": {}}
_STATS_TTL_SEC = 5.0


def _parse_mem_mb(token: str) -> Optional[float]:
    # On hosts without the memory cgroup, docker stats reports "0B" / "-- / --";
    # treat those as unavailable (None) rather than a misleading 0 MB.
    m = re.match(r"\s*([\d.]+)\s*([KMGT]?i?B)", token or "", re.IGNORECASE)
    if not m:
        return None
    val = float(m.group(1))
    unit = m.group(2).upper()
    factor = {
        "B": 1 / (1024 * 1024), "KIB": 1 / 1024, "KB": 1 / 1024,
        "MIB": 1.0, "MB": 1.0, "GIB": 1024.0, "GB": 1024.0,
        "TIB": 1024 * 1024.0, "TB": 1024 * 1024.0,
    }.get(unit, 1.0)
    mb = round(val * factor, 1)
    return mb if mb > 0 else None


def _docker_stats_all() -> dict[str, dict[str, Any]]:
    """Return {container_name: {cpu_pct, mem_mb}} from a single docker stats call."""
    import time as _time

    now = _time.monotonic()
    if (now - float(_STATS_CACHE["at"])) < _STATS_TTL_SEC and _STATS_CACHE["data"]:
        return _STATS_CACHE["data"]
    out: dict[str, dict[str, Any]] = {}
    if not Path("/var/run/docker.sock").exists():
        return out
    try:
        proc = subprocess.run(
            ["docker", "stats", "--no-stream", "--format", "{{.Name}}|{{.CPUPerc}}|{{.MemUsage}}"],
            capture_output=True,
            text=True,
            timeout=12,
        )
        if proc.returncode == 0:
            for line in proc.stdout.splitlines():
                cols = line.split("|")
                if len(cols) < 3:
                    continue
                name, cpu, mem = cols[0].strip(), cols[1].strip(), cols[2].strip()
                cpu_pct = None
                try:
                    cpu_pct = round(float(cpu.replace("%", "").strip()), 1)
                except ValueError:
                    pass
                out[name] = {"cpu_pct": cpu_pct, "mem_mb": _parse_mem_mb(mem)}
    except Exception:
        return _STATS_CACHE["data"] or {}
    _STATS_CACHE["at"] = now
    _STATS_CACHE["data"] = out
    return out


# ---- EdgeX service version — HTTP /api/v3/version, longer-cached ------------
_VERSION_CACHE: dict[str, Any] = {}
_VERSION_TTL_SEC = 60.0


def _service_version(base_url: Optional[str], image: Optional[str]) -> Optional[str]:
    import time as _time

    now = _time.monotonic()
    if base_url:
        cached = _VERSION_CACHE.get(base_url)
        if cached and (now - cached[0]) < _VERSION_TTL_SEC:
            return cached[1]
        ver = None
        try:
            resp = httpx.get(f"{base_url.rstrip('/')}/api/v3/version", timeout=3.0)
            if resp.status_code == 200:
                ver = resp.json().get("version")
        except Exception:
            ver = None
        if ver:
            _VERSION_CACHE[base_url] = (now, ver)
            return ver
    # Fall back to the image tag (e.g. edgexfoundry/core-data:4.0.0).
    if image and ":" in image:
        tag = image.rsplit(":", 1)[-1]
        if tag and tag != "latest":
            return tag
    return None


def _service_ping_url(spec: dict[str, Any]) -> Optional[str]:
    env_key = spec.get("ping_url_env")
    if env_key:
        val = os.environ.get(env_key, "").strip()
        return val or None
    port = spec.get("port")
    container = spec.get("container", "")
    if port and container:
        return f"http://{container}:{port}"
    return None


def _service_row(spec: dict[str, Any], stats: dict[str, dict[str, Any]]) -> tuple[dict[str, Any], dict[str, Any]]:
    """Build one Edge Runtime row (docker state + optional HTTP ping + stats)."""
    container = spec["container"]
    docker = _docker_status(container)
    row: dict[str, Any] = {
        "id": spec["id"],
        "label": spec["label"],
        "container": container,
        "port": spec.get("port"),
        "optional": bool(spec.get("optional")),
        "group": spec.get("group", "edgex"),
        "docker": docker,
    }
    ping_url = _service_ping_url(spec)
    if ping_url and spec.get("ping_path"):
        row["api"] = _ping_service(ping_url, spec["ping_path"])
    elif ping_url and spec["id"] in ("core-data", "core-metadata"):
        row["api"] = _ping_service(ping_url)
    else:
        row["api"] = None

    st = stats.get(container, {})
    row["cpu_pct"] = st.get("cpu_pct")
    row["mem_mb"] = st.get("mem_mb")
    row["started_at"] = docker.get("started_at")
    row["health"] = docker.get("health")
    # Only query version over HTTP for services that actually answered.
    ver_url = ping_url if (row["api"] and row["api"].get("ok")) else None
    row["version"] = _service_version(ver_url, docker.get("image"))

    row["ok"] = bool(docker.get("running")) and (
        row["api"] is None or row["api"].get("ok") is not False
    )
    if docker.get("status") == "missing" and spec.get("optional"):
        row["ok"] = None
    return row, docker


def _discover_extra_containers(exclude: set[str]) -> list[dict[str, Any]]:
    """List running SenseL/IDS containers not in the curated EdgeX list.

    Uses a live ``docker ps`` so any enabled overlay (Suricata, Snort, lab
    publishers, …) surfaces in Edge Runtime without a code change.
    """
    if not Path("/var/run/docker.sock").exists():
        return []
    try:
        proc = subprocess.run(
            ["docker", "ps", "--format", "{{.Names}}"],
            capture_output=True,
            text=True,
            timeout=8,
        )
    except Exception:
        return []
    if proc.returncode != 0:
        return []
    out: list[dict[str, Any]] = []
    for line in proc.stdout.splitlines():
        name = line.strip()
        if not name or name in exclude or not _is_sensel_container(name):
            continue
        out.append(
            {
                "id": name,
                "label": _SENSEL_LABELS.get(name, name),
                "container": name,
                "port": None,
                "optional": True,
                "group": "sensel",
            }
        )
    return sorted(out, key=lambda s: s["label"])


def build_platform() -> dict[str, Any]:
    services_out: list[dict[str, Any]] = []
    cores_ok = 0
    cores_total = 0
    stats = _docker_stats_all()

    for spec in _EDGEX_SERVICES:
        row, docker = _service_row(spec, stats)
        if spec["id"] in ("core-data", "core-metadata"):
            cores_total += 1
            if (row.get("api") and row["api"].get("ok")) and docker.get("running"):
                cores_ok += 1
        services_out.append(row)

    # SenseL edge-stack / NDR engines (Suricata, Snort, packet-sensor, …),
    # discovered live so the runtime view reflects every enabled container.
    curated = {spec["container"] for spec in _EDGEX_SERVICES}
    for spec in _discover_extra_containers(curated):
        row, _docker = _service_row(spec, stats)
        services_out.append(row)

    meta_ping = _ping_service(_metadata_url())
    data_ping = _ping_service(_data_url())

    return {
        "reachable": meta_ping.get("ok") and data_ping.get("ok"),
        "metadata_ping": meta_ping,
        "data_ping": data_ping,
        "cores_healthy": cores_ok == cores_total and cores_total > 0,
        "services": services_out,
        "message_bus": {
            "edgex_internal": {"host": "edgex-mqtt-broker", "port": 1883},
            "local_features": {"host": "local-mqtt", "port": 1883, "note": "Packet Sensor → device-mqtt"},
        },
        "ui_url": os.environ.get("EDGEX_UI_URL", "http://127.0.0.1:4000"),
        "metadata_url": _metadata_url(),
        "data_url": _data_url(),
    }


def _parse_device_names_from_yaml(path: Path) -> list[str]:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return []
    return re.findall(r"^\s+-\s+name:\s+(\S+)\s*$", text, re.MULTILINE)


def _devices_from_config_files() -> list[dict[str, Any]]:
    devices_dir = _devices_config_dir()
    if not devices_dir.is_dir():
        return []
    out: list[dict[str, Any]] = []
    for yml in sorted(devices_dir.glob("*.yaml")) + sorted(devices_dir.glob("*.yml")):
        for name in _parse_device_names_from_yaml(yml):
            out.append(
                {
                    "name": name,
                    "profileName": "",
                    "description": f"(config file {yml.name})",
                    "operatingState": "UNKNOWN",
                    "adminState": "UNKNOWN",
                    "protocol": "—",
                    "endpoint": "—",
                    "serviceName": "",
                    "labels": [],
                    "source": "config",
                    "last_event_at": None,
                    "readings_count_hint": None,
                }
            )
    return out


def _device_protocol(device: dict[str, Any]) -> str:
    protocols = device.get("protocols")
    if isinstance(protocols, dict) and protocols:
        key = next(iter(protocols.keys()))
        return key.replace("-", " ").upper()
    svc = str(device.get("serviceName") or "")
    if "modbus" in svc.lower():
        return "MODBUS TCP"
    if "mqtt" in svc.lower():
        return "MQTT"
    return "—"


def _device_endpoint(device: dict[str, Any]) -> str:
    protocols = device.get("protocols")
    if not isinstance(protocols, dict):
        return "—"
    for proto in protocols.values():
        if not isinstance(proto, dict):
            continue
        host = proto.get("Address") or proto.get("Host") or ""
        port = proto.get("Port") or ""
        if host and port:
            return f"{host}:{port}"
        if host:
            return str(host)
    return "—"


def _normalize_device(raw: dict[str, Any], *, source: str = "metadata") -> dict[str, Any]:
    return {
        "name": raw.get("name") or "",
        "profileName": raw.get("profileName") or "",
        "description": raw.get("description") or "",
        "operatingState": raw.get("operatingState") or "UNKNOWN",
        "adminState": raw.get("adminState") or "UNKNOWN",
        "protocol": _device_protocol(raw),
        "endpoint": _device_endpoint(raw),
        "serviceName": raw.get("serviceName") or "",
        "labels": raw.get("labels") or [],
        "source": source,
        "last_event_at": None,
        "readings_count_hint": None,
    }


def _fetch_metadata_devices() -> tuple[list[dict[str, Any]], Optional[str]]:
    url = f"{_metadata_url()}/api/v3/device/all"
    try:
        resp = httpx.get(url, timeout=5.0)
        if resp.status_code != 200:
            return [], f"metadata HTTP {resp.status_code}"
        payload = resp.json()
        raw_list = _unwrap_list(payload, "devices")
        return [_normalize_device(d) for d in raw_list if isinstance(d, dict)], None
    except Exception as exc:
        return [], str(exc)[:200]


def _latest_event_time(device_name: str) -> Optional[str]:
    url = f"{_data_url()}/api/v3/event/device/name/{device_name}"
    try:
        resp = httpx.get(url, params={"limit": 1}, timeout=4.0)
        if resp.status_code != 200:
            return None
        events = _unwrap_list(resp.json(), "events", "event")
        if not events:
            return None
        ev = events[0]
        if not isinstance(ev, dict):
            return None
        return ev.get("origin") or ev.get("created")
    except Exception:
        return None


def list_devices(*, enrich_telemetry: bool = True) -> dict[str, Any]:
    devices, err = _fetch_metadata_devices()
    source = "metadata"
    if not devices:
        devices = _devices_from_config_files()
        source = "config" if devices else "none"

    if enrich_telemetry and devices and err is None:
        for d in devices:
            if d.get("name"):
                d["last_event_at"] = _latest_event_time(d["name"])

    online = sum(
        1
        for d in devices
        if str(d.get("operatingState", "")).upper() == "UP"
    )
    return {
        "count": len(devices),
        "online": online,
        "source": source,
        "metadata_error": err,
        "devices": devices,
    }


def get_device_readings(device_name: str, limit: int = 10) -> dict[str, Any]:
    safe_limit = max(1, min(limit, 50))
    url = f"{_data_url()}/api/v3/event/device/name/{device_name}"
    try:
        resp = httpx.get(url, params={"limit": safe_limit}, timeout=6.0)
        if resp.status_code != 200:
            return {
                "device": device_name,
                "ok": False,
                "error": f"core-data HTTP {resp.status_code}",
                "events": [],
                "readings": [],
            }
        events = _unwrap_list(resp.json(), "events", "event")
        readings: list[dict[str, Any]] = []
        for ev in events:
            if not isinstance(ev, dict):
                continue
            for rd in ev.get("readings") or []:
                if isinstance(rd, dict):
                    readings.append(
                        {
                            "resourceName": rd.get("resourceName"),
                            "value": rd.get("value"),
                            "valueType": rd.get("valueType"),
                            "origin": rd.get("origin") or ev.get("origin"),
                        }
                    )
        return {
            "device": device_name,
            "ok": True,
            "events": events,
            "readings": readings[: safe_limit * 5],
        }
    except Exception as exc:
        return {
            "device": device_name,
            "ok": False,
            "error": str(exc)[:200],
            "events": [],
            "readings": [],
        }


def build_protocol_matrix() -> dict[str, Any]:
    platform = build_platform()
    device_payload = list_devices(enrich_telemetry=False)
    devices = device_payload.get("devices") or []

    protocols_in_use: set[str] = set()
    for d in devices:
        p = str(d.get("protocol") or "").lower()
        if "modbus" in p:
            protocols_in_use.add("modbus")
        if "mqtt" in p:
            protocols_in_use.add("mqtt")
        if "opc" in p or "ua" in p:
            protocols_in_use.add("opcua")
        if "s7" in p:
            protocols_in_use.add("s7")

    svc_running = {
        s["id"]: (s.get("docker") or {}).get("running")
        for s in platform.get("services") or []
    }

    matrix: list[dict[str, Any]] = []
    for spec in _PROTOCOL_MATRIX:
        pid = spec["id"]
        enabled = False
        reason = ""
        if pid == "modbus":
            enabled = bool(svc_running.get("device-modbus")) and ("modbus" in protocols_in_use or devices)
            reason = "device-modbus + relay/simulator" if enabled else "未部署或無設備"
        elif pid == "mqtt":
            enabled = bool(svc_running.get("device-mqtt")) and ("mqtt" in protocols_in_use or any(
                "mqtt" in str(d.get("protocol", "")).lower() for d in devices
            ))
            reason = "device-mqtt + local-mqtt" if enabled else "未部署"
        elif pid == "iec61850":
            ps = _docker_status(os.environ.get("PACKET_SENSOR_CONTAINER", "sensel-packet-sensor"))
            enabled = ps.get("running") is True
            reason = "packet-sensor mirror 被動擷取" if enabled else "packet-sensor 未運行"
        elif pid == "opcua":
            running = bool(svc_running.get("device-opc-ua"))
            enabled = running and ("opcua" in protocols_in_use or bool(devices))
            reason = "device-opc-ua 已啟動" if running else "請啟用 Phase 2 profile"
        elif pid == "s7":
            running = bool(svc_running.get("device-s7"))
            enabled = running and ("s7" in protocols_in_use or bool(devices))
            reason = "device-s7 已啟動" if running else "請啟用 Phase 2 profile"
        else:
            enabled = False
            reason = "未支援"
        matrix.append({**spec, "enabled": enabled, "reason": reason})

    return {"protocols": matrix, "device_count": len(devices)}


def restart_edgex_container(container: str) -> tuple[bool, str]:
    # Restarting the console itself would kill the request mid-flight.
    if container == "sensel-edge-console":
        return False, "Refusing to restart the Edge Console itself"
    if container not in _RESTARTABLE and not _container_allowed(container):
        return False, f"Container not allowed: {container}"
    if os.environ.get("EDGE_CONSOLE_DOCKER_RESTART", "").lower() not in ("1", "true", "yes"):
        return False, f"Docker restart disabled; restart {container} manually"
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
        return True, f"Restarted {container}"
    except subprocess.CalledProcessError as exc:
        return False, (exc.stderr or exc.stdout or str(exc))[:300]
    except FileNotFoundError:
        return False, "docker CLI not available"


def start_edgex_container(container: str) -> tuple[bool, str]:
    if container not in _RESTARTABLE and not _container_allowed(container):
        return False, f"Container not allowed: {container}"
    if os.environ.get("EDGE_CONSOLE_DOCKER_RESTART", "").lower() not in ("1", "true", "yes"):
        return False, f"Docker control disabled; start {container} manually"
    if not Path("/var/run/docker.sock").exists():
        return False, "Docker socket not mounted"
    try:
        subprocess.run(
            ["docker", "start", container],
            check=True,
            capture_output=True,
            text=True,
            timeout=90,
        )
        return True, f"Started {container}"
    except subprocess.CalledProcessError as exc:
        return False, (exc.stderr or exc.stdout or str(exc))[:300]
    except FileNotFoundError:
        return False, "docker CLI not available"


# Logs are read-only, so allow any EdgeX/SenseL edge-stack container (no
# restart gate). Curated EdgeX names plus the discovered-container safelist.
_LOGGABLE = {spec["container"] for spec in _EDGEX_SERVICES}


def container_logs(container: str, tail: int = 200) -> tuple[bool, str]:
    if container not in _LOGGABLE and not _container_allowed(container):
        return False, f"Container not allowed: {container}"
    if not Path("/var/run/docker.sock").exists():
        return False, "Docker socket not mounted"
    try:
        proc = subprocess.run(
            ["docker", "logs", "--tail", str(max(1, min(tail, 1000))), container],
            capture_output=True,
            text=True,
            timeout=15,
        )
        if proc.returncode != 0:
            return False, (proc.stderr or proc.stdout or "docker logs failed")[:300]
        # docker logs writes to both stdout and stderr; merge and cap size.
        return True, (proc.stdout + proc.stderr)[-20000:]
    except FileNotFoundError:
        return False, "docker CLI not available"
    except Exception as exc:
        return False, str(exc)[:300]
