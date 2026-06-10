"""EdgeX device config CRUD, connectivity probes, Phase 2 service control."""

from __future__ import annotations

import os
import re
import socket
import subprocess
from pathlib import Path
from typing import Any, Optional

from src.edgex_service import _docker_status, restart_edgex_container

_NAME_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9_-]{0,62}$")

_PROTOCOL_SPECS: dict[str, dict[str, Any]] = {
    "modbus": {
        "profile": "ModbusRelay",
        "service": "device-modbus",
        "container": "edgex-device-modbus",
        "file_prefix": "modbus",
    },
    "mqtt": {
        "profile": "FeatureSummary",
        "service": "device-mqtt",
        "container": "edgex-device-mqtt",
        "file_prefix": "mqtt",
    },
    "opcua": {
        "profile": "OPCUASample",
        "service": "device-opc-ua",
        "container": "edgex-device-opc-ua",
        "file_prefix": "opcua",
        "phase2": True,
    },
    "s7": {
        "profile": "S7Sample",
        "service": "device-s7",
        "container": "edgex-device-s7",
        "file_prefix": "s7",
        "phase2": True,
    },
}

_PHASE2_CONTAINERS = ("edgex-device-opc-ua", "edgex-device-s7")


def _devices_dir() -> Path:
    return Path(os.environ.get("EDGEX_DEVICES_DIR", "/config/edgex/devices"))


def _profiles_dir() -> Path:
    return Path(os.environ.get("EDGEX_PROFILES_DIR", "/config/edgex/profiles"))


def _validate_name(name: str) -> str:
    n = (name or "").strip()
    if not _NAME_RE.match(n):
        raise ValueError("設備名稱須為英數、-、_，且以字母開頭")
    return n


def list_config_devices() -> dict[str, Any]:
    devices_dir = _devices_dir()
    items: list[dict[str, Any]] = []
    if not devices_dir.is_dir():
        return {"devices": [], "config_dir": str(devices_dir), "writable": False}
    for path in sorted(devices_dir.glob("*.yaml")) + sorted(devices_dir.glob("*.yml")):
        if path.name.endswith(".example.yaml") or path.name.endswith(".example.yml"):
            continue
        for name in _parse_names(path):
            items.append({"name": name, "file": path.name, "path": str(path)})
    return {
        "devices": items,
        "config_dir": str(devices_dir),
        "writable": os.access(devices_dir, os.W_OK),
    }


def _parse_names(path: Path) -> list[str]:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return []
    return re.findall(r"^\s+-\s+name:\s+(\S+)\s*$", text, re.MULTILINE)


def get_config_device(name: str) -> dict[str, Any]:
    safe = _validate_name(name)
    devices_dir = _devices_dir()
    for path in devices_dir.glob("*.yaml"):
        text = path.read_text(encoding="utf-8")
        if re.search(rf"^\s+-\s+name:\s+{re.escape(safe)}\s*$", text, re.MULTILINE):
            return {"ok": True, "name": safe, "file": path.name, "content": text}
    return {"ok": False, "error": f"設備 {safe} 不在 config 檔案中"}


def _device_yaml_modbus(name: str, host: str, port: int, unit_id: int, interval: str) -> str:
    return f"""# Managed by SenseL EdgeX Console
deviceList:
  - name: {name}
    profileName: ModbusRelay
    description: Modbus TCP device
    adminState: UNLOCKED
    operatingState: UP
    labels: [ot, modbus]
    protocols:
      modbus-tcp:
        Address: {host}
        Port: "{port}"
        UnitID: "{unit_id}"
        Timeout: "5"
        IdleTimeout: "5"
    autoEvents:
      - interval: {interval}
        onChange: false
        sourceName: Status
"""


def _device_yaml_mqtt(name: str, host: str, port: int, interval: str) -> str:
    return f"""# Managed by SenseL EdgeX Console
deviceList:
  - name: {name}
    profileName: FeatureSummary
    description: MQTT feature bridge
    adminState: UNLOCKED
    operatingState: UP
    serviceName: device-mqtt
    labels: [ot, mqtt]
    protocols:
      mqtt:
        CommandTopic: command/{name}
        Host: {host}
        Port: "{port}"
        ClientId: edgex-mqtt-{name}
        QoS: "0"
    autoEvents:
      - interval: {interval}
        onChange: false
        sourceName: FeatureSummary
"""


def _device_yaml_opcua(name: str, endpoint: str, interval: str) -> str:
    return f"""# Managed by SenseL EdgeX Console
deviceList:
  - name: {name}
    profileName: OPCUASample
    description: OPC UA device
    adminState: UNLOCKED
    operatingState: UP
    serviceName: device-opc-ua
    labels: [ot, opcua]
    protocols:
      opc-ua:
        Endpoint: "{endpoint}"
        SecurityPolicy: "None"
        SecurityMode: "None"
        AuthMode: "Anonymous"
    autoEvents:
      - interval: {interval}
        onChange: false
        sourceName: AllResources
"""


def _device_yaml_s7(name: str, host: str, port: int, rack: int, slot: int, interval: str) -> str:
    return f"""# Managed by SenseL EdgeX Console
deviceList:
  - name: {name}
    profileName: S7Sample
    description: Siemens S7 PLC
    adminState: UNLOCKED
    operatingState: UP
    serviceName: device-s7
    labels: [ot, s7]
    protocols:
      s7:
        Host: "{host}"
        Port: "{port}"
        Rack: "{rack}"
        Slot: "{slot}"
        Timeout: "30"
        IdleTimeout: "30"
    autoEvents:
      - interval: {interval}
        onChange: false
        sourceName: AllResource
"""


def upsert_config_device(payload: dict[str, Any]) -> dict[str, Any]:
    protocol = str(payload.get("protocol") or "").lower()
    spec = _PROTOCOL_SPECS.get(protocol)
    if not spec:
        raise ValueError(f"不支援的協定: {protocol}")

    name = _validate_name(str(payload.get("name") or ""))
    interval = str(payload.get("interval") or "10s")
    devices_dir = _devices_dir()
    if not devices_dir.is_dir():
        raise ValueError(f"config 目錄不存在: {devices_dir}")
    if not os.access(devices_dir, os.W_OK):
        raise ValueError("config 目錄唯讀，無法寫入設備")

    if protocol == "modbus":
        host = str(payload.get("host") or "modbus-simulator")
        port = int(payload.get("port") or 1502)
        unit_id = int(payload.get("unit_id") or 1)
        content = _device_yaml_modbus(name, host, port, unit_id, interval)
    elif protocol == "mqtt":
        host = str(payload.get("host") or "local-mqtt")
        port = int(payload.get("port") or 1883)
        content = _device_yaml_mqtt(name, host, port, interval)
    elif protocol == "opcua":
        host = str(payload.get("host") or "127.0.0.1")
        port = int(payload.get("port") or 4840)
        endpoint = str(payload.get("endpoint") or f"opc.tcp://{host}:{port}")
        content = _device_yaml_opcua(name, endpoint, interval)
    elif protocol == "s7":
        host = str(payload.get("host") or "192.168.1.60")
        port = int(payload.get("port") or 102)
        rack = int(payload.get("rack") or 0)
        slot = int(payload.get("slot") or 1)
        content = _device_yaml_s7(name, host, port, rack, slot, interval)
    else:
        raise ValueError("protocol handler missing")

    filename = f"{spec['file_prefix']}-{name}.yaml"
    path = devices_dir / filename
    path.write_text(content, encoding="utf-8")

    restart_target = spec.get("container")
    restarted = None
    if restart_target and _docker_status(restart_target).get("running"):
        ok, msg = restart_edgex_container(restart_target)
        restarted = {"ok": ok, "message": msg}

    return {
        "ok": True,
        "name": name,
        "protocol": protocol,
        "file": filename,
        "service": spec["service"],
        "restart": restarted,
    }


def delete_config_device(name: str) -> dict[str, Any]:
    safe = _validate_name(name)
    devices_dir = _devices_dir()
    removed: Optional[str] = None
    for path in list(devices_dir.glob("*.yaml")) + list(devices_dir.glob("*.yml")):
        text = path.read_text(encoding="utf-8")
        if not re.search(rf"^\s+-\s+name:\s+{re.escape(safe)}\s*$", text, re.MULTILINE):
            continue
        if len(_parse_names(path)) <= 1:
            path.unlink(missing_ok=True)
            removed = path.name
        else:
            raise ValueError("多設備共用檔案，請手動編輯 YAML")
    if not removed:
        return {"ok": False, "error": f"找不到設備 {safe}"}
    return {"ok": True, "removed": removed, "name": safe}


def probe_connectivity(protocol: str, host: str, port: int, timeout: float = 3.0) -> dict[str, Any]:
    protocol = protocol.lower()
    host = host.strip()
    port = int(port)
    if not host:
        return {"ok": False, "error": "host 必填"}

    if protocol in ("iec61850", "goose", "mms"):
        ps = _docker_status(os.environ.get("PACKET_SENSOR_CONTAINER", "sensel-packet-sensor"))
        return {
            "ok": ps.get("running") is True,
            "protocol": protocol,
            "detail": "packet-sensor mirror" if ps.get("running") else "packet-sensor 未運行",
        }

    try:
        with socket.create_connection((host, port), timeout=timeout):
            return {"ok": True, "protocol": protocol, "host": host, "port": port, "detail": "TCP 連線成功"}
    except OSError as exc:
        return {"ok": False, "protocol": protocol, "host": host, "port": port, "error": str(exc)[:200]}


def get_wizard_templates() -> dict[str, Any]:
    templates = []
    for pid, spec in _PROTOCOL_SPECS.items():
        docker = _docker_status(spec["container"]) if spec.get("container") else {}
        templates.append(
            {
                "id": pid,
                "label": pid.upper() if pid != "opcua" else "OPC UA",
                "profileName": spec["profile"],
                "serviceName": spec["service"],
                "phase": 2 if spec.get("phase2") else 1,
                "container": spec.get("container"),
                "running": docker.get("running"),
            }
        )
    return {"templates": templates}


def phase2_status() -> dict[str, Any]:
    services = []
    any_running = False
    for c in _PHASE2_CONTAINERS:
        st = _docker_status(c)
        if st.get("running"):
            any_running = True
        services.append({"container": c, **st})
    return {
        "enabled": any_running,
        "services": services,
        "compose_hint": "docker compose --profile phase2 up -d device-opc-ua device-s7",
    }


def enable_phase2_services() -> dict[str, Any]:
    if os.environ.get("EDGE_CONSOLE_DOCKER_RESTART", "").lower() not in ("1", "true", "yes"):
        return {"ok": False, "error": "Docker 控制已停用"}
    sock = Path("/var/run/docker.sock")
    if not sock.exists():
        return {"ok": False, "error": "未掛載 Docker socket"}

    project_dir = os.environ.get("EDGEX_COMPOSE_PROJECT_DIR", "/project")
    compose_files = os.environ.get(
        "EDGEX_COMPOSE_FILES",
        "-f docker-compose.yml -f docker-compose.pi4.yml -f docker-compose.lab-61850.yml -f docker-compose.pi-lab.yml",
    )
    cmd = (
        f"cd {project_dir} && docker compose {compose_files} --profile phase2 "
        "up -d device-opc-ua device-s7"
    )
    try:
        proc = subprocess.run(
            ["bash", "-lc", cmd],
            capture_output=True,
            text=True,
            timeout=180,
        )
        if proc.returncode != 0:
            return {"ok": False, "error": (proc.stderr or proc.stdout or "compose failed")[:400]}
        return {"ok": True, "message": "Phase 2 服務已啟動", "stdout": (proc.stdout or "")[-500:]}
    except Exception as exc:
        return {"ok": False, "error": str(exc)[:200]}


def run_connectivity_suite(hosts: Optional[dict[str, Any]] = None) -> dict[str, Any]:
    """One-click diagnostics for common lab endpoints."""
    checks = []
    defaults = [
        ("modbus", "modbus-simulator", 1502),
        ("mqtt", "local-mqtt", 1883),
    ]
    if hosts:
        for item in hosts.get("checks") or []:
            checks.append(probe_connectivity(item.get("protocol", "tcp"), item["host"], int(item["port"])))
    else:
        for proto, h, p in defaults:
            checks.append(probe_connectivity(proto, h, p))
    opc = _docker_status("edgex-device-opc-ua")
    s7 = _docker_status("edgex-device-s7")
    return {
        "checks": checks,
        "phase2": phase2_status(),
        "opcua_service": opc,
        "s7_service": s7,
    }
