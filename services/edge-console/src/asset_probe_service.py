"""Asset identity inventory: manual overrides + opt-in active probe.

Model/firmware cannot be derived passively. This module stores operator-entered
overrides (always available, zero risk) and the results of an opt-in active
probe (read-only Modbus FC43 + TCP fingerprint) run inside packet-sensor.

Precedence when merged into the asset inventory: manual > probe > (OUI vendor
/ mock) handled client-side.
"""

from __future__ import annotations

import ipaddress
import json
import os
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

_SENSOR_ASSETS_DIR = "/app/data/assets"


def _now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _agent_dir() -> Path:
    return Path(os.environ.get("DETECTION_POLICY_PATH", "/data/agent/detection-policy.json")).parent


def _assets_dir() -> Path:
    return Path(os.environ.get("ASSETS_DIR", "/data/assets"))


def _inventory_path() -> Path:
    return _agent_dir() / "asset-inventory.json"


def _container() -> str:
    return os.environ.get("PACKET_SENSOR_CONTAINER", "sensel-packet-sensor")


def active_probe_enabled() -> bool:
    return os.environ.get("EDGE_CONSOLE_ACTIVE_PROBE", "").lower() in ("1", "true", "yes")


def _read_json(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except (OSError, json.JSONDecodeError):
        return {}


def _atomic_write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, ensure_ascii=False, indent=2)
        os.replace(tmp, str(path))
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def _valid_ip(ip: str) -> bool:
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def get_inventory() -> dict[str, Any]:
    doc = _read_json(_inventory_path())
    entries = doc.get("entries") if isinstance(doc.get("entries"), dict) else {}
    return {"entries": entries, "active_probe_enabled": active_probe_enabled()}


def _save_entry(ip: str, patch: dict[str, Any]) -> dict[str, Any]:
    doc = _read_json(_inventory_path())
    entries = doc.get("entries") if isinstance(doc.get("entries"), dict) else {}
    entry = entries.get(ip) if isinstance(entries.get(ip), dict) else {}
    entry.update(patch)
    entry["updated_at"] = _now_iso()
    entries[ip] = entry
    doc["entries"] = entries
    _atomic_write_json(_inventory_path(), doc)
    return entry


def set_identity(ip: str, *, vendor: str | None, model: str | None, firmware: str | None) -> dict[str, Any]:
    if not _valid_ip(ip):
        return {"ok": False, "error": "IP 格式不正確", "status": 400}
    manual: dict[str, Any] = {}
    if vendor is not None:
        manual["vendor"] = vendor.strip() or None
    if model is not None:
        manual["model"] = model.strip() or None
    if firmware is not None:
        manual["firmware"] = firmware.strip() or None
    entry = _save_entry(ip, {"manual": manual})
    return {"ok": True, "ip": ip, "entry": entry}


def probe(ip: str) -> dict[str, Any]:
    if not active_probe_enabled():
        return {"ok": False, "error": "主動探測未啟用（設定 EDGE_CONSOLE_ACTIVE_PROBE=true 並重啟）", "status": 403}
    if not _valid_ip(ip):
        return {"ok": False, "error": "IP 格式不正確", "status": 400}
    if not Path("/var/run/docker.sock").exists():
        return {"ok": False, "error": "Docker socket 未掛載，無法在 packet-sensor 內探測", "status": 503}

    sensor_out = f"{_SENSOR_ASSETS_DIR}/probe/{ip}.json"
    cmd = ["docker", "exec", _container(), "python", "-m", "src.probe.device_probe", "--ip", ip, "--out", sensor_out]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
    except subprocess.TimeoutExpired:
        return {"ok": False, "error": "探測逾時", "status": 504}
    except FileNotFoundError:
        return {"ok": False, "error": "docker CLI 不可用", "status": 503}
    if proc.returncode != 0:
        detail = (proc.stderr or proc.stdout or "").strip()[-400:]
        return {"ok": False, "error": f"探測失敗: {detail}", "status": 500}

    result = _read_json(_assets_dir() / "probe" / f"{ip}.json")
    if not result:
        return {"ok": False, "error": "探測完成但找不到結果", "status": 500}
    identity = result.get("identity") if isinstance(result.get("identity"), dict) else {}
    entry = _save_entry(ip, {
        "probe": {
            "vendor": identity.get("vendor"),
            "model": identity.get("model"),
            "firmware": identity.get("firmware"),
            "open_ports": result.get("open_ports") or [],
            "reachable": result.get("reachable", False),
            "identity_source": result.get("identity_source"),
            "probed_at": result.get("probed_at"),
        },
    })
    return {"ok": True, "ip": ip, "entry": entry, "probe": result}
