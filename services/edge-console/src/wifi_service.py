"""Wi-Fi management for the Edge Console via the host NetworkManager.

The console container mounts the host's system D-Bus socket
(`/run/dbus/system_bus_socket`) and ships the `nmcli` client, so it can drive
the host's NetworkManager (scan / connect / radio) without a separate host
agent. All operations are gated by ``EDGE_CONSOLE_WIFI_ADMIN`` and run nmcli
with argv lists (no shell) so SSIDs/passwords cannot inject commands.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from typing import Any, Optional

_SSID_MAX = 64
_PASSWORD_MAX = 128
# Reject control chars in SSID/password (defence in depth; argv already avoids shell).
_CTRL_RE = re.compile(r"[\x00-\x1f\x7f]")


def wifi_admin_enabled() -> bool:
    return os.environ.get("EDGE_CONSOLE_WIFI_ADMIN", "").strip().lower() in ("1", "true", "yes")


def nmcli_available() -> bool:
    return shutil.which("nmcli") is not None


def _nmcli(args: list[str], timeout: float = 20.0) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["nmcli", *args],
        capture_output=True,
        text=True,
        timeout=timeout,
    )


def _split_terse(line: str) -> list[str]:
    """Split an nmcli `-t` terse line on unescaped ':' (nmcli escapes ':' and '\\')."""
    fields: list[str] = []
    cur: list[str] = []
    esc = False
    for ch in line:
        if esc:
            cur.append(ch)
            esc = False
        elif ch == "\\":
            esc = True
        elif ch == ":":
            fields.append("".join(cur))
            cur = []
        else:
            cur.append(ch)
    fields.append("".join(cur))
    return fields


def _wifi_devices() -> list[dict[str, str]]:
    """Return all Wi-Fi device rows: [{device, state, connection}, ...]."""
    try:
        proc = _nmcli(["-t", "-f", "DEVICE,TYPE,STATE,CONNECTION", "dev", "status"], timeout=10.0)
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return []
    if proc.returncode != 0:
        return []
    devices: list[dict[str, str]] = []
    for line in proc.stdout.splitlines():
        f = _split_terse(line)
        if len(f) >= 4 and f[1] == "wifi":
            devices.append({"device": f[0], "state": f[2], "connection": f[3]})
    return devices


def _wifi_device() -> Optional[dict[str, str]]:
    """Return the first Wi-Fi device row (back-compat helper)."""
    devices = _wifi_devices()
    return devices[0] if devices else None


def _device_connected(dev: dict[str, str]) -> bool:
    return dev.get("state", "").startswith("connected") and dev.get("connection") not in ("", "--", None)


def _active_connection_for(device: str) -> Optional[str]:
    """Return the active connection NAME bound to a device, or None."""
    try:
        proc = _nmcli(["-t", "-f", "NAME,DEVICE", "connection", "show", "--active"], timeout=10.0)
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return None
    if proc.returncode != 0:
        return None
    for line in proc.stdout.splitlines():
        f = _split_terse(line)
        if len(f) >= 2 and f[1] == device:
            return f[0]
    return None


def _connection_never_default(conn: str) -> bool:
    """True if the connection is configured NOT to carry the default route."""
    try:
        proc = _nmcli(["-t", "-f", "ipv4.never-default", "connection", "show", conn], timeout=10.0)
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False
    if proc.returncode != 0:
        return False
    parts = _split_terse(proc.stdout.strip())  # terse: "ipv4.never-default:yes"
    return parts[-1].strip().lower() == "yes" if parts else False


def _set_device_never_default(device: str, never_default: bool) -> bool:
    """Set ipv4/ipv6 never-default on a device's active connection and reapply it."""
    conn = _active_connection_for(device)
    if not conn:
        return False
    val = "yes" if never_default else "no"
    try:
        mod = _nmcli(
            ["connection", "modify", conn, "ipv4.never-default", val, "ipv6.never-default", val],
            timeout=15.0,
        )
        if mod.returncode != 0:
            return False
        _nmcli(["connection", "up", conn], timeout=40.0)
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False
    return True


def _has_other_primary(exclude: str) -> bool:
    """True if a connected Wi-Fi device other than `exclude` owns the default route."""
    for d in _wifi_devices():
        dev = d["device"]
        if dev == exclude or not _device_connected(d):
            continue
        conn = _active_connection_for(dev)
        if conn and not _connection_never_default(conn):
            return True
    return False


def radio_on() -> Optional[bool]:
    try:
        proc = _nmcli(["radio", "wifi"], timeout=10.0)
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return None
    if proc.returncode != 0:
        return None
    return proc.stdout.strip().lower() == "enabled"


def set_radio(on: bool) -> dict[str, Any]:
    if not (wifi_admin_enabled() and nmcli_available()):
        return {"ok": False, "status": 403, "error": "Wi-Fi 控制未啟用"}
    try:
        proc = _nmcli(["radio", "wifi", "on" if on else "off"], timeout=15.0)
    except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
        return {"ok": False, "status": 503, "error": f"nmcli 失敗：{exc}"}
    if proc.returncode != 0:
        return {"ok": False, "status": 502, "error": (proc.stderr or proc.stdout).strip()[:200]}
    return {"ok": True, "radio_on": on, "message": f"Wi-Fi 無線電已{'開啟' if on else '關閉'}"}


def scan(rescan: bool = True, iface: Optional[str] = None) -> list[dict[str, Any]]:
    """Return de-duplicated visible networks sorted by signal desc.

    When ``iface`` is given the scan is scoped to that wireless device, so each
    Wi-Fi card reports the networks it can actually see/connect to.
    """
    args = ["-t", "-f", "IN-USE,SSID,SIGNAL,SECURITY,FREQ", "dev", "wifi", "list"]
    if iface:
        args += ["ifname", iface]
    if rescan:
        args += ["--rescan", "yes"]
    try:
        proc = _nmcli(args, timeout=25.0)
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return []
    if proc.returncode != 0:
        return []
    best: dict[str, dict[str, Any]] = {}
    for line in proc.stdout.splitlines():
        f = _split_terse(line)
        if len(f) < 5:
            continue
        in_use, ssid, signal, security, freq = f[0], f[1], f[2], f[3], f[4]
        if not ssid:  # hidden network
            continue
        try:
            sig = int(signal)
        except ValueError:
            sig = 0
        sec = security.strip() or "open"
        freq_m = re.match(r"\s*(\d+)", freq or "")
        freq_mhz = int(freq_m.group(1)) if freq_m else 0
        row = {
            "ssid": ssid,
            "signal": sig,
            "security": sec,
            "open": sec == "open",
            "freq": freq_mhz or None,
            "band": "5G" if freq_mhz >= 4000 else "2.4G",
            "in_use": in_use.strip() == "*",
        }
        prev = best.get(ssid)
        if prev is None or sig > prev["signal"] or row["in_use"]:
            best[ssid] = row
    return sorted(best.values(), key=lambda r: (not r["in_use"], -r["signal"]))


def status(include_scan: bool = True, rescan: bool = False) -> dict[str, Any]:
    available = wifi_admin_enabled() and nmcli_available()
    if not available:
        return {
            "available": False,
            "reason": "Wi-Fi 控制未啟用或 nmcli 不存在",
            "radio_on": None,
            "interfaces": [],
            "networks": [],
        }
    on = radio_on()
    interfaces: list[dict[str, Any]] = []
    for d in _wifi_devices():
        dev = d["device"]
        connected = _device_connected(d)
        conn = _active_connection_for(dev) if connected else None
        is_primary = bool(connected and conn and not _connection_never_default(conn))
        interfaces.append({
            "device": dev,
            "state": d.get("state"),
            "connected": connected,
            "active_ssid": d.get("connection") if connected else None,
            "is_primary": is_primary,
            "networks": scan(rescan=rescan, iface=dev) if (on and include_scan) else [],
        })
    # Back-compat single-device view prefers the primary uplink.
    primary = next((i for i in interfaces if i["is_primary"]), interfaces[0] if interfaces else None)
    return {
        "available": True,
        "radio_on": on,
        "interfaces": interfaces,
        "device": primary["device"] if primary else None,
        "active_ssid": primary["active_ssid"] if primary else None,
        "networks": primary["networks"] if primary else [],
    }


def _validate_ssid(ssid: str) -> Optional[str]:
    if not ssid or not ssid.strip():
        return "SSID 不可為空"
    if len(ssid) > _SSID_MAX or _CTRL_RE.search(ssid):
        return "SSID 無效"
    return None


def connect(ssid: str, password: Optional[str] = None, iface: Optional[str] = None) -> dict[str, Any]:
    if not (wifi_admin_enabled() and nmcli_available()):
        return {"ok": False, "status": 403, "error": "Wi-Fi 控制未啟用"}
    err = _validate_ssid(ssid)
    if err:
        return {"ok": False, "status": 400, "error": err}
    if password is not None and (len(password) > _PASSWORD_MAX or _CTRL_RE.search(password)):
        return {"ok": False, "status": 400, "error": "密碼無效"}
    if iface is not None and not re.match(r"^[A-Za-z0-9][A-Za-z0-9_.@:-]{0,14}$", iface):
        return {"ok": False, "status": 400, "error": "介面名稱無效"}

    if radio_on() is False:
        r = set_radio(True)
        if not r.get("ok"):
            return r

    args = ["dev", "wifi", "connect", ssid]
    if password:
        args += ["password", password]
    if iface:
        args += ["ifname", iface]
    try:
        proc = _nmcli(args, timeout=50.0)
    except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
        return {"ok": False, "status": 504, "error": f"連線逾時：{exc}"}
    if proc.returncode != 0:
        detail = (proc.stderr or proc.stdout or "").strip()
        msg = "連線失敗"
        low = detail.lower()
        if "secrets were required" in low or "802-11-wireless-security" in low or "no key" in low:
            msg = "連線失敗：密碼錯誤或需要認證"
        elif "not found" in low or "no network" in low:
            msg = f"連線失敗：找不到 SSID {ssid}"
        return {"ok": False, "status": 502, "error": msg, "detail": detail[:200]}
    if iface:
        # Keep a single default route: a freshly connected card only becomes the
        # primary uplink if no other connected Wi-Fi card already owns it.
        # Otherwise mark it never-default so two cards don't fight over routing.
        _set_device_never_default(iface, never_default=_has_other_primary(exclude=iface))
    return {"ok": True, "ssid": ssid, "message": f"已連線到 {ssid}"}


def set_primary(iface: str) -> dict[str, Any]:
    """Make ``iface`` the primary uplink (owns default route); demote the rest."""
    if not (wifi_admin_enabled() and nmcli_available()):
        return {"ok": False, "status": 403, "error": "Wi-Fi 控制未啟用"}
    if not iface or not re.match(r"^[A-Za-z0-9][A-Za-z0-9_.@:-]{0,14}$", iface):
        return {"ok": False, "status": 400, "error": "介面名稱無效"}
    devices = _wifi_devices()
    target = next((d for d in devices if d["device"] == iface), None)
    if target is None:
        return {"ok": False, "status": 404, "error": f"找不到 Wi-Fi 介面 {iface}"}
    if not _device_connected(target):
        return {"ok": False, "status": 409, "error": f"{iface} 尚未連線，無法設為主要上行"}
    if not _set_device_never_default(iface, never_default=False):
        return {"ok": False, "status": 502, "error": "設定主要上行失敗"}
    for d in devices:
        dev = d["device"]
        if dev == iface or not _device_connected(d):
            continue
        _set_device_never_default(dev, never_default=True)
    return {"ok": True, "iface": iface, "message": f"已將 {iface} 設為主要上行"}


def disconnect(iface: Optional[str] = None) -> dict[str, Any]:
    if not (wifi_admin_enabled() and nmcli_available()):
        return {"ok": False, "status": 403, "error": "Wi-Fi 控制未啟用"}
    dev = iface
    if not dev:
        wd = _wifi_device()
        dev = wd.get("device") if wd else None
    if not dev or not re.match(r"^[A-Za-z0-9][A-Za-z0-9_.@:-]{0,14}$", dev):
        return {"ok": False, "status": 400, "error": "找不到 Wi-Fi 介面"}
    try:
        proc = _nmcli(["dev", "disconnect", dev], timeout=20.0)
    except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
        return {"ok": False, "status": 503, "error": f"nmcli 失敗：{exc}"}
    if proc.returncode != 0:
        return {"ok": False, "status": 502, "error": (proc.stderr or proc.stdout).strip()[:200]}
    return {"ok": True, "message": f"{dev} 已斷線"}
