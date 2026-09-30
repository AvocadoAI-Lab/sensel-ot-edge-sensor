"""Wi-Fi management for the Edge Console via the host NetworkManager.

The console container mounts the host's system D-Bus socket
(`/run/dbus/system_bus_socket`) and ships the `nmcli` client, so it can drive
the host's NetworkManager (scan / connect / radio) without a separate host
agent. All operations are gated by ``EDGE_CONSOLE_WIFI_ADMIN`` and run nmcli
with argv lists (no shell) so SSIDs/passwords cannot inject commands.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any, Optional

_SSID_MAX = 64
_PASSWORD_MAX = 128
# How many recently-used Wi-Fi APs to remember for auto-reconnect on reboot.
# NetworkManager auto-connects saved profiles on boot; we keep only the most
# recent N and assign descending autoconnect-priority so the appliance tries the
# most-recently-connected AP first, then the next, etc.
_WIFI_HISTORY_KEEP = 3
_WIFI_PRIORITY_BASE = 100
# Operator-pinned fallback APs (e.g. phone hotspot, switch Wi-Fi) live in a
# higher priority band so they always outrank the recency list, and they are
# NEVER pruned — so the appliance can always fall back to them when offline.
# Their order within the band is set explicitly from System Maintenance.
_WIFI_PINNED_BASE = 200
_WIFI_PINNED_MAX = 10
_PINNED_FILE = Path(os.environ.get("WIFI_PRIORITY_FILE", "/data/agent/wifi-priority.json"))
# Reject control chars in SSID/password (defence in depth; argv already avoids shell).
_CTRL_RE = re.compile(r"[\x00-\x1f\x7f]")


def _load_pinned() -> list[str]:
    """Ordered list of operator-pinned fallback SSIDs (highest priority first)."""
    try:
        data = json.loads(_PINNED_FILE.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return []
    order = data.get("order") if isinstance(data, dict) else data
    if not isinstance(order, list):
        return []
    return [s for s in order if isinstance(s, str) and s]


def _save_pinned(order: list[str]) -> None:
    try:
        _PINNED_FILE.parent.mkdir(parents=True, exist_ok=True)
        _PINNED_FILE.write_text(json.dumps({"order": order}, ensure_ascii=False), encoding="utf-8")
    except OSError:
        pass


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


def _saved_wifi_connections() -> list[dict[str, Any]]:
    """Saved Wi-Fi connection profiles with their last-activation timestamp.

    Returns rows ``{name, uuid, timestamp}`` (timestamp = epoch seconds of last
    successful activation; 0 if never), unsorted.
    """
    try:
        proc = _nmcli(["-t", "-f", "NAME,UUID,TYPE,TIMESTAMP", "connection", "show"], timeout=10.0)
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return []
    if proc.returncode != 0:
        return []
    rows: list[dict[str, Any]] = []
    for line in proc.stdout.splitlines():
        f = _split_terse(line)
        if len(f) >= 4 and f[2] == "802-11-wireless":
            try:
                ts = int(f[3])
            except ValueError:
                ts = 0
            rows.append({"name": f[0], "uuid": f[1], "timestamp": ts})
    return rows


def promote_and_prune_wifi(active_ssid: str, keep: int = _WIFI_HISTORY_KEEP) -> dict[str, Any]:
    """Keep only the ``keep`` most-recently-used Wi-Fi APs and order their
    auto-reconnect priority by recency (most recent tried first on reboot).

    Called after a successful connect. ``active_ssid`` is forced to the front so
    it always survives pruning and gets the highest priority, even if NM has not
    yet flushed its activation timestamp.
    """
    if keep <= 0:
        return {"kept": [], "deleted": [], "pinned": []}
    conns = _saved_wifi_connections()
    if not conns:
        return {"kept": [], "deleted": [], "pinned": []}
    # Operator-pinned fallback APs are never re-prioritised here (they keep their
    # high pinned band) and are never pruned.
    pinned = set(_load_pinned())
    non_pinned = [c for c in conns if c["name"] not in pinned]
    non_pinned.sort(key=lambda c: (c["name"] != active_ssid, -c["timestamp"]))
    kept, pruned = non_pinned[:keep], non_pinned[keep:]
    for i, c in enumerate(kept):
        prio = _WIFI_PRIORITY_BASE - i
        try:
            _nmcli([
                "connection", "modify", c["uuid"],
                "connection.autoconnect", "yes",
                "connection.autoconnect-priority", str(prio),
            ], timeout=10.0)
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass
    deleted: list[str] = []
    for c in pruned:
        try:
            r = _nmcli(["connection", "delete", "uuid", c["uuid"]], timeout=10.0)
            if r.returncode == 0:
                deleted.append(c["name"])
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass
    return {
        "kept": [c["name"] for c in kept],
        "deleted": deleted,
        "pinned": [c["name"] for c in conns if c["name"] in pinned],
    }


def pinned_networks() -> list[dict[str, Any]]:
    """Operator-pinned fallback APs in tried-first order (for UI + watchdog)."""
    saved = {c["name"]: c for c in _saved_wifi_connections()}
    out: list[dict[str, Any]] = []
    for idx, ssid in enumerate(_load_pinned()):
        if ssid in saved:
            out.append({
                "ssid": ssid,
                "order": idx + 1,
                "last_connected_ts": saved[ssid]["timestamp"] or None,
            })
    return out


def set_wifi_priority(order: list[Any]) -> dict[str, Any]:
    """Set the explicit offline-fallback order of pinned APs (highest first).

    ``order`` is a list of SSIDs; only SSIDs that already have a saved Wi-Fi
    profile are accepted. Pinned APs get a high autoconnect-priority band so the
    appliance tries them first when offline, and they are exempt from pruning.
    SSIDs removed from the list fall back to the recency-managed band.
    """
    if not (wifi_admin_enabled() and nmcli_available()):
        return {"ok": False, "status": 403, "error": "Wi-Fi 控制未啟用"}
    if not isinstance(order, list):
        return {"ok": False, "status": 400, "error": "順序格式無效"}
    cleaned: list[str] = []
    for s in order:
        if not isinstance(s, str):
            continue
        s = s.strip()
        if not s or len(s) > _SSID_MAX or _CTRL_RE.search(s):
            continue
        if s not in cleaned:
            cleaned.append(s)
    if len(cleaned) > _WIFI_PINNED_MAX:
        return {"ok": False, "status": 400, "error": f"釘選數量上限為 {_WIFI_PINNED_MAX}"}

    saved = {c["name"]: c for c in _saved_wifi_connections()}
    new_order = [s for s in cleaned if s in saved]
    old_order = _load_pinned()

    for i, ssid in enumerate(new_order):
        prio = _WIFI_PINNED_BASE - i
        try:
            _nmcli([
                "connection", "modify", saved[ssid]["uuid"],
                "connection.autoconnect", "yes",
                "connection.autoconnect-priority", str(prio),
            ], timeout=10.0)
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass
    # SSIDs that were unpinned drop back to the default (recency) band.
    for ssid in old_order:
        if ssid not in new_order and ssid in saved:
            try:
                _nmcli([
                    "connection", "modify", saved[ssid]["uuid"],
                    "connection.autoconnect-priority", "0",
                ], timeout=10.0)
            except (FileNotFoundError, subprocess.TimeoutExpired):
                pass

    _save_pinned(new_order)
    return {"ok": True, "pinned": pinned_networks(), "message": "已更新離線自動重連順序"}


def known_networks(keep: Optional[int] = None) -> list[dict[str, Any]]:
    """All remembered APs, most-recently-used first, each flagged if pinned.

    ``keep`` optionally caps the count (None = all saved), so the UI can let the
    operator pin any remembered network as an offline fallback.
    """
    pinned = set(_load_pinned())
    conns = _saved_wifi_connections()
    conns.sort(key=lambda c: -c["timestamp"])
    rows = conns if keep is None else conns[:keep]
    out: list[dict[str, Any]] = []
    for idx, c in enumerate(rows):
        out.append({
            "ssid": c["name"],
            "last_connected_ts": c["timestamp"] or None,
            "order": idx + 1,
            "never_connected": c["timestamp"] == 0,
            "pinned": c["name"] in pinned,
        })
    return out


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
        # Remembered APs (most-recent first); each flagged if pinned as fallback.
        "known": known_networks(),
        # Operator-pinned offline-fallback order (tried first when offline).
        "pinned": pinned_networks(),
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
    # Remember this AP for boot-time auto-reconnect: keep the most-recent few and
    # order their priority by recency (this SSID first).
    history = promote_and_prune_wifi(ssid)
    return {"ok": True, "ssid": ssid, "message": f"已連線到 {ssid}", "history": history}


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
