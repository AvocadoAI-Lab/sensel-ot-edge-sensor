"""Host network interface inventory for the Edge Console "進階" page.

The Edge Console container runs on Docker bridge networks, so it cannot see the
appliance's real wired/wireless NICs from its own network namespace. The
packet-sensor container runs with ``network_mode: host`` (and ships Python), so
we probe interfaces by exec'ing a small stdlib-only script inside it. When that
path is unavailable (dev / tests / packet-sensor down) we fall back to probing
the local namespace and flag the source so the UI can be honest about it.

Light mapping (matches the operator request):
  * green  ("up_ip")    — interface has an IP address
  * orange ("up_no_ip") — link is up but no IP yet
  * red    ("down")     — no link / no carrier
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any, Optional

# Standalone, stdlib-only probe executed inside the host-net container (or
# locally as a fallback). Emits a JSON array of raw interface dicts on stdout.
PROBE_SCRIPT = r"""
import json, os, socket, struct, fcntl

SYS = "/sys/class/net"
SIOCGIFADDR = 0x8915


def _read(path):
    try:
        with open(path, "r") as fh:
            return fh.read().strip()
    except Exception:
        return None


def _ipv4(name):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        packed = struct.pack("256s", name[:15].encode())
        res = fcntl.ioctl(sock.fileno(), SIOCGIFADDR, packed)
        return socket.inet_ntoa(res[20:24])
    except OSError:
        return None
    finally:
        sock.close()


def _ipv6_map():
    out = {}
    try:
        with open("/proc/net/if_inet6", "r") as fh:
            for line in fh:
                parts = line.split()
                if len(parts) >= 6:
                    addr, name = parts[0], parts[5]
                    grouped = ":".join(addr[i:i + 4] for i in range(0, 32, 4))
                    out.setdefault(name, []).append(grouped)
    except Exception:
        pass
    return out


def _default_route_ifaces():
    # /proc/net/route: Iface Destination ... Flags ...  (hex, little-endian fields)
    out = set()
    try:
        with open("/proc/net/route", "r") as fh:
            next(fh, None)
            for line in fh:
                f = line.split()
                if len(f) >= 4 and f[1] == "00000000" and (int(f[3], 16) & 0x1):
                    out.add(f[0])
    except Exception:
        pass
    return out


def main():
    v6 = _ipv6_map()
    default_ifaces = _default_route_ifaces()
    try:
        names = sorted({n for _, n in socket.if_nameindex()})
    except Exception:
        names = sorted(os.listdir(SYS)) if os.path.isdir(SYS) else []
    rows = []
    for name in names:
        base = os.path.join(SYS, name)
        rows.append({
            "name": name,
            "mac": _read(base + "/address"),
            "operstate": _read(base + "/operstate"),
            "carrier": _read(base + "/carrier"),
            "speed": _read(base + "/speed"),
            "mtu": _read(base + "/mtu"),
            "type": _read(base + "/type"),
            "wireless": os.path.isdir(base + "/wireless") or os.path.exists(base + "/phy80211"),
            "has_device": os.path.exists(base + "/device"),
            "ipv4": _ipv4(name),
            "ipv6": v6.get(name, []),
            "default_route": name in default_ifaces,
        })
    print(json.dumps(rows))


main()
"""

# Standalone script to flip IFF_UP via ioctl (needs CAP_NET_ADMIN; packet-sensor
# has it). argv: <ifname> <up|down>. Prints "ok" on success.
SET_STATE_SCRIPT = r"""
import sys, socket, struct, fcntl

SIOCGIFFLAGS = 0x8913
SIOCSIFFLAGS = 0x8914
IFF_UP = 0x1

name = sys.argv[1]
up = sys.argv[2] == "up"
nb = name[:15].encode()
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
try:
    res = fcntl.ioctl(sock.fileno(), SIOCGIFFLAGS, struct.pack("16sH", nb, 0))
    flags = struct.unpack("16sH", res)[1]
    flags = (flags | IFF_UP) if up else (flags & ~IFF_UP)
    fcntl.ioctl(sock.fileno(), SIOCSIFFLAGS, struct.pack("16sH", nb, flags))
    print("ok")
finally:
    sock.close()
"""

_VIRTUAL_PREFIXES = (
    "lo",
    "docker",
    "br-",
    "veth",
    "virbr",
    "cni",
    "flannel",
    "tap",
    "tun",
    "kube",
    "cali",
    "vxlan",
)


_IFNAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.@:-]{0,14}$")


def _packet_sensor_container() -> str:
    return os.environ.get("PACKET_SENSOR_CONTAINER", "sensel-packet-sensor")


def _net_admin_enabled() -> bool:
    return os.environ.get("EDGE_CONSOLE_NET_ADMIN", "").strip().lower() in ("1", "true", "yes")


def _capture_interface_default(explicit: Optional[str]) -> str:
    return (explicit or os.environ.get("CAPTURE_INTERFACE") or "").strip()


def _docker_available() -> bool:
    return Path("/var/run/docker.sock").exists()


def _run_probe_remote(container: str, *, timeout: float = 8.0) -> Optional[list[dict[str, Any]]]:
    """Run the probe inside the host-net packet-sensor container."""
    if not _docker_available():
        return None
    try:
        proc = subprocess.run(
            ["docker", "exec", "-i", container, "python3", "-"],
            input=PROBE_SCRIPT,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return None
    if proc.returncode != 0 or not proc.stdout.strip():
        return None
    try:
        data = json.loads(proc.stdout)
    except json.JSONDecodeError:
        return None
    return data if isinstance(data, list) else None


def _run_probe_local(*, timeout: float = 5.0) -> Optional[list[dict[str, Any]]]:
    """Fallback: probe the console's own namespace (dev / tests only)."""
    try:
        proc = subprocess.run(
            [sys.executable, "-"],
            input=PROBE_SCRIPT,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return None
    if proc.returncode != 0 or not proc.stdout.strip():
        return None
    try:
        data = json.loads(proc.stdout)
    except json.JSONDecodeError:
        return None
    return data if isinstance(data, list) else None


def _is_virtual(name: str, raw: dict[str, Any]) -> bool:
    if name == "lo":
        return True
    if not raw.get("has_device") and any(name.startswith(p) for p in _VIRTUAL_PREFIXES):
        return True
    return False


def _routable_ipv6(addrs: list[str]) -> list[str]:
    return [a for a in (addrs or []) if not a.lower().startswith("fe80")]


def _link_up(raw: dict[str, Any]) -> bool:
    operstate = (raw.get("operstate") or "").lower()
    carrier = raw.get("carrier")
    if operstate == "up":
        return True
    if operstate == "down":
        return False
    # operstate "unknown" (common for some drivers / loopback): trust carrier.
    return carrier == "1"


def derive_state(raw: dict[str, Any]) -> tuple[str, str]:
    """Return (state, zh-TW label). Green requires an IP per the operator spec."""
    has_ip = bool(raw.get("ipv4")) or bool(_routable_ipv6(raw.get("ipv6") or []))
    if has_ip:
        return "up_ip", "已取得 IP"
    if _link_up(raw):
        return "up_no_ip", "已連線（未取得 IP）"
    return "down", "未連線"


# state → status-dot CSS class reused from tokens.css (.status-dot ok/unk/bad)
_STATE_DOT = {"up_ip": "ok", "up_no_ip": "unk", "down": "bad"}


def _toggle_block_reason(name: str, raw: dict[str, Any], capture_iface: str) -> Optional[str]:
    """Why an interface must NOT be toggled off — guards against lockout."""
    if _is_virtual(name, raw):
        return "虛擬介面不可操作"
    if raw.get("default_route"):
        return "預設路由（管理連線）介面，停用會導致斷線"
    if capture_iface and name == capture_iface:
        return "擷取介面，停用會中斷封包偵測"
    return None


def _shape(raw: dict[str, Any], capture_iface: str = "") -> dict[str, Any]:
    name = str(raw.get("name") or "")
    state, label = derive_state(raw)
    ipv6_routable = _routable_ipv6(raw.get("ipv6") or [])
    speed = raw.get("speed")
    try:
        speed_val = int(speed) if speed not in (None, "", "-1") else None
    except (TypeError, ValueError):
        speed_val = None
    block_reason = _toggle_block_reason(name, raw, capture_iface)
    return {
        "name": name,
        "kind": "wireless" if raw.get("wireless") else "wired",
        "virtual": _is_virtual(name, raw),
        "mac": raw.get("mac"),
        "operstate": raw.get("operstate"),
        "carrier": raw.get("carrier"),
        "link_up": _link_up(raw),
        "default_route": bool(raw.get("default_route")),
        "ipv4": raw.get("ipv4"),
        "ipv6": ipv6_routable,
        "ipv6_all": raw.get("ipv6") or [],
        "speed_mbps": speed_val,
        "mtu": raw.get("mtu"),
        "state": state,
        "state_label": label,
        "dot": _STATE_DOT.get(state, "unk"),
        "can_toggle": block_reason is None,
        "toggle_block_reason": block_reason,
    }


def _gather_raw() -> tuple[Optional[list[dict[str, Any]]], str]:
    container = _packet_sensor_container()
    raw = _run_probe_remote(container)
    if raw is not None:
        return raw, "packet-sensor"
    return _run_probe_local(), "console-local"


def collect_interfaces(capture_interface: Optional[str] = None) -> dict[str, Any]:
    """Gather host interfaces; primary path is the host-net packet-sensor."""
    container = _packet_sensor_container()
    capture_iface = _capture_interface_default(capture_interface)
    raw, source = _gather_raw()
    if raw is None:
        return {
            "ok": False,
            "source": None,
            "net_admin_enabled": _net_admin_enabled(),
            "interfaces": [],
            "error": (
                f"無法取得主機網卡（需 {container} 容器運行且 docker.sock 已掛載）。"
            ),
        }

    shaped = [_shape(r, capture_iface) for r in raw if isinstance(r, dict) and r.get("name")]
    # Physical (wired/wireless) first, then virtual; stable by name within group.
    shaped.sort(key=lambda i: (i["virtual"], i["kind"] != "wireless", i["name"]))
    physical = [i for i in shaped if not i["virtual"]]
    summary = {
        "total": len(physical),
        "up_ip": sum(1 for i in physical if i["state"] == "up_ip"),
        "up_no_ip": sum(1 for i in physical if i["state"] == "up_no_ip"),
        "down": sum(1 for i in physical if i["state"] == "down"),
    }
    return {
        "ok": True,
        "source": source,
        "container": container if source == "packet-sensor" else None,
        "net_admin_enabled": _net_admin_enabled(),
        "capture_interface": capture_iface or None,
        "summary": summary,
        "interfaces": shaped,
    }


def set_interface_state(
    name: str,
    up: bool,
    *,
    capture_interface: Optional[str] = None,
) -> dict[str, Any]:
    """Bring an interface up/down via packet-sensor (CAP_NET_ADMIN), with guards."""
    if not _IFNAME_RE.match(name or ""):
        return {"ok": False, "status": 400, "error": "介面名稱無效"}
    if not _net_admin_enabled():
        return {
            "ok": False,
            "status": 403,
            "error": "網路控制未啟用（請設定 EDGE_CONSOLE_NET_ADMIN=true 並重啟 Console）",
        }

    raw, source = _gather_raw()
    if raw is None:
        return {"ok": False, "status": 503, "error": "無法存取主機網卡（packet-sensor 未就緒）"}
    target = next((r for r in raw if isinstance(r, dict) and r.get("name") == name), None)
    if target is None:
        return {"ok": False, "status": 404, "error": f"找不到介面 {name}"}

    capture_iface = _capture_interface_default(capture_interface)
    # Guard against lockout only when disabling.
    if not up:
        reason = _toggle_block_reason(name, target, capture_iface)
        if reason:
            return {"ok": False, "status": 409, "error": f"{name} 無法停用：{reason}"}

    if source != "packet-sensor":
        return {
            "ok": False,
            "status": 503,
            "error": "僅能透過 host 網路的 packet-sensor 變更介面狀態",
        }

    container = _packet_sensor_container()
    try:
        proc = subprocess.run(
            ["docker", "exec", "-i", container, "python3", "-", name, "up" if up else "down"],
            input=SET_STATE_SCRIPT,
            capture_output=True,
            text=True,
            timeout=10.0,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
        return {"ok": False, "status": 503, "error": f"docker exec 失敗：{exc}"}
    if proc.returncode != 0 or "ok" not in proc.stdout:
        detail = (proc.stderr or proc.stdout or "unknown").strip()
        if "RF-kill" in detail or "rfkill" in detail.lower():
            return {
                "ok": False,
                "status": 409,
                "error": f"{name} 的無線電被 rfkill 阻斷（Wi-Fi radio 已關閉）。請改用 Wi-Fi 設定開啟無線網路。",
            }
        return {"ok": False, "status": 502, "error": f"設定失敗：{detail[:200]}"}

    return {
        "ok": True,
        "name": name,
        "up": up,
        "message": f"{name} 已{'啟用' if up else '停用'}",
    }
