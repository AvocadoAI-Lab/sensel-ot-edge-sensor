"""OpenVPN client management for the Edge Console.

The Console never runs OpenVPN itself (it lives on a Docker bridge network with
no tun device). Instead it is the *control plane*: it manages ``.ovpn`` profiles
and writes a declarative ``desired.json`` onto the shared ``/data/agent/vpn``
volume. The host-network ``vpn-client`` sidecar reconciles the running tunnel to
that desired state and publishes ``status.json`` back.

This mirrors the existing ``wifi_service`` / ``network_service`` conventions:
all mutating ops are gated by ``EDGE_CONSOLE_VPN_ADMIN``, return
``{ok, status, error}`` dicts, and never persist/return secrets in the clear.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

_PROFILE_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
_CTRL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_MAX_OVPN_BYTES = 512 * 1024  # 512 KB is plenty for an inline-cert profile
_CRED_MAX = 256

# Inline blocks / directives that carry secrets — masked in the "view" output.
_SECRET_BLOCK_RE = re.compile(
    r"<(key|tls-auth|tls-crypt|tls-crypt-v2|secret)>.*?</\1>",
    re.DOTALL | re.IGNORECASE,
)
_SECRET_LINE_RE = re.compile(
    r"^\s*(askpass|auth-user-pass)\s+\S.*$", re.MULTILINE | re.IGNORECASE
)


def vpn_admin_enabled() -> bool:
    return os.environ.get("EDGE_CONSOLE_VPN_ADMIN", "").strip().lower() in ("1", "true", "yes")


def _state_dir() -> Path:
    return Path(os.environ.get("VPN_STATE_DIR", "/data/agent/vpn"))


def _profiles_dir() -> Path:
    return _state_dir() / "profiles"


def _desired_path() -> Path:
    return _state_dir() / "desired.json"


def _status_path() -> Path:
    return _state_dir() / "status.json"


def _vpn_container() -> str:
    return os.environ.get("VPN_CLIENT_CONTAINER", "sensel-vpn-client")


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _disabled() -> dict[str, Any]:
    return {"ok": False, "status": 403, "error": "VPN 控制未啟用（請設定 EDGE_CONSOLE_VPN_ADMIN=true 並重啟 Console）"}


def _valid_name(name: str) -> bool:
    return bool(name) and bool(_PROFILE_RE.match(name)) and ".." not in name


def _profile_file(name: str) -> Optional[Path]:
    if not _valid_name(name):
        return None
    base = _profiles_dir().resolve()
    p = (base / f"{name}.ovpn").resolve()
    try:
        p.relative_to(base)
    except ValueError:
        return None
    return p


def _read_json(path: Path) -> dict[str, Any]:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}


def _atomic_write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
    os.replace(tmp, path)


# --- profile CRUD -----------------------------------------------------------

def validate_ovpn(content: bytes) -> Optional[str]:
    """Return an error string if the upload does not look like a usable .ovpn."""
    if not content:
        return "空的設定內容"
    if len(content) > _MAX_OVPN_BYTES:
        return f"設定檔超過 {_MAX_OVPN_BYTES // 1024}KB 上限"
    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError:
        return "設定檔非 UTF-8 文字（請確認為 .ovpn 純文字）"
    low = text.lower()
    if "remote " not in low and "<connection>" not in low:
        return "設定檔缺少 remote 指令，無法判定 VPN 伺服器"
    if "client" not in low and "tls-client" not in low:
        return "僅支援 client 模式的 .ovpn 設定檔"
    return None


def profile_warnings(content: str) -> list[str]:
    """Non-fatal advisories surfaced to the operator (does not block upload)."""
    warns: list[str] = []
    low = content.lower()
    if re.search(r"^\s*(up|down|route-up|tls-verify)\s+", content, re.MULTILINE | re.IGNORECASE):
        warns.append("設定檔含 up/down 等腳本指令；本機以 --script-security 1 執行，這些腳本不會被執行。")
    if "auth-user-pass" in low and not re.search(r"auth-user-pass\s+\S", low):
        warns.append("設定檔需要帳號/密碼（auth-user-pass），連線時請一併提供。")
    return warns


def needs_auth(content: str) -> bool:
    """True if the profile expects interactive username/password (no inline file)."""
    return bool(re.search(r"^\s*auth-user-pass\s*$", content, re.MULTILINE | re.IGNORECASE))


def list_profiles() -> dict[str, Any]:
    pdir = _profiles_dir()
    profiles: list[dict[str, Any]] = []
    if pdir.is_dir():
        for f in sorted(pdir.glob("*.ovpn")):
            name = f.stem
            if not _valid_name(name):
                continue
            try:
                st = f.stat()
                text = f.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            remote = _extract_remote(text)
            profiles.append({
                "name": name,
                "size": st.st_size,
                "uploaded_at": datetime.fromtimestamp(st.st_mtime, timezone.utc).isoformat(),
                "remote": remote,
                "needs_auth": needs_auth(text),
                "has_auth_file": f.with_suffix(".auth").is_file(),
            })
    return {
        "ok": True,
        "admin": vpn_admin_enabled(),
        "profiles": profiles,
        "status": get_status().get("status_data"),
    }


def _extract_remote(text: str) -> Optional[str]:
    m = re.search(r"^\s*remote\s+(\S+)(?:\s+(\d+))?", text, re.MULTILINE | re.IGNORECASE)
    if not m:
        return None
    return f"{m.group(1)}:{m.group(2)}" if m.group(2) else m.group(1)


def save_profile(name: str, content: bytes) -> dict[str, Any]:
    if not vpn_admin_enabled():
        return _disabled()
    if not _valid_name(name):
        return {"ok": False, "status": 400, "error": "設定檔名稱無效（僅允許英數 . _ -，長度 1–64）"}
    err = validate_ovpn(content)
    if err:
        return {"ok": False, "status": 400, "error": err}
    path = _profile_file(name)
    if path is None:
        return {"ok": False, "status": 400, "error": "設定檔名稱無效"}
    text = content.decode("utf-8")
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
        os.chmod(path, 0o600)
        try:
            os.chmod(path.parent, 0o700)
        except OSError:
            pass
    except OSError as exc:
        return {"ok": False, "status": 500, "error": f"寫入設定檔失敗：{exc}"}
    return {
        "ok": True,
        "name": name,
        "remote": _extract_remote(text),
        "needs_auth": needs_auth(text),
        "warnings": profile_warnings(text),
        "message": f"已儲存設定檔 {name}",
    }


def delete_profile(name: str) -> dict[str, Any]:
    if not vpn_admin_enabled():
        return _disabled()
    path = _profile_file(name)
    if path is None:
        return {"ok": False, "status": 400, "error": "設定檔名稱無效"}
    if not path.is_file():
        return {"ok": False, "status": 404, "error": f"找不到設定檔 {name}"}
    # Refuse to delete the profile that is currently the desired/active tunnel.
    desired = _read_json(_desired_path())
    if desired.get("connect") and desired.get("profile") == name:
        return {"ok": False, "status": 409, "error": "此設定檔正在使用中，請先中斷連線"}
    try:
        path.unlink(missing_ok=True)
        path.with_suffix(".auth").unlink(missing_ok=True)
    except OSError as exc:
        return {"ok": False, "status": 500, "error": f"刪除失敗：{exc}"}
    return {"ok": True, "message": f"已刪除設定檔 {name}"}


def view_profile(name: str) -> dict[str, Any]:
    path = _profile_file(name)
    if path is None:
        return {"ok": False, "status": 400, "error": "設定檔名稱無效"}
    if not path.is_file():
        return {"ok": False, "status": 404, "error": f"找不到設定檔 {name}"}
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        return {"ok": False, "status": 500, "error": f"讀取失敗：{exc}"}
    masked = _SECRET_BLOCK_RE.sub(
        lambda m: f"<{m.group(1)}>\n*** 已遮蔽（機敏內容）***\n</{m.group(1)}>", text
    )
    masked = _SECRET_LINE_RE.sub(r"\g<1> *** 已遮蔽 ***", masked)
    return {
        "ok": True,
        "name": name,
        "content": masked,
        "remote": _extract_remote(text),
        "needs_auth": needs_auth(text),
        "warnings": profile_warnings(text),
    }


# --- connect / disconnect (declarative desired state) -----------------------

def connect(
    profile: str,
    *,
    redirect_gateway: bool = False,
    username: Optional[str] = None,
    password: Optional[str] = None,
    auto_reconnect: bool = True,
) -> dict[str, Any]:
    if not vpn_admin_enabled():
        return _disabled()
    path = _profile_file(profile)
    if path is None:
        return {"ok": False, "status": 400, "error": "設定檔名稱無效"}
    if not path.is_file():
        return {"ok": False, "status": 404, "error": f"找不到設定檔 {profile}"}

    use_auth = False
    if username or password:
        if username and (_CTRL_RE.search(username) or len(username) > _CRED_MAX):
            return {"ok": False, "status": 400, "error": "帳號格式無效"}
        if password and (_CTRL_RE.search(password) or len(password) > _CRED_MAX):
            return {"ok": False, "status": 400, "error": "密碼格式無效"}
        auth_path = path.with_suffix(".auth")
        try:
            auth_path.write_text(f"{username or ''}\n{password or ''}\n", encoding="utf-8")
            os.chmod(auth_path, 0o600)
        except OSError as exc:
            return {"ok": False, "status": 500, "error": f"寫入認證檔失敗：{exc}"}
        use_auth = True
    else:
        # Reuse a previously stored auth file if present.
        use_auth = path.with_suffix(".auth").is_file()

    prev = _read_json(_desired_path())
    epoch = int(prev.get("epoch") or 0) + 1
    try:
        _atomic_write_json(_desired_path(), {
            "connect": True,
            "profile": profile,
            "redirect_gateway": bool(redirect_gateway),
            "auth": use_auth,
            "auto_reconnect": bool(auto_reconnect),
            "epoch": epoch,
            "updated_at": _now_iso(),
        })
    except OSError as exc:
        return {"ok": False, "status": 500, "error": f"寫入連線指令失敗：{exc}"}
    return {"ok": True, "profile": profile, "epoch": epoch, "message": f"已要求連線 {profile}（背景建立中）"}


def set_auto_reconnect(on: bool) -> dict[str, Any]:
    """Toggle tunnel auto-reconnect without forcing a reconnect.

    Updates ``desired.json`` in place (does NOT bump ``epoch``) so the running
    tunnel is left untouched; the supervisor simply changes whether it restarts
    OpenVPN the next time the link drops.
    """
    if not vpn_admin_enabled():
        return _disabled()
    desired = _read_json(_desired_path())
    desired["auto_reconnect"] = bool(on)
    desired["updated_at"] = _now_iso()
    try:
        _atomic_write_json(_desired_path(), desired)
    except OSError as exc:
        return {"ok": False, "status": 500, "error": f"寫入設定失敗：{exc}"}
    return {
        "ok": True,
        "auto_reconnect": bool(on),
        "message": "已啟用斷線自動重連" if on else "已停用斷線自動重連（連線中斷後不會自動重連）",
    }


def disconnect() -> dict[str, Any]:
    if not vpn_admin_enabled():
        return _disabled()
    prev = _read_json(_desired_path())
    epoch = int(prev.get("epoch") or 0) + 1
    try:
        _atomic_write_json(_desired_path(), {
            "connect": False,
            "profile": prev.get("profile"),
            "epoch": epoch,
            "updated_at": _now_iso(),
        })
    except OSError as exc:
        return {"ok": False, "status": 500, "error": f"寫入中斷指令失敗：{exc}"}
    return {"ok": True, "message": "已要求中斷連線"}


# --- status -----------------------------------------------------------------

def _supervisor_fresh(status: dict[str, Any]) -> bool:
    """True if status.json was updated recently (supervisor alive)."""
    raw = status.get("updated_at")
    if not raw:
        return False
    try:
        ts = datetime.fromisoformat(raw)
    except ValueError:
        return False
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=timezone.utc)
    return (datetime.now(timezone.utc) - ts).total_seconds() < 30


def get_status() -> dict[str, Any]:
    status = _read_json(_status_path())
    desired = _read_json(_desired_path())
    fresh = _supervisor_fresh(status) if status else False
    state = status.get("state") if status else None
    if not status:
        state = "unknown"
    elif not fresh:
        state = "stale"
    return {
        "ok": True,
        "admin": vpn_admin_enabled(),
        "supervisor_alive": fresh,
        "desired_connect": bool(desired.get("connect")),
        "desired_profile": desired.get("profile"),
        "desired_auto_reconnect": bool(desired.get("auto_reconnect", True)),
        "state": state,
        "status_data": status or None,
    }


# --- diagnostics (run inside the host-net vpn-client) -----------------------

# Stdlib-only probe executed inside the vpn-client container (host netns), so it
# sees the real tun device + routes. argv: <target_host> <target_port>.
DIAG_SCRIPT = r"""
import json, os, socket, struct, fcntl, sys

SIOCGIFADDR = 0x8915
target = sys.argv[1] if len(sys.argv) > 1 else ""
try:
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 0
except ValueError:
    port = 0


def ipv4(name):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        packed = struct.pack("256s", name[:15].encode())
        res = fcntl.ioctl(s.fileno(), SIOCGIFADDR, packed)
        return socket.inet_ntoa(res[20:24])
    except OSError:
        return None
    finally:
        s.close()


def tun_ifaces():
    out = []
    base = "/sys/class/net"
    if os.path.isdir(base):
        for n in sorted(os.listdir(base)):
            if n.startswith(("tun", "tap", "utun")):
                out.append({"name": n, "ipv4": ipv4(n)})
    return out


def routes():
    rows = []
    try:
        with open("/proc/net/route") as fh:
            next(fh, None)
            for line in fh:
                f = line.split()
                if len(f) >= 8:
                    dest = socket.inet_ntoa(struct.pack("<L", int(f[1], 16)))
                    mask = socket.inet_ntoa(struct.pack("<L", int(f[7], 16)))
                    rows.append({"iface": f[0], "dest": dest, "mask": mask})
    except Exception:
        pass
    return rows


def tcp_check(host, p):
    if not host or not p:
        return None
    try:
        ip = socket.gethostbyname(host)
    except OSError as e:
        return {"ok": False, "error": "DNS 解析失敗：%s" % e, "host": host, "port": p}
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(5.0)
    try:
        s.connect((ip, p))
        return {"ok": True, "host": host, "ip": ip, "port": p}
    except OSError as e:
        return {"ok": False, "host": host, "ip": ip, "port": p, "error": str(e)}
    finally:
        s.close()


tuns = tun_ifaces()
connected_tun = next((t for t in tuns if t["ipv4"]), None)
result = {
    "tun_interfaces": tuns,
    "tun_up": connected_tun is not None,
    "assigned_ip": connected_tun["ipv4"] if connected_tun else None,
    "routes": routes(),
    "tcp_target": tcp_check(target, port),
}
print(json.dumps(result))
"""


def _docker_available() -> bool:
    return Path("/var/run/docker.sock").exists()


def diagnose(target_host: str = "192.168.1.203", target_port: int = 1883) -> dict[str, Any]:
    """Run a tunnel reachability probe inside the vpn-client (host netns).

    Defaults target the lab MQTT broker (192.168.1.203:1883), i.e. answers the
    operational question "can the appliance reach the internal MQTT over VPN?".
    """
    if not vpn_admin_enabled():
        return _disabled()
    if target_host and _CTRL_RE.search(target_host):
        return {"ok": False, "status": 400, "error": "目標主機格式無效"}
    if not (0 < int(target_port) <= 65535):
        return {"ok": False, "status": 400, "error": "目標埠號無效"}
    if not _docker_available():
        return {"ok": False, "status": 503, "error": "Docker socket 未掛載，無法在 vpn-client 內診斷"}

    container = _vpn_container()
    try:
        proc = subprocess.run(
            ["docker", "exec", "-i", container, "python3", "-", str(target_host), str(int(target_port))],
            input=DIAG_SCRIPT,
            capture_output=True,
            text=True,
            timeout=20.0,
        )
    except FileNotFoundError:
        return {"ok": False, "status": 503, "error": "docker CLI 不可用"}
    except subprocess.TimeoutExpired:
        return {"ok": False, "status": 504, "error": "診斷逾時"}
    if proc.returncode != 0 or not proc.stdout.strip():
        detail = (proc.stderr or proc.stdout or "unknown").strip()
        return {"ok": False, "status": 502, "error": f"診斷執行失敗：{detail[:200]}"}
    try:
        probe = json.loads(proc.stdout)
    except json.JSONDecodeError:
        return {"ok": False, "status": 502, "error": "診斷輸出解析失敗"}

    tcp = probe.get("tcp_target") or {}
    reachable = bool(tcp.get("ok"))
    summary = (
        f"tun {'已就緒' if probe.get('tun_up') else '未建立'}"
        f" · {target_host}:{target_port} "
        f"{'可連線' if reachable else '不可連線'}"
    )
    return {
        "ok": True,
        "target": {"host": target_host, "port": int(target_port)},
        "reachable": reachable,
        "summary": summary,
        "probe": probe,
    }
