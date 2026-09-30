"""SenseL VPN client supervisor — declarative, self-healing OpenVPN runner.

Design goals (stable + autonomous):
  * Declarative: the Edge Console only writes a *desired* state file
    (``desired.json``); this daemon reconciles the running OpenVPN process to
    match it. No long-lived control connection from the console is required, so
    a console restart / crash never leaves the tunnel in an unknown state.
  * Self-healing: if OpenVPN dies while it is *meant* to be connected the
    supervisor restarts it (with capped backoff). OpenVPN's own
    ``--ping-restart`` handles dead-peer detection at the link layer.
  * Crash-safe: on container restart the supervisor reads ``desired.json`` and
    re-establishes the tunnel automatically (``restart: unless-stopped`` on the
    container + this reconcile loop = the tunnel comes back by itself).
  * Lockout-safe default: split tunnel (pushed LAN routes are kept, but the
    server is *not* allowed to hijack the default gateway) unless the operator
    explicitly opts into full-tunnel per profile.

The process owns the OpenVPN child directly (so it can always stop it), and
reads live state from OpenVPN's management interface (assigned tunnel IP,
connection state, byte counters), falling back to an ioctl probe of the tun
device when the management socket is unavailable.

Stdlib only — no third-party deps — to keep the image small and robust.
"""

from __future__ import annotations

import json
import os
import re
import shlex
import signal
import socket
import struct
import subprocess
import sys
import time
import fcntl
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

STATE_DIR = Path(os.environ.get("VPN_STATE_DIR", "/data/agent/vpn"))
PROFILES_DIR = STATE_DIR / "profiles"
RUN_DIR = STATE_DIR / "run"
DESIRED_PATH = STATE_DIR / "desired.json"
STATUS_PATH = STATE_DIR / "status.json"
LOG_PATH = RUN_DIR / "openvpn.log"

MGMT_HOST = "127.0.0.1"
MGMT_PORT = int(os.environ.get("VPN_MGMT_PORT", "7505") or "7505")

RECONCILE_INTERVAL = 2.0
BACKOFF_BASE = 3.0
BACKOFF_MAX = 60.0

SIOCGIFADDR = 0x8915
_PROFILE_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
_TUN_OPEN_RE = re.compile(r"(?:TUN/TAP device|Opened utun device|net_iface_mtu_set:\s*mtu \d+ for)\s+([a-z]+\d+)")
_TUN_DEV_RE = re.compile(r"\b(tun\d+|tap\d+|utun\d+)\b")


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _ensure_dirs() -> None:
    for d in (STATE_DIR, PROFILES_DIR, RUN_DIR):
        try:
            d.mkdir(parents=True, exist_ok=True)
        except OSError:
            pass


def _read_json(path: Path) -> dict[str, Any]:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}


def _atomic_write_json(path: Path, payload: dict[str, Any]) -> None:
    tmp = path.with_suffix(path.suffix + ".tmp")
    try:
        tmp.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
        os.replace(tmp, path)
    except OSError:
        pass


def _profile_path(name: str) -> Optional[Path]:
    if not name or not _PROFILE_RE.match(name):
        return None
    p = (PROFILES_DIR / f"{name}.ovpn").resolve()
    # Guard against path traversal: must stay inside PROFILES_DIR.
    try:
        p.relative_to(PROFILES_DIR.resolve())
    except ValueError:
        return None
    return p if p.is_file() else None


def _ioctl_ipv4(ifname: str) -> Optional[str]:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        packed = struct.pack("256s", ifname[:15].encode())
        res = fcntl.ioctl(sock.fileno(), SIOCGIFADDR, packed)
        return socket.inet_ntoa(res[20:24])
    except OSError:
        return None
    finally:
        sock.close()


class MgmtClient:
    """Tiny OpenVPN management-interface client (read-only state/stats)."""

    def __init__(self, host: str = MGMT_HOST, port: int = MGMT_PORT) -> None:
        self.host = host
        self.port = port

    def _converse(self, command: str, timeout: float = 3.0) -> Optional[str]:
        try:
            with socket.create_connection((self.host, self.port), timeout=timeout) as sock:
                sock.settimeout(timeout)
                # Drain the greeting banner.
                self._drain(sock)
                sock.sendall((command + "\n").encode())
                return self._read_until_end(sock)
        except (OSError, socket.timeout):
            return None

    @staticmethod
    def _drain(sock: socket.socket) -> None:
        sock.settimeout(0.4)
        try:
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
        except (OSError, socket.timeout):
            pass
        sock.settimeout(3.0)

    @staticmethod
    def _read_until_end(sock: socket.socket) -> str:
        buf = b""
        deadline = time.time() + 3.0
        while time.time() < deadline:
            try:
                chunk = sock.recv(4096)
            except (OSError, socket.timeout):
                break
            if not chunk:
                break
            buf += chunk
            if b"\nEND" in buf or buf.strip().endswith(b"END"):
                break
        return buf.decode(errors="replace")

    def state(self) -> Optional[dict[str, Any]]:
        raw = self._converse("state")
        if raw is None:
            return None
        for line in raw.splitlines():
            line = line.strip()
            if not line or line.startswith(">") or line == "END" or line.startswith("SUCCESS"):
                continue
            parts = line.split(",")
            if len(parts) >= 2 and parts[1]:
                return {
                    "name": parts[1],
                    "detail": parts[2] if len(parts) > 2 else "",
                    "tun_ip": parts[3] if len(parts) > 3 and parts[3] else None,
                    "server_ip": parts[4] if len(parts) > 4 and parts[4] else None,
                }
        return None

    def stats(self) -> dict[str, Optional[int]]:
        raw = self._converse("status")
        bin_, bout = None, None
        if raw:
            for line in raw.splitlines():
                low = line.lower()
                if "read bytes" in low or "bytes received" in low:
                    bin_ = _last_int(line)
                elif "write bytes" in low or "bytes sent" in low:
                    bout = _last_int(line)
        return {"bytes_in": bin_, "bytes_out": bout}


def _last_int(line: str) -> Optional[int]:
    nums = re.findall(r"\d+", line)
    return int(nums[-1]) if nums else None


# OpenVPN connection-state names that mean "the link is fully up".
_CONNECTED = {"CONNECTED"}
_TRANSIENT = {"CONNECTING", "WAIT", "AUTH", "GET_CONFIG", "ASSIGN_IP", "ADD_ROUTES", "RECONNECTING", "RESOLVE"}


class Supervisor:
    def __init__(self) -> None:
        self.proc: Optional[subprocess.Popen] = None
        self.active_profile: Optional[str] = None
        self.active_epoch: Optional[int] = None
        self.connected_since: Optional[str] = None
        self.last_error: Optional[str] = None
        self.backoff = 0.0
        self.next_start_at = 0.0
        self.tun_device: Optional[str] = None
        self.mgmt = MgmtClient()
        self._stop = False
        # When auto-reconnect is disabled, remember the epoch we already gave up
        # on so we don't restart OpenVPN until the operator explicitly reconnects
        # (which bumps the desired epoch).
        self.gave_up_epoch: Optional[int] = None

    # --- OpenVPN process lifecycle -----------------------------------------
    def _build_argv(self, profile_path: Path, desired: dict[str, Any]) -> list[str]:
        auto_reconnect = bool(desired.get("auto_reconnect", True))
        argv = [
            "openvpn",
            "--config", str(profile_path),
            "--cd", str(PROFILES_DIR),
            "--management", MGMT_HOST, str(MGMT_PORT),
            "--verb", "3",
            "--ping", "10",
            "--persist-tun",
            "--persist-key",
            "--connect-retry", "5",
            "--log", str(LOG_PATH),
            "--writepid", str(RUN_DIR / "openvpn.pid"),
            "--status", str(RUN_DIR / "openvpn-status.log"), "5",
            # Never run user scripts embedded in an uploaded profile.
            "--script-security", "1",
        ]
        if auto_reconnect:
            # Self-healing link: on dead-peer detection OpenVPN restarts its own
            # session, and it retries the initial connect forever. The supervisor
            # additionally relaunches the process if it ever exits.
            argv += ["--ping-restart", "60", "--connect-retry-max", "0"]
        else:
            # Auto-reconnect disabled: OpenVPN EXITS on dead peer (ping-exit) and
            # gives up after a couple of failed initial connects, so a dropped
            # tunnel stays down until the operator reconnects.
            argv += ["--ping-exit", "60", "--connect-retry-max", "2"]
        # Lockout-safe default (split tunnel): keep pushed LAN routes but reject
        # ANY server attempt to seize the default gateway, unless the operator
        # opts into full tunnel. We must filter BOTH redirect-gateway AND an
        # explicit default-route push: filtering only redirect-gateway while the
        # server also pushes `route 0.0.0.0 0.0.0.0` leaves the default hijacked
        # WITHOUT OpenVPN's protective host route to the server, which loops the
        # tunnel's own packets and kills the data channel.
        if not desired.get("redirect_gateway"):
            for opt in (
                "redirect-gateway",
                "route 0.0.0.0 0.0.0.0",
                "route 0.0.0.0 128.0.0.0",
                "route 128.0.0.0 128.0.0.0",
            ):
                argv += ["--pull-filter", "ignore", opt]
        # Optional username/password (written by the console next to the profile).
        auth_path = profile_path.with_suffix(".auth")
        if desired.get("auth") and auth_path.is_file():
            argv += ["--auth-user-pass", str(auth_path)]
        return argv

    def _start(self, profile: str, profile_path: Path, desired: dict[str, Any]) -> None:
        self._truncate_log()
        argv = self._build_argv(profile_path, desired)
        try:
            self.proc = subprocess.Popen(
                argv,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                start_new_session=True,
            )
        except (OSError, FileNotFoundError) as exc:
            self.last_error = f"openvpn 啟動失敗：{exc}"
            self.proc = None
            self._bump_backoff()
            return
        self.active_profile = profile
        self.active_epoch = desired.get("epoch")
        self.connected_since = None
        self.tun_device = None
        self.last_error = None

    def _truncate_log(self) -> None:
        try:
            LOG_PATH.write_text("", encoding="utf-8")
        except OSError:
            pass

    def _stop_proc(self, reason: str = "") -> None:
        if self.proc and self.proc.poll() is None:
            try:
                self.proc.send_signal(signal.SIGTERM)
                for _ in range(30):
                    if self.proc.poll() is not None:
                        break
                    time.sleep(0.1)
                if self.proc.poll() is None:
                    self.proc.kill()
            except OSError:
                pass
        self.proc = None
        self.active_profile = None
        self.active_epoch = None
        self.connected_since = None
        self.tun_device = None
        if reason:
            self.last_error = reason

    def _bump_backoff(self) -> None:
        self.backoff = min(BACKOFF_MAX, max(BACKOFF_BASE, self.backoff * 2 or BACKOFF_BASE))
        self.next_start_at = time.time() + self.backoff

    # --- tun device discovery ----------------------------------------------
    def _discover_tun(self) -> Optional[str]:
        if self.tun_device and _ioctl_ipv4(self.tun_device):
            return self.tun_device
        try:
            text = LOG_PATH.read_text(encoding="utf-8", errors="replace")
        except OSError:
            text = ""
        m = _TUN_OPEN_RE.search(text) or _TUN_DEV_RE.search(text)
        if m:
            self.tun_device = m.group(1)
            return self.tun_device
        # Fallback: scan for a tun* interface that already has an IPv4.
        sysnet = Path("/sys/class/net")
        if sysnet.is_dir():
            for entry in sorted(sysnet.iterdir()):
                if entry.name.startswith(("tun", "tap", "utun")) and _ioctl_ipv4(entry.name):
                    self.tun_device = entry.name
                    return self.tun_device
        return None

    # --- status snapshot ----------------------------------------------------
    def _write_status(self, desired: dict[str, Any]) -> None:
        running = bool(self.proc and self.proc.poll() is None)
        state_name = "disconnected"
        tun_ip = None
        server = None
        bytes_in = bytes_out = None

        if running:
            mgmt_state = self.mgmt.state()
            if mgmt_state:
                name = (mgmt_state.get("name") or "").upper()
                tun_ip = mgmt_state.get("tun_ip")
                server = mgmt_state.get("server_ip")
                if name in _CONNECTED:
                    state_name = "connected"
                elif name in _TRANSIENT:
                    state_name = "connecting"
                else:
                    state_name = name.lower() or "connecting"
                stats = self.mgmt.stats()
                bytes_in, bytes_out = stats.get("bytes_in"), stats.get("bytes_out")
            else:
                state_name = "connecting"
            # Resolve tunnel device + IP via the host namespace as ground truth.
            dev = self._discover_tun()
            ioctl_ip = _ioctl_ipv4(dev) if dev else None
            if ioctl_ip:
                tun_ip = ioctl_ip
                if state_name == "connecting":
                    state_name = "connected"
            if state_name == "connected" and not self.connected_since:
                self.connected_since = _now_iso()
            if state_name != "connected":
                self.connected_since = None

        desired_connect = bool(desired.get("connect"))
        auto_reconnect = bool(desired.get("auto_reconnect", True))
        gave_up = (not auto_reconnect) and self.gave_up_epoch == desired.get("epoch")
        if not running and desired_connect and not gave_up:
            state_name = "reconnecting" if self.last_error else "connecting"

        _atomic_write_json(STATUS_PATH, {
            "state": state_name,
            "desired_connect": desired_connect,
            "profile": self.active_profile or (desired.get("profile") if desired_connect else None),
            "assigned_ip": tun_ip,
            "tun_device": self.tun_device,
            "server": server,
            "since": self.connected_since,
            "bytes_in": bytes_in,
            "bytes_out": bytes_out,
            "last_error": self.last_error,
            "supervisor": "running",
            "updated_at": _now_iso(),
        })

    # --- main reconcile -----------------------------------------------------
    def reconcile_once(self) -> None:
        desired = _read_json(DESIRED_PATH)
        want_connect = bool(desired.get("connect"))
        want_profile = str(desired.get("profile") or "") if want_connect else ""
        target_path = _profile_path(want_profile) if want_profile else None
        auto_reconnect = bool(desired.get("auto_reconnect", True))
        epoch = desired.get("epoch")

        if want_connect and target_path is None:
            self._stop_proc()
            self.last_error = f"找不到設定檔：{want_profile}" if want_profile else "未指定設定檔"
            self._write_status(desired)
            return

        running = bool(self.proc and self.proc.poll() is None)

        # Operator wants disconnect (or no valid profile).
        if not target_path:
            if running or self.active_profile:
                self._stop_proc()
            self.last_error = None
            self.backoff = 0.0
            self._write_status(desired)
            return

        # A new desired epoch (or profile switch) forces a clean restart. A fresh
        # epoch also clears any prior "gave up" latch (operator reconnected).
        epoch_changed = epoch != self.active_epoch
        profile_changed = self.active_profile not in (None, want_profile)
        if self.gave_up_epoch is not None and self.gave_up_epoch != epoch:
            self.gave_up_epoch = None
        if running and (profile_changed or epoch_changed):
            self._stop_proc()
            self.backoff = 0.0
            self.next_start_at = 0.0
            running = False

        if running:
            self._write_status(desired)
            return

        # Process exited or never started: decide whether to (re)start.
        if self.proc is not None and self.proc.poll() is not None:
            code = self.proc.returncode
            self.proc = None
            self.active_profile = None
            if not auto_reconnect:
                # Operator opted out of auto-reconnect: latch on this epoch and
                # stay down until they explicitly reconnect (new epoch).
                self.gave_up_epoch = epoch
                self.last_error = "連線已結束（未啟用斷線自動重連）"
            else:
                self.last_error = f"OpenVPN 程序結束（code={code}）"
                self._bump_backoff()

        # With auto-reconnect off, do not relaunch once we've given up this epoch.
        if not auto_reconnect and self.gave_up_epoch == epoch:
            self._write_status(desired)
            return

        if time.time() >= self.next_start_at:
            self._start(want_profile, target_path, desired)
            self.backoff = 0.0
        self._write_status(desired)

    def run(self) -> None:
        _ensure_dirs()
        signal.signal(signal.SIGTERM, self._handle_term)
        signal.signal(signal.SIGINT, self._handle_term)
        while not self._stop:
            try:
                self.reconcile_once()
            except Exception as exc:  # never let the supervisor die
                self.last_error = f"supervisor error: {exc}"
            time.sleep(RECONCILE_INTERVAL)
        self._stop_proc("supervisor shutting down")

    def _handle_term(self, *_a: Any) -> None:
        self._stop = True


if __name__ == "__main__":
    Supervisor().run()
