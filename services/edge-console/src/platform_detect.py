"""Best-effort host hardware/platform detection for the Edge Console.

Mirrors the edge agent's detection so the platform.json written by the console
carries an accurate "hardware" label (e.g. "pi4", "ubuntu", "windows-docker")
instead of a hardcoded default. The console runs in a container, so we probe
host-visible signals (Raspberry Pi device-tree, the host kernel build string in
/proc/version) rather than the container base image. Never raises.
"""

from __future__ import annotations

import platform
import re
from functools import lru_cache
from pathlib import Path

_KNOWN_DISTROS = ("ubuntu", "debian", "alpine", "fedora", "centos", "arch", "raspbian", "gentoo")


def _read_text(path: str) -> str:
    try:
        return Path(path).read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return ""


def _raspberry_pi_model() -> str | None:
    for candidate in ("/proc/device-tree/model", "/sys/firmware/devicetree/base/model"):
        text = _read_text(candidate).replace("\x00", "")
        if "raspberry pi" in text.lower():
            m = re.search(r"raspberry pi\s*(\d+)", text, re.IGNORECASE)
            return f"pi{m.group(1)}" if m else "pi"
    cpuinfo = _read_text("/proc/cpuinfo").lower()
    if "raspberry pi" in cpuinfo:
        m = re.search(r"raspberry pi\s*(\d+)", cpuinfo)
        return f"pi{m.group(1)}" if m else "pi"
    return None


def _host_os_from_kernel() -> str | None:
    marker = (_read_text("/proc/version") + " " + platform.release()).lower()
    if not marker.strip():
        return None
    if "microsoft" in marker or "wsl" in marker:
        return "windows-docker"
    for distro in _KNOWN_DISTROS:
        if distro in marker:
            return distro
    return None


def _os_release_id() -> str | None:
    text = _read_text("/etc/os-release")
    for line in text.splitlines():
        key, sep, value = line.partition("=")
        if sep and key.strip() == "ID":
            cleaned = value.strip().strip('"').strip("'").lower()
            if cleaned:
                return cleaned
    return None


@lru_cache(maxsize=1)
def detect_hardware() -> str:
    try:
        system = platform.system()
        if system == "Windows":
            return "windows"
        if system == "Darwin":
            return "macos"
        pi = _raspberry_pi_model()
        if pi:
            return pi
        host = _host_os_from_kernel()
        if host:
            return host
        return _os_release_id() or "linux"
    except Exception:
        return "unknown"
