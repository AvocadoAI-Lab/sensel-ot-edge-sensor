"""Best-effort hardware / platform detection for the edge sensor.

The platform shows a short label under each registered sensor (e.g. "pi4",
"ubuntu", "ubuntu-docker", "ubuntu-docker-win"). Historically this value was a
static string ("ubuntu" by default), so the column was inaccurate whenever the
operator forgot to set it. This module derives an accurate label at runtime.

All probes are best-effort and never raise; on any failure we fall back to a
generic label so registration is never blocked.

Examples produced:
  - Raspberry Pi 4 (bare metal)           -> "pi4"
  - Generic Ubuntu host (bare metal)      -> "ubuntu"
  - Linux container on a Linux host       -> "ubuntu-docker"
  - Linux container on Docker Desktop/WSL -> "ubuntu-docker-win"
  - Windows host (native)                 -> "windows"
"""

from __future__ import annotations

import platform
import re
from functools import lru_cache
from pathlib import Path


def _read_text(path: str) -> str:
    try:
        return Path(path).read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return ""


def _raspberry_pi_model() -> str | None:
    """Return "pi4"/"pi5"/… when running on a Raspberry Pi, else None."""
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


def _os_release_id() -> str | None:
    """Return the distro ID from /etc/os-release (e.g. "ubuntu", "debian")."""
    text = _read_text("/etc/os-release")
    for line in text.splitlines():
        key, sep, value = line.partition("=")
        if sep and key.strip() == "ID":
            cleaned = value.strip().strip('"').strip("'").lower()
            if cleaned:
                return cleaned
    return None


def _in_container() -> bool:
    if Path("/.dockerenv").exists() or Path("/run/.containerenv").exists():
        return True
    cgroup = _read_text("/proc/1/cgroup") + _read_text("/proc/self/cgroup")
    return any(tok in cgroup for tok in ("docker", "containerd", "kubepods", "/lxc"))


def _windows_host_under_linux_container() -> bool:
    """Detect Docker Desktop on Windows (WSL2 backend) from inside a container.

    Docker Desktop runs Linux containers on a WSL2 kernel whose version string
    contains "microsoft"/"WSL", which lets us flag the host as Windows even
    though the container itself is Linux.
    """
    marker = (_read_text("/proc/version") + " " + platform.release()).lower()
    return "microsoft" in marker or "wsl" in marker


@lru_cache(maxsize=1)
def detect_hardware() -> str:
    """Return a concise, accurate platform label. Never raises."""
    try:
        system = platform.system()
        if system == "Windows":
            return "windows"
        if system == "Darwin":
            return "macos"

        # Linux (bare metal or container)
        pi = _raspberry_pi_model()
        base = pi or _os_release_id() or "linux"
        if _in_container():
            return f"{base}-docker-win" if _windows_host_under_linux_container() else f"{base}-docker"
        return base
    except Exception:
        return "unknown"
