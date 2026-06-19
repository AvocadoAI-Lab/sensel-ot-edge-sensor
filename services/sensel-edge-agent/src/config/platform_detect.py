"""Best-effort hardware / platform detection for the edge sensor.

The platform shows a short label under each registered sensor (e.g. "pi4",
"ubuntu", "windows-docker"). Historically this value was a static string
("ubuntu" by default), so the column was inaccurate whenever the operator
forgot to set it. This module derives an accurate label at runtime.

IMPORTANT: the agent normally runs inside a container, so the *container* base
image (e.g. debian for python:slim) is NOT a reliable signal for the host.
We therefore probe host-visible sources first:

  - Raspberry Pi model via device-tree/cpuinfo (host hardware)  -> "pi4"/"pi5"
  - host distro from /proc/version (the host kernel build string) -> "ubuntu"
  - Docker Desktop on Windows (WSL2 kernel marker)               -> "windows-docker"

Only as a last resort do we fall back to the container's /etc/os-release.

All probes are best-effort and never raise; on any failure we return a generic
label so registration is never blocked.
"""

from __future__ import annotations

import platform
import re
from functools import lru_cache
from pathlib import Path

# Distro tokens recognised inside the host kernel build string (/proc/version).
_KNOWN_DISTROS = ("ubuntu", "debian", "alpine", "fedora", "centos", "arch", "raspbian", "gentoo")


def _read_text(path: str) -> str:
    try:
        return Path(path).read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return ""


def _raspberry_pi_model() -> str | None:
    """Return "pi4"/"pi5"/… when running on a Raspberry Pi, else None.

    /sys/firmware/devicetree is bind-mounted from the host into containers, so
    this works even when the agent is containerised on a Pi.
    """
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
    """Infer the host OS from the kernel build string (host-owned, not the container).

    /proc/version reflects the *host* kernel even inside a container, e.g.
    "... (Ubuntu 15.2.0-...)" on an Ubuntu host, or "...microsoft-standard-WSL2..."
    under Docker Desktop on Windows.
    """
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
    """Return the distro ID from /etc/os-release (container's, used as fallback)."""
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
    """Return a concise, accurate host-platform label. Never raises."""
    try:
        system = platform.system()
        if system == "Windows":
            return "windows"
        if system == "Darwin":
            return "macos"

        # Linux: prefer host-visible signals over the container base image.
        pi = _raspberry_pi_model()
        if pi:
            return pi
        host = _host_os_from_kernel()
        if host:
            return host
        return _os_release_id() or "linux"
    except Exception:
        return "unknown"
