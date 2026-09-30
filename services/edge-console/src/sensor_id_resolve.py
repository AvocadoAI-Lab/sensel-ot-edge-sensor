"""Derive a stable, unique sensor_id from the host hostname.

Mirrors the edge agent module so platform.json and the setup wizard carry a
unique sensor_id per host instead of the shared ot-edge-001 default.
Never raises.
"""

from __future__ import annotations

import json
import os
import re
import socket
from functools import lru_cache
from pathlib import Path

_PLACEHOLDER_IDS = frozenset({"", "ot-edge-001"})
_MAX_LEN = 64
_PREFIX = "ot-edge"
_ID_PATTERN = re.compile(r"[^a-z0-9_-]+")


def _read_hostname_file() -> str:
    try:
        text = Path("/etc/hostname").read_text(encoding="utf-8", errors="ignore").strip()
        if text:
            return text.split(".")[0]
    except Exception:
        pass
    return ""


@lru_cache(maxsize=1)
def get_hostname() -> str:
    """Return the short host name (no domain suffix). Never raises."""
    try:
        name = (_read_hostname_file() or socket.gethostname() or "").strip()
        return name.split(".")[0] if name else ""
    except Exception:
        return ""


def sanitize_sensor_token(value: str) -> str:
    cleaned = value.strip().lower().replace(".", "-").replace(" ", "-")
    cleaned = _ID_PATTERN.sub("-", cleaned)
    cleaned = re.sub(r"-+", "-", cleaned).strip("-_")
    return cleaned[:_MAX_LEN]


def sensor_id_from_hostname(*, prefix: str = _PREFIX) -> str:
    host = sanitize_sensor_token(get_hostname()) or "unknown"
    pref = sanitize_sensor_token(prefix) or _PREFIX
    if host.startswith(f"{pref}-") or host == pref:
        sensor_id = host
    else:
        sensor_id = f"{pref}-{host}"
    return sensor_id[:_MAX_LEN]


def is_placeholder_sensor_id(value: str | None) -> bool:
    if value is None:
        return True
    return value.strip().lower() in _PLACEHOLDER_IDS


def should_auto_assign_from_hostname(
    sensor_id: str,
    *,
    configured: bool,
    registered: bool,
) -> bool:
    """Only replace placeholder IDs before a successful registration."""
    if not is_placeholder_sensor_id(sensor_id):
        return False
    if configured and registered:
        return False
    return True


def _hostname_enabled() -> bool:
    return os.environ.get("SENSOR_ID_FROM_HOSTNAME", "1").lower() not in ("0", "false", "no")


def resolve_sensor_id(
    *,
    env_id: str = "",
    yaml_id: str = "",
    platform_id: str = "",
    allow_hostname: bool | None = None,
) -> str:
    sensor_id, _ = resolve_sensor_id_with_source(
        env_id=env_id,
        yaml_id=yaml_id,
        platform_id=platform_id,
        allow_hostname=allow_hostname,
    )
    return sensor_id


def resolve_sensor_id_with_source(
    *,
    env_id: str = "",
    yaml_id: str = "",
    platform_id: str = "",
    allow_hostname: bool | None = None,
) -> tuple[str, str]:
    if allow_hostname is None:
        allow_hostname = _hostname_enabled()

    for source, candidate in (
        ("env", env_id),
        ("platform", platform_id),
        ("yaml", yaml_id),
    ):
        if candidate and not is_placeholder_sensor_id(candidate):
            return candidate.strip(), source

    if allow_hostname:
        derived = sensor_id_from_hostname()
        if derived:
            return derived, "hostname"

    return "ot-edge-001", "fallback"
