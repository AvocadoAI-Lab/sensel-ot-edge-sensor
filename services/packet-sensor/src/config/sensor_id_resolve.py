"""Derive a stable, unique sensor_id from the host hostname.

When operators clone images or copy .env without changing SENSOR_ID, multiple
edges collide on the same MQTT credentials (ndr-{tenant}-{sensor_id}). This
module picks a per-host identifier automatically while still honouring an
explicit SENSOR_ID, platform.json, or sensor.yaml value.

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
    """Normalize a hostname fragment for use inside sensor_id."""
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


def _platform_config_path() -> Path:
    primary = Path(os.environ.get("PLATFORM_CONFIG_PATH", "/app/data/platform.json"))
    if primary.is_file():
        return primary
    alt = Path("/app/data/agent/platform.json")
    return alt if alt.is_file() else primary


def load_platform_sensor_id() -> str:
    path = _platform_config_path()
    if not path.is_file():
        return ""
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
        sid = str(raw.get("sensor_id") or "").strip()
        return sid if sid and not is_placeholder_sensor_id(sid) else ""
    except Exception:
        return ""


def _hostname_enabled() -> bool:
    return os.environ.get("SENSOR_ID_FROM_HOSTNAME", "1").lower() not in ("0", "false", "no")


def resolve_sensor_id(
    *,
    env_id: str = "",
    yaml_id: str = "",
    platform_id: str = "",
    allow_hostname: bool | None = None,
) -> str:
    """Return the effective sensor_id.

    Priority:
      1. SENSOR_ID env (non-placeholder)
      2. platform.json sensor_id (non-placeholder)
      3. sensor.yaml id (non-placeholder)
      4. hostname-derived (when enabled)
      5. ot-edge-001
    """
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
