"""Persist MQTT credentials auto-issued by the Control Plane at registration.

The Control Plane returns per-sensor MQTT credentials (username/password and the
broker endpoint) in the registration response. We persist them locally so the
agent can keep talking to the broker across restarts even before the next
registration completes. The plaintext secret is stored with ``0600`` perms in
the agent data dir (same trust boundary as the sensor's API key).
"""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger(__name__)


def credentials_path() -> Path:
    return Path(os.environ.get("MQTT_CREDENTIALS_PATH", "/app/data/mqtt-credentials.json"))


def load_persisted_credentials(path: Optional[Path] = None) -> Optional[dict[str, Any]]:
    """Return the last-persisted credentials, or ``None`` if absent/invalid."""
    p = path or credentials_path()
    if not p.is_file():
        return None
    try:
        raw = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        logger.warning("Ignoring unreadable MQTT credentials file at %s", p)
        return None
    if not isinstance(raw, dict):
        return None
    username = str(raw.get("username") or "").strip()
    if not username:
        return None
    return raw


def credentials_status(path: Optional[Path] = None) -> dict[str, Any]:
    """Return non-secret metadata about the persisted MQTT credentials.

    Safe to surface in the Edge Console / runtime snapshot: the plaintext
    password is **never** included — only whether Control-Plane credentials
    have "landed" locally and their identifying fields.
    """
    raw = load_persisted_credentials(path)
    if not raw:
        return {"landed": False}
    return {
        "landed": True,
        "username": str(raw.get("username") or ""),
        "host": raw.get("host"),
        "port": raw.get("port"),
        "tenant_id": raw.get("tenant_id"),
        "acl_version": raw.get("acl_version"),
    }


def persist_credentials(
    *,
    username: str,
    password: str,
    host: Optional[str] = None,
    port: Optional[int] = None,
    tenant_id: Optional[str] = None,
    acl_version: Optional[int] = None,
    path: Optional[Path] = None,
) -> bool:
    """Atomically write the credentials with ``0600`` perms. Returns success."""
    username = (username or "").strip()
    if not username:
        return False
    p = path or credentials_path()
    body: dict[str, Any] = {"username": username, "password": password or ""}
    if host:
        body["host"] = host
    if port:
        body["port"] = int(port)
    if tenant_id:
        body["tenant_id"] = tenant_id
    if acl_version is not None:
        body["acl_version"] = acl_version
    try:
        p.parent.mkdir(parents=True, exist_ok=True)
        tmp = p.with_suffix(p.suffix + ".tmp")
        tmp.write_text(json.dumps(body, indent=2), encoding="utf-8")
        try:
            os.chmod(tmp, 0o600)
        except OSError:
            pass
        os.replace(tmp, p)
        return True
    except OSError:
        logger.exception("Failed to persist MQTT credentials to %s", p)
        return False
