"""Local IoC cache built from Control Plane blacklist feed artifacts."""

from __future__ import annotations

import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

SCHEMA_VERSION = "1.0"
IP_IOC_TYPES = frozenset({"ipv4", "ip"})
DOMAIN_IOC_TYPE = "domain"
HASH_IOC_TYPE = "hash"


def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def build_cache_from_artifact(
    artifact: dict[str, Any],
    *,
    tenant_id: str,
    etag: str = "",
) -> dict[str, Any]:
    """Normalize blacklist.json payload into edge-local ioc-cache.json."""
    now = _now_utc()
    default_ttl = int(artifact.get("ttl_default_seconds") or 86400)
    ipv4: dict[str, dict[str, Any]] = {}
    domain: dict[str, dict[str, Any]] = {}
    hash_map: dict[str, dict[str, Any]] = {}

    for item in artifact.get("items") or []:
        if not isinstance(item, dict):
            continue
        if item.get("revoke"):
            continue
        ioc_type = str(item.get("ioc_type") or "").strip().lower()
        value = str(item.get("value") or "").strip()
        if not value:
            continue
        ttl_seconds = int(item.get("ttl_seconds") or default_ttl)
        expires_at = (now + timedelta(seconds=max(ttl_seconds, 60))).isoformat()
        entry = {
            "item_id": str(item.get("item_id") or ""),
            "confidence": item.get("confidence"),
            "expires_at": expires_at,
            "revoke": False,
        }
        if ioc_type in IP_IOC_TYPES:
            ipv4[value] = entry
        elif ioc_type == DOMAIN_IOC_TYPE:
            domain[value.lower()] = entry
        elif ioc_type == HASH_IOC_TYPE:
            hash_map[value.lower()] = entry

    manifest = artifact.get("manifest") or {}
    resolved_etag = etag or str(manifest.get("sha256") or "")

    return {
        "schema_version": SCHEMA_VERSION,
        "tenant_id": tenant_id or str(artifact.get("tenant_id") or ""),
        "artifact_version": str(artifact.get("version") or ""),
        "updated_at": now.isoformat(),
        "etag": resolved_etag,
        "ipv4": ipv4,
        "domain": domain,
        "hash": hash_map,
        "item_count": len(ipv4) + len(domain) + len(hash_map),
    }


def load_cache(path: Path | str) -> dict[str, Any] | None:
    cache_path = Path(path)
    if not cache_path.is_file():
        return None
    try:
        raw = json.loads(cache_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return raw if isinstance(raw, dict) else None


def write_cache(path: Path | str, cache: dict[str, Any]) -> None:
    """Atomic write with mode 600."""
    cache_path = Path(path)
    cache_path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = cache_path.with_suffix(cache_path.suffix + ".tmp")
    tmp_path.write_text(json.dumps(cache, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    try:
        os.chmod(tmp_path, 0o600)
    except OSError:
        pass
    tmp_path.replace(cache_path)


def write_stamp(stamp_path: Path | str, *, updated_at: str) -> None:
    stamp = Path(stamp_path)
    stamp.parent.mkdir(parents=True, exist_ok=True)
    stamp.write_text(updated_at + "\n", encoding="utf-8")
    try:
        os.chmod(stamp, 0o600)
    except OSError:
        pass
