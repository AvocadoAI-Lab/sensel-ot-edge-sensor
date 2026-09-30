"""Load and hot-reload IoC cache written by edge-agent policy sync."""

from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


def _parse_iso(value: str) -> datetime | None:
    if not value:
        return None
    try:
        text = value.replace("Z", "+00:00")
        return datetime.fromisoformat(text)
    except ValueError:
        return None


@dataclass
class IocEntry:
    item_id: str
    confidence: int | None
    expires_at: datetime | None


@dataclass
class IocCacheStore:
    cache_path: Path
    stamp_path: Path
    reload_check_sec: float = 5.0
    _ipv4: dict[str, IocEntry] = field(default_factory=dict, init=False)
    _artifact_version: str = field(default="", init=False)
    _tenant_id: str = field(default="", init=False)
    _etag: str = field(default="", init=False)
    _last_stamp_mtime: float = field(default=0.0, init=False)
    _last_check_monotonic: float = field(default=0.0, init=False)
    _loaded: bool = field(default=False, init=False)

    def maybe_reload(self, *, force: bool = False) -> bool:
        now = time.monotonic()
        if not force and self._loaded and (now - self._last_check_monotonic) < self.reload_check_sec:
            return False
        self._last_check_monotonic = now

        stamp_mtime = 0.0
        if self.stamp_path.is_file():
            try:
                stamp_mtime = self.stamp_path.stat().st_mtime
            except OSError:
                stamp_mtime = 0.0
        elif self.cache_path.is_file():
            try:
                stamp_mtime = self.cache_path.stat().st_mtime
            except OSError:
                stamp_mtime = 0.0

        if self._loaded and not force and stamp_mtime == self._last_stamp_mtime:
            return False

        if not self.cache_path.is_file():
            if self._loaded:
                logger.info("IoC cache removed; clearing local index")
            self._ipv4 = {}
            self._artifact_version = ""
            self._tenant_id = ""
            self._etag = ""
            self._last_stamp_mtime = stamp_mtime
            self._loaded = True
            return True

        try:
            raw = json.loads(self.cache_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            logger.warning("IoC cache read failed: %s", exc)
            return False

        if not isinstance(raw, dict):
            logger.warning("IoC cache payload is not an object")
            return False

        now_utc = datetime.now(timezone.utc)
        ipv4: dict[str, IocEntry] = {}
        for ip, meta in (raw.get("ipv4") or {}).items():
            if not isinstance(meta, dict):
                continue
            expires_at = _parse_iso(str(meta.get("expires_at") or ""))
            if expires_at and expires_at <= now_utc:
                continue
            ipv4[str(ip)] = IocEntry(
                item_id=str(meta.get("item_id") or ""),
                confidence=meta.get("confidence") if meta.get("confidence") is not None else None,
                expires_at=expires_at,
            )

        self._ipv4 = ipv4
        self._artifact_version = str(raw.get("artifact_version") or "")
        self._tenant_id = str(raw.get("tenant_id") or "")
        self._etag = str(raw.get("etag") or "")
        self._last_stamp_mtime = stamp_mtime
        self._loaded = True
        logger.info(
            "IoC cache loaded tenant=%s version=%s entries=%d",
            self._tenant_id,
            self._artifact_version,
            len(self._ipv4),
        )
        return True

    def lookup_ipv4(self, ip: str | None) -> IocEntry | None:
        if not ip:
            return None
        self.maybe_reload()
        return self._ipv4.get(ip)

    @property
    def artifact_version(self) -> str:
        return self._artifact_version

    @property
    def tenant_id(self) -> str:
        return self._tenant_id

    @property
    def entry_count(self) -> int:
        return len(self._ipv4)
