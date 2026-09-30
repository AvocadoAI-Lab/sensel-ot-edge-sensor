"""Enforce OT protection-center managed whitelist before detection / northbound.

Reads ``managed-listfiles.json`` (``allow`` bucket from listfile_sync) and excludes
matching indicators so whitelisted traffic does not generate or report events (G6).
"""

from __future__ import annotations

import ipaddress
import json
import time
from pathlib import Path
from typing import Any


class ManagedListfileEnforcer:
    """Hot-reload managed whitelist cache written by ``ListfileSync``."""

    def __init__(
        self,
        cache_path: str | Path,
        stamp_path: str | Path,
        *,
        reload_check_sec: float = 5.0,
    ) -> None:
        self._cache_path = Path(cache_path)
        self._stamp_path = Path(stamp_path)
        self._reload_check_sec = max(float(reload_check_sec), 0.0)
        self._last_check = 0.0
        self._stamp_mtime = 0.0
        self._allow_ips: set[str] = set()
        self._allow_cidrs: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
        self._allow_domains: set[str] = set()
        self._allow_hashes: set[str] = set()

    def maybe_reload(self, *, force: bool = False) -> bool:
        now = time.monotonic()
        if not force and (now - self._last_check) < self._reload_check_sec:
            return False
        self._last_check = now
        stamp_mtime = self._stamp_path.stat().st_mtime if self._stamp_path.is_file() else 0.0
        if not force and stamp_mtime == self._stamp_mtime and self._allow_ips:
            return False
        self._stamp_mtime = stamp_mtime
        self._load()
        return True

    def _load(self) -> None:
        self._allow_ips = set()
        self._allow_cidrs = []
        self._allow_domains = set()
        self._allow_hashes = set()
        if not self._cache_path.is_file():
            return
        try:
            raw = json.loads(self._cache_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return
        if not isinstance(raw, dict):
            return
        allow = raw.get("allow") if isinstance(raw.get("allow"), dict) else {}
        for ip in allow.get("ip") or []:
            value = str(ip).strip()
            if value:
                self._allow_ips.add(value)
        for cidr in allow.get("cidr") or []:
            value = str(cidr).strip()
            if not value:
                continue
            try:
                self._allow_cidrs.append(ipaddress.ip_network(value, strict=False))
            except ValueError:
                continue
        for domain in allow.get("domain") or []:
            value = str(domain).strip().lower()
            if value:
                self._allow_domains.add(value)
        for digest in allow.get("hash") or []:
            value = str(digest).strip().lower()
            if value:
                self._allow_hashes.add(value)

    def is_ip_whitelisted(self, ip: str | None) -> bool:
        value = str(ip or "").strip()
        if not value:
            return False
        if value in self._allow_ips:
            return True
        try:
            addr = ipaddress.ip_address(value)
        except ValueError:
            return False
        return any(addr in net for net in self._allow_cidrs)

    def is_domain_whitelisted(self, domain: str | None) -> bool:
        value = str(domain or "").strip().lower()
        return bool(value) and value in self._allow_domains

    def is_hash_whitelisted(self, digest: str | None) -> bool:
        value = str(digest or "").strip().lower()
        return bool(value) and value in self._allow_hashes

    def is_event_whitelisted(self, event: dict[str, Any]) -> bool:
        """Return True when the event should be excluded (managed whitelist hit)."""
        for field in ("src_ip", "dst_ip"):
            if self.is_ip_whitelisted(str(event.get(field) or "")):
                return True
        evidence = event.get("evidence") if isinstance(event.get("evidence"), dict) else {}
        ioc_value = str(evidence.get("ioc_value") or "").strip()
        ioc_type = str(evidence.get("ioc_type") or "").lower()
        if ioc_type in ("ipv4", "ip", "") and ioc_value and self.is_ip_whitelisted(ioc_value):
            return True
        if ioc_type == "domain" and self.is_domain_whitelisted(ioc_value):
            return True
        if ioc_type == "hash" and self.is_hash_whitelisted(ioc_value):
            return True
        domain = str(evidence.get("domain") or "").strip()
        if domain and self.is_domain_whitelisted(domain):
            return True
        file_hash = str(evidence.get("hash") or evidence.get("file_hash") or "").strip()
        if file_hash and self.is_hash_whitelisted(file_hash):
            return True
        return False
