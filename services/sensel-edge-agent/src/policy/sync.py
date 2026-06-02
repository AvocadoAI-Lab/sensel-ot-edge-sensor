"""Pull CTI blacklist from SenseL Control Plane and persist local IoC cache."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import httpx

from src.config.settings import AppConfig
from src.policy.ioc_cache import build_cache_from_artifact, load_cache, write_cache, write_stamp

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class PolicySyncResult:
    ok: bool
    changed: bool
    status_code: int
    item_count: int = 0
    artifact_version: str = ""
    tenant_id: str = ""
    error: str | None = None


class PolicySync:
    """HTTP pull sync for /api/v1/feed/{tenant_id}/blacklist.json."""

    def __init__(self, config: AppConfig) -> None:
        self._config = config
        self._base = config.sensel.api_url.rstrip("/")
        self._cache_path = Path(config.policy_sync.cache_path)
        self._stamp_path = Path(config.policy_sync.stamp_path)
        self._last_etag = ""
        existing = load_cache(self._cache_path)
        if existing:
            self._last_etag = str(existing.get("etag") or "")

    def resolve_feed_tenant_id(self) -> str | None:
        override = (self._config.policy_sync.feed_tenant_id or "").strip()
        if override:
            return override
        return self.resolve_tenant_id()

    def resolve_tenant_id(self) -> str | None:
        tenant = (self._config.northbound_mqtt.tenant_id or "").strip()
        if tenant and tenant != "default":
            return tenant
        cached = load_cache(self._cache_path)
        if cached:
            cached_tenant = str(cached.get("tenant_id") or "").strip()
            if cached_tenant and cached_tenant != "default":
                return cached_tenant
        if self._config.northbound_mqtt.require_tenant:
            return None
        return tenant or None

    def _feed_url(self, tenant_id: str) -> str:
        template = self._config.policy_sync.feed_path_template
        path = template.format(tenant_id=tenant_id)
        if not path.startswith("/"):
            path = f"/{path}"
        return f"{self._base}{path}"

    def _request_headers(self) -> dict[str, str]:
        headers = {"Accept": "application/json"}
        intel_key = (self._config.policy_sync.smb_intel_api_key or "").strip()
        if intel_key:
            headers["X-API-Key"] = intel_key
        if self._last_etag:
            headers["If-None-Match"] = f'"{self._last_etag}"'
        return headers

    def pull_http_feed(self, *, force: bool = False) -> PolicySyncResult:
        if not self._config.policy_sync.enabled:
            return PolicySyncResult(
                ok=True,
                changed=False,
                status_code=0,
                error="policy_sync_disabled",
            )

        tenant_id = self.resolve_feed_tenant_id()
        if not tenant_id:
            msg = "tenant_id unresolved (set POLICY_SYNC_TENANT_ID or register sensor)"
            logger.warning("Policy sync skipped: %s", msg)
            return PolicySyncResult(ok=False, changed=False, status_code=0, error=msg)

        url = self._feed_url(tenant_id)
        headers = self._request_headers()
        if force:
            headers.pop("If-None-Match", None)

        try:
            with httpx.Client(timeout=30.0, verify=self._config.sensel.verify_tls) as client:
                response = client.get(url, headers=headers)
        except httpx.HTTPError as exc:
            logger.warning("Policy sync HTTP error: %s", exc)
            return PolicySyncResult(
                ok=False,
                changed=False,
                status_code=0,
                tenant_id=tenant_id,
                error=str(exc),
            )

        if response.status_code == 304:
            logger.debug("Policy sync unchanged (304) tenant=%s", tenant_id)
            return PolicySyncResult(
                ok=True,
                changed=False,
                status_code=304,
                tenant_id=tenant_id,
                artifact_version=str((load_cache(self._cache_path) or {}).get("artifact_version") or ""),
                item_count=int((load_cache(self._cache_path) or {}).get("item_count") or 0),
            )

        if response.status_code == 404:
            msg = f"no blacklist artifact for tenant {tenant_id}"
            logger.warning("Policy sync: %s", msg)
            return PolicySyncResult(
                ok=False,
                changed=False,
                status_code=404,
                tenant_id=tenant_id,
                error=msg,
            )

        if response.status_code >= 400:
            detail = response.text[:300]
            logger.warning("Policy sync failed (%s): %s", response.status_code, detail)
            return PolicySyncResult(
                ok=False,
                changed=False,
                status_code=response.status_code,
                tenant_id=tenant_id,
                error=detail or f"HTTP {response.status_code}",
            )

        try:
            artifact = response.json()
        except ValueError as exc:
            return PolicySyncResult(
                ok=False,
                changed=False,
                status_code=response.status_code,
                tenant_id=tenant_id,
                error=f"invalid JSON: {exc}",
            )

        if not isinstance(artifact, dict):
            return PolicySyncResult(
                ok=False,
                changed=False,
                status_code=response.status_code,
                tenant_id=tenant_id,
                error="feed payload is not a JSON object",
            )

        etag_header = (response.headers.get("etag") or "").strip().strip('"')
        return self.apply_artifact(
            artifact,
            tenant_id=tenant_id,
            etag=etag_header,
            source="http",
            status_code=response.status_code,
        )

    def apply_artifact(
        self,
        artifact: dict[str, Any],
        *,
        tenant_id: str,
        etag: str = "",
        source: str = "http",
        status_code: int = 200,
    ) -> PolicySyncResult:
        if not self._config.policy_sync.enabled:
            return PolicySyncResult(
                ok=True,
                changed=False,
                status_code=status_code,
                error="policy_sync_disabled",
            )

        manifest = artifact.get("manifest") or {}
        resolved_etag = etag or str(manifest.get("sha256") or "")
        existing = load_cache(self._cache_path)
        if (
            existing
            and resolved_etag
            and str(existing.get("etag") or "") == resolved_etag
            and str(existing.get("artifact_version") or "")
            == str(artifact.get("version") or "")
        ):
            return PolicySyncResult(
                ok=True,
                changed=False,
                status_code=status_code,
                tenant_id=tenant_id,
                artifact_version=str(existing.get("artifact_version") or ""),
                item_count=int(existing.get("item_count") or 0),
            )

        cache = build_cache_from_artifact(artifact, tenant_id=tenant_id, etag=resolved_etag)
        write_cache(self._cache_path, cache)
        write_stamp(self._stamp_path, updated_at=str(cache["updated_at"]))
        if resolved_etag:
            self._last_etag = resolved_etag

        logger.info(
            "Policy sync OK via %s tenant=%s version=%s items=%s",
            source,
            tenant_id,
            cache.get("artifact_version"),
            cache.get("item_count"),
        )
        return PolicySyncResult(
            ok=True,
            changed=True,
            status_code=status_code,
            tenant_id=tenant_id,
            artifact_version=str(cache.get("artifact_version") or ""),
            item_count=int(cache.get("item_count") or 0),
        )
