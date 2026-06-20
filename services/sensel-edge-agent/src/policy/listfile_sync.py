"""Pull the Control Plane managed black/white lists (P1 listfiles feed) and keep
a signed local cache the edge detection path can enforce.

Distinct from ``PolicySync`` (CTI ``blacklist.json`` IoC feed): this consumes the
OT protection-center *managed* lists at ``/api/v1/feed/{tenant}/listfiles.json``,
where ``blacklist`` = detect and ``whitelist`` = exclude, grouped by entry kind
(ip / cidr / domain / hash). The body is HMAC-signed (D8) and verified before use.
"""

from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Optional

import httpx

from src.config.settings import AppConfig
from src.policy.feed_signing import sha256_hex, verify_artifact
from src.policy.policy_ack import listfile_ack_payload

logger = logging.getLogger(__name__)

SCHEMA_VERSION = "ot_managed_listfile.v1"
ENTRY_KINDS = ("ip", "cidr", "domain", "hash")


@dataclass(frozen=True)
class ListfileSyncResult:
    ok: bool
    changed: bool
    status_code: int = 0
    item_count: int = 0
    artifact_version: str = ""
    tenant_id: str = ""
    error: str | None = None


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def build_cache_from_artifact(artifact: dict[str, Any], *, tenant_id: str, etag: str) -> dict[str, Any]:
    deny: dict[str, list[str]] = {k: [] for k in ENTRY_KINDS}
    allow: dict[str, list[str]] = {k: [] for k in ENTRY_KINDS}
    for lst in artifact.get("lists") or []:
        if not isinstance(lst, dict):
            continue
        kind = str(lst.get("entry_kind") or "").strip().lower()
        if kind not in ENTRY_KINDS:
            continue
        bucket = deny if str(lst.get("list_type") or "").strip().lower() == "blacklist" else allow
        for entry in lst.get("entries") or []:
            value = str(entry).strip()
            if value:
                bucket[kind].append(value)
    # Stable de-dup per kind while preserving insertion order.
    for bucket in (deny, allow):
        for kind in ENTRY_KINDS:
            bucket[kind] = list(dict.fromkeys(bucket[kind]))
    item_count = sum(len(v) for v in deny.values()) + sum(len(v) for v in allow.values())
    return {
        "schema_version": SCHEMA_VERSION,
        "tenant_id": tenant_id or str(artifact.get("tenant_id") or ""),
        "artifact_version": str(artifact.get("version") or ""),
        "updated_at": _utc_now(),
        "etag": etag,
        "deny": deny,
        "allow": allow,
        "item_count": item_count,
    }


class ListfileSync:
    """HTTP pull + signed apply for /api/v1/feed/{tenant_id}/listfiles.json."""

    def __init__(
        self,
        config: AppConfig,
        ack_callback: Optional[Callable[[dict[str, Any]], None]] = None,
    ) -> None:
        ps = config.policy_sync
        self._config = config
        self._ack_callback = ack_callback
        self._base = config.sensel.api_url.rstrip("/")
        self._enabled = bool(ps.listfile_enabled)
        self._feed_template = ps.listfile_feed_path_template
        self._cache_path = Path(ps.listfile_cache_path)
        self._stamp_path = Path(ps.listfile_stamp_path)
        self._signing_secret = (ps.ids_rule_signing_secret or config.sensel.api_key or "").strip()

    @property
    def enabled(self) -> bool:
        return self._enabled

    def _emit_ack(self, result: "ListfileSyncResult") -> None:
        if self._ack_callback is None:
            return
        try:
            self._ack_callback(listfile_ack_payload(result))
        except Exception:  # noqa: BLE001 - ACK reporting must never break apply
            logger.debug("Listfile ACK callback failed", exc_info=True)

    def _load_cache(self) -> dict[str, Any]:
        if not self._cache_path.is_file():
            return {}
        try:
            raw = json.loads(self._cache_path.read_text(encoding="utf-8"))
            return raw if isinstance(raw, dict) else {}
        except (OSError, json.JSONDecodeError):
            return {}

    def _write_cache(self, cache: dict[str, Any]) -> None:
        self._cache_path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self._cache_path.with_suffix(self._cache_path.suffix + ".tmp")
        tmp.write_text(json.dumps(cache, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        try:
            os.chmod(tmp, 0o600)
        except OSError:
            pass
        tmp.replace(self._cache_path)
        self._stamp_path.parent.mkdir(parents=True, exist_ok=True)
        self._stamp_path.write_text(str(cache.get("updated_at") or _utc_now()) + "\n", encoding="utf-8")

    def _resolve_tenant_id(self) -> str | None:
        override = (self._config.policy_sync.feed_tenant_id or "").strip()
        if override:
            return override
        tenant = (self._config.northbound_mqtt.tenant_id or "").strip()
        if tenant and tenant != "default":
            return tenant
        if self._config.northbound_mqtt.require_tenant:
            return None
        return tenant or None

    def _feed_url(self, tenant_id: str) -> str:
        path = self._feed_template.format(tenant_id=tenant_id)
        if not path.startswith("/"):
            path = f"/{path}"
        return f"{self._base}{path}"

    def pull_http_feed(self, *, force: bool = False) -> ListfileSyncResult:
        if not self._enabled:
            return ListfileSyncResult(ok=True, changed=False, error="listfile_disabled")

        tenant_id = self._resolve_tenant_id()
        if not tenant_id:
            msg = "tenant_id unresolved (set POLICY_SYNC_TENANT_ID or register sensor)"
            logger.warning("Listfile sync skipped: %s", msg)
            return ListfileSyncResult(ok=False, changed=False, error=msg)

        headers = {"Accept": "application/json"}
        intel_key = (self._config.policy_sync.smb_intel_api_key or "").strip()
        if intel_key:
            headers["X-API-Key"] = intel_key
        etag = str(self._load_cache().get("etag") or "")
        if etag and not force:
            headers["If-None-Match"] = f'"{etag}"'

        try:
            with httpx.Client(timeout=30.0, verify=self._config.sensel.verify_tls) as client:
                response = client.get(self._feed_url(tenant_id), headers=headers)
        except httpx.HTTPError as exc:
            logger.warning("Listfile sync HTTP error: %s", exc)
            return ListfileSyncResult(ok=False, changed=False, tenant_id=tenant_id, error=str(exc))

        if response.status_code == 304:
            cache = self._load_cache()
            return ListfileSyncResult(
                ok=True, changed=False, status_code=304, tenant_id=tenant_id,
                artifact_version=str(cache.get("artifact_version") or ""),
                item_count=int(cache.get("item_count") or 0),
            )
        if response.status_code >= 400:
            detail = response.text[:300]
            logger.warning("Listfile sync failed (%s): %s", response.status_code, detail)
            return ListfileSyncResult(
                ok=False, changed=False, status_code=response.status_code,
                tenant_id=tenant_id, error=detail or f"HTTP {response.status_code}",
            )

        body = response.content
        signature = response.headers.get("X-Signature") or ""
        if not verify_artifact(body, signature, tenant_id=tenant_id, base_secret=self._signing_secret):
            logger.error("Listfile sync signature verification failed tenant=%s", tenant_id)
            result = ListfileSyncResult(
                ok=False, changed=False, status_code=response.status_code,
                tenant_id=tenant_id, error="signature verification failed",
            )
            self._emit_ack(result)
            return result

        try:
            artifact = response.json()
        except ValueError as exc:
            return ListfileSyncResult(
                ok=False, changed=False, status_code=response.status_code,
                tenant_id=tenant_id, error=f"invalid JSON: {exc}",
            )
        if not isinstance(artifact, dict):
            return ListfileSyncResult(
                ok=False, changed=False, status_code=response.status_code,
                tenant_id=tenant_id, error="feed payload is not a JSON object",
            )

        new_etag = (response.headers.get("etag") or "").strip().strip('"') or sha256_hex(body)
        return self.apply_artifact(
            artifact, tenant_id=tenant_id, etag=new_etag, status_code=response.status_code
        )

    def apply_artifact(
        self,
        artifact: dict[str, Any],
        *,
        tenant_id: str,
        etag: str = "",
        status_code: int = 200,
    ) -> ListfileSyncResult:
        if not self._enabled:
            return ListfileSyncResult(ok=True, changed=False, status_code=status_code, error="listfile_disabled")

        resolved_etag = etag or sha256_hex(
            json.dumps(artifact, ensure_ascii=False, sort_keys=True).encode("utf-8")
        )
        existing = self._load_cache()
        if (
            existing
            and str(existing.get("etag") or "") == resolved_etag
            and str(existing.get("artifact_version") or "") == str(artifact.get("version") or "")
        ):
            return ListfileSyncResult(
                ok=True, changed=False, status_code=status_code, tenant_id=tenant_id,
                artifact_version=str(existing.get("artifact_version") or ""),
                item_count=int(existing.get("item_count") or 0),
            )

        cache = build_cache_from_artifact(artifact, tenant_id=tenant_id, etag=resolved_etag)
        self._write_cache(cache)
        logger.info(
            "Listfile sync OK tenant=%s version=%s items=%s",
            tenant_id, cache.get("artifact_version"), cache.get("item_count"),
        )
        result = ListfileSyncResult(
            ok=True, changed=True, status_code=status_code, tenant_id=tenant_id,
            artifact_version=str(cache.get("artifact_version") or ""),
            item_count=int(cache.get("item_count") or 0),
        )
        self._emit_ack(result)
        return result
