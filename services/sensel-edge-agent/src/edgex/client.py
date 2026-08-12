"""Small, bounded client for the EdgeX 4 Core Metadata v3 API."""

from __future__ import annotations

from typing import Any
from urllib.parse import quote

import httpx


class EdgeXMetadataError(RuntimeError):
    """Core Metadata is unavailable or returned an invalid response."""


def _unwrap_list(payload: Any, key: str) -> list[dict[str, Any]]:
    if isinstance(payload, list):
        values = payload
    elif isinstance(payload, dict):
        values = payload.get(key, [])
    else:
        values = []
    return [dict(value) for value in values if isinstance(value, dict)]


class EdgeXMetadataClient:
    def __init__(
        self,
        base_url: str,
        *,
        timeout_sec: float = 5.0,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self._client = httpx.Client(
            base_url=self.base_url,
            timeout=timeout_sec,
            transport=transport,
        )

    def _json(self, path: str) -> Any:
        try:
            response = self._client.get(path)
            response.raise_for_status()
            return response.json()
        except (httpx.HTTPError, ValueError) as exc:
            raise EdgeXMetadataError(f"EdgeX GET {path} failed: {exc}") from exc

    def ping(self) -> bool:
        try:
            response = self._client.get("/api/v3/ping")
            return response.status_code == 200
        except httpx.HTTPError:
            return False

    def _paged(self, path: str, key: str, *, page_size: int = 1000) -> list[dict[str, Any]]:
        result: list[dict[str, Any]] = []
        offset = 0
        while len(result) < 10_000:
            try:
                response = self._client.get(
                    path, params={"offset": offset, "limit": page_size}
                )
                response.raise_for_status()
                payload = response.json()
            except (httpx.HTTPError, ValueError) as exc:
                raise EdgeXMetadataError(f"EdgeX GET {path} failed: {exc}") from exc
            page = _unwrap_list(payload, key)
            result.extend(page)
            total = int(payload.get("totalCount", 0)) if isinstance(payload, dict) else 0
            if not page or len(page) < page_size or (total and len(result) >= total):
                break
            offset += len(page)
        return result

    def list_devices(self) -> list[dict[str, Any]]:
        return self._paged("/api/v3/device/all", "devices")

    def get_device(self, name: str) -> dict[str, Any]:
        payload = self._json(f"/api/v3/device/name/{quote(name, safe='')}")
        if isinstance(payload, dict) and isinstance(payload.get("device"), dict):
            return dict(payload["device"])
        if isinstance(payload, dict) and payload.get("name"):
            return dict(payload)
        raise EdgeXMetadataError(f"EdgeX device not found in response: {name}")

    def list_device_profiles(self) -> list[dict[str, Any]]:
        return self._paged("/api/v3/deviceprofile/all", "profiles")

    def update_device(self, device: dict[str, Any]) -> None:
        """Apply one complete device update through Core Metadata.

        Reconciliation only mutates adminState/autoEvents before calling this
        method; protocol endpoints and profile bindings are preserved verbatim.
        """

        request_device = {
            key: value
            for key, value in device.items()
            if key not in {"created", "modified", "origin"}
        }
        body = [{"apiVersion": "v3", "device": request_device}]
        try:
            response = self._client.put("/api/v3/device", json=body)
            response.raise_for_status()
            payload = response.json()
        except (httpx.HTTPError, ValueError) as exc:
            raise EdgeXMetadataError(f"EdgeX device update failed: {exc}") from exc
        responses = payload if isinstance(payload, list) else [payload]
        failures = [
            item
            for item in responses
            if isinstance(item, dict) and int(item.get("statusCode", 200)) >= 400
        ]
        if failures:
            detail = str(failures[0].get("message") or failures[0])[:300]
            raise EdgeXMetadataError(f"EdgeX device update rejected: {detail}")

    def close(self) -> None:
        self._client.close()
