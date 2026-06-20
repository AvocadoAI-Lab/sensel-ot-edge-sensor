"""SenseL platform HTTP client (TLS, API key auth)."""

from __future__ import annotations

import logging
from typing import Any

import httpx

from src.config.settings import AppConfig

logger = logging.getLogger(__name__)


class SenseLClient:
    def __init__(self, config: AppConfig) -> None:
        self._config = config
        self._base = config.sensel.api_url.rstrip("/")
        self._headers = {
            "Authorization": f"Bearer {config.sensel.api_key}",
            "Content-Type": "application/json",
        }
        self._client = httpx.Client(
            timeout=30.0,
            verify=config.sensel.verify_tls,
        )

    def close(self) -> None:
        self._client.close()

    def _post(self, path: str, payload: dict[str, Any]) -> httpx.Response:
        url = f"{self._base}{path}"
        logger.debug("POST %s", url)
        return self._client.post(url, json=payload, headers=self._headers)

    def register(self) -> dict[str, Any]:
        sensor = self._config.sensor
        payload = {
            "sensor_id": sensor.id,
            "site_id": sensor.site_id,
            "sensor_type": sensor.type,
            "hardware": sensor.hardware,
            "software_version": sensor.software_version,
            "capabilities": sensor.capabilities,
        }
        token = (self._config.sensel.registration_token or "").strip()
        if token:
            payload["registration_token"] = token
        response = self._post(self._config.sensel.upload.register_path, payload)
        response.raise_for_status()
        data = response.json()
        logger.info(
            "Registered sensor %s with SenseL (tenant=%s)",
            sensor.id,
            data.get("tenant_id"),
        )
        return data if isinstance(data, dict) else {}

    def upload_health(self, payload: dict[str, Any]) -> httpx.Response:
        response = self._post(self._config.sensel.upload.health_path, payload)
        response.raise_for_status()
        logger.debug("Health upload OK for %s", payload.get("sensor_id"))
        return response

    def upload_security_event(self, payload: dict[str, Any]) -> httpx.Response:
        response = self._post(self._config.sensel.upload.events_path, payload)
        response.raise_for_status()
        return response
