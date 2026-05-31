"""SenseL platform register / health test client."""

from __future__ import annotations

from typing import Any

import httpx

from src.config_store import PlatformConfig


def register_sensor(config: PlatformConfig) -> dict[str, Any]:
    base = config.sensel_api_url.rstrip("/")
    token = (config.registration_token or "").strip()
    api_key = (config.sensel_api_key or "").strip()
    if not base:
        raise ValueError("SenseL API URL is required")
    if not api_key:
        raise ValueError("SenseL API key is required")
    if len(token) < 4:
        raise ValueError("Enterprise invite code must be at least 4 characters")

    payload = {
        "sensor_id": config.sensor_id,
        "site_id": config.site_id,
        "sensor_type": config.sensor_type,
        "hardware": config.hardware,
        "software_version": "0.1.0",
        "capabilities": [],
        "registration_token": token,
    }
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }
    with httpx.Client(timeout=30.0, verify=config.sensel_verify_tls) as client:
        response = client.post(f"{base}/api/v1/edge-sensors/register", json=payload, headers=headers)
        if response.status_code >= 400:
            detail = response.text[:500]
            try:
                body = response.json()
                detail = body.get("detail") or detail
            except Exception:
                pass
            raise RuntimeError(f"Register failed ({response.status_code}): {detail}")
        data = response.json()
        if not isinstance(data, dict):
            raise RuntimeError("Invalid register response")
        return data


def ping_sensel(config: PlatformConfig) -> dict[str, Any]:
    base = config.sensel_api_url.rstrip("/")
    if not base:
        raise ValueError("SenseL API URL is required")
    with httpx.Client(timeout=10.0, verify=config.sensel_verify_tls) as client:
        response = client.get(f"{base}/api/health")
        response.raise_for_status()
        return response.json() if response.content else {"status": "ok"}
