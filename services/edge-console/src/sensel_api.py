<<<<<<< Updated upstream
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


def _ping_error_message(exc: Exception, base: str) -> str:
    if isinstance(exc, httpx.TimeoutException):
        return (
            f"連線逾時：無法在 10 秒內連到 {base}。"
            " 請確認 Portal 已啟動、與 Pi 同網段，或 Lab 改用 "
            "http://192.168.1.123:8765（mock-sensel）。"
        )
    if isinstance(exc, httpx.ConnectError):
        return f"無法連線到 {base}（主機拒絕或路由不通）。"
    return str(exc)


def ping_sensel(config: PlatformConfig) -> dict[str, Any]:
    base = config.sensel_api_url.rstrip("/")
    if not base:
        raise ValueError("SenseL API URL is required")
    paths = ("/api/health", "/health")
    last_exc: Exception | None = None
    with httpx.Client(timeout=10.0, verify=config.sensel_verify_tls) as client:
        for path in paths:
            try:
                response = client.get(f"{base}{path}")
                if response.status_code == 404 and path == "/api/health":
                    continue
                response.raise_for_status()
                return response.json() if response.content else {"status": "ok"}
            except httpx.HTTPStatusError as exc:
                if exc.response.status_code == 404 and path == "/api/health":
                    continue
                raise RuntimeError(_ping_error_message(exc, base)) from exc
            except (httpx.TimeoutException, httpx.ConnectError) as exc:
                last_exc = exc
                break
            except httpx.HTTPError as exc:
                last_exc = exc
                break
    if last_exc is not None:
        raise RuntimeError(_ping_error_message(last_exc, base)) from last_exc
    raise RuntimeError(f"SenseL 健康檢查失敗：{base}")
=======
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


def _ping_error_message(exc: Exception, base: str) -> str:
    if isinstance(exc, httpx.TimeoutException):
        return (
            f"連線逾時：無法在 10 秒內連到 {base}。"
            " 請確認 Portal 已啟動、與 Pi 同網段，或 Lab 改用 "
            "http://192.168.1.123:8765（mock-sensel）。"
        )
    if isinstance(exc, httpx.ConnectError):
        return f"無法連線到 {base}（主機拒絕或路由不通）。"
    return str(exc)


def ping_sensel(config: PlatformConfig) -> dict[str, Any]:
    base = config.sensel_api_url.rstrip("/")
    if not base:
        raise ValueError("SenseL API URL is required")
    paths = ("/api/health", "/health")
    last_exc: Exception | None = None
    with httpx.Client(timeout=10.0, verify=config.sensel_verify_tls) as client:
        for path in paths:
            try:
                response = client.get(f"{base}{path}")
                if response.status_code == 404 and path == "/api/health":
                    continue
                response.raise_for_status()
                return response.json() if response.content else {"status": "ok"}
            except httpx.HTTPStatusError as exc:
                if exc.response.status_code == 404 and path == "/api/health":
                    continue
                raise RuntimeError(_ping_error_message(exc, base)) from exc
            except (httpx.TimeoutException, httpx.ConnectError) as exc:
                last_exc = exc
                break
            except httpx.HTTPError as exc:
                last_exc = exc
                break
    if last_exc is not None:
        raise RuntimeError(_ping_error_message(last_exc, base)) from last_exc
    raise RuntimeError(f"SenseL 健康檢查失敗：{base}")
>>>>>>> Stashed changes
