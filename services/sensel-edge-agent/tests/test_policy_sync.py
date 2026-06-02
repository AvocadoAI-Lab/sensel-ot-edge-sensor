"""Tests for HTTP policy sync."""

from __future__ import annotations

import json
from pathlib import Path

import httpx
import pytest

from src.config.settings import (
    AppConfig,
    LoggingConfig,
    NorthboundMqttConfig,
    PolicySyncConfig,
    SensorIdentity,
    SenselConfig,
)
from src.policy.ioc_cache import load_cache
from src.policy.sync import PolicySync


def _config(tmp_path: Path, *, tenant_id: str = "company-test") -> AppConfig:
    return AppConfig(
        sensor=SensorIdentity(id="ot-edge-001", site_id="site-a"),
        sensel=SenselConfig(
            api_url="http://192.168.1.108:8081",
            api_key="ingest-key",
            verify_tls=False,
        ),
        northbound_mqtt=NorthboundMqttConfig(tenant_id=tenant_id),
        policy_sync=PolicySyncConfig(
            enabled=True,
            interval_sec=60,
            cache_path=str(tmp_path / "ioc-cache.json"),
            stamp_path=str(tmp_path / "ioc-cache.stamp"),
            smb_intel_api_key="test-intel-key",
        ),
        logging=LoggingConfig(),
    )


def test_pull_http_feed_writes_cache(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    artifact = {
        "tenant_id": "company-test",
        "version": "20260601-001",
        "ttl_default_seconds": 86400,
        "manifest": {"sha256": "sha-abc"},
        "items": [
            {
                "item_id": "i1",
                "ioc_type": "ipv4",
                "value": "203.0.113.99",
                "confidence": 85,
                "revoke": False,
            }
        ],
    }

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/api/v1/feed/company-test/blacklist.json"
        assert request.headers.get("X-API-Key") == "test-intel-key"
        return httpx.Response(200, json=artifact, headers={"ETag": '"sha-abc"'})

    transport = httpx.MockTransport(handler)
    real_client = httpx.Client

    def client_factory(*args, **kwargs):
        kwargs["transport"] = transport
        return real_client(*args, **kwargs)

    monkeypatch.setattr(httpx, "Client", client_factory)

    sync = PolicySync(_config(tmp_path))
    result = sync.pull_http_feed(force=True)

    assert result.ok is True
    assert result.changed is True
    assert result.item_count == 1
    assert result.artifact_version == "20260601-001"

    cache = load_cache(tmp_path / "ioc-cache.json")
    assert cache is not None
    assert cache["ipv4"]["203.0.113.99"]["item_id"] == "i1"
    assert (tmp_path / "ioc-cache.stamp").is_file()


def test_pull_http_feed_304_not_changed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    cache_path = tmp_path / "ioc-cache.json"
    cache_path.write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "tenant_id": "company-test",
                "artifact_version": "20260601-001",
                "updated_at": "2026-06-01T00:00:00+00:00",
                "etag": "sha-abc",
                "ipv4": {},
                "domain": {},
                "hash": {},
                "item_count": 0,
            }
        ),
        encoding="utf-8",
    )

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers.get("If-None-Match") == '"sha-abc"'
        return httpx.Response(304)

    transport = httpx.MockTransport(handler)
    real_client = httpx.Client

    def client_factory(*args, **kwargs):
        kwargs["transport"] = transport
        return real_client(*args, **kwargs)

    monkeypatch.setattr(httpx, "Client", client_factory)

    sync = PolicySync(_config(tmp_path))
    result = sync.pull_http_feed()

    assert result.ok is True
    assert result.changed is False
    assert result.status_code == 304


def test_pull_http_feed_uses_feed_tenant_override(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    artifact = {
        "tenant_id": "sensel-platform",
        "version": "20260601-002",
        "ttl_default_seconds": 86400,
        "manifest": {"sha256": "sha-xyz"},
        "items": [],
    }

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/api/v1/feed/sensel-platform/blacklist.json"
        return httpx.Response(200, json=artifact, headers={"ETag": '"sha-xyz"'})

    transport = httpx.MockTransport(handler)
    real_client = httpx.Client

    def client_factory(*args, **kwargs):
        kwargs["transport"] = transport
        return real_client(*args, **kwargs)

    monkeypatch.setattr(httpx, "Client", client_factory)

    cfg = _config(tmp_path, tenant_id="company-a9ae1234648ee138")
    cfg = cfg.model_copy(
        update={
            "policy_sync": cfg.policy_sync.model_copy(
                update={"feed_tenant_id": "sensel-platform"}
            )
        }
    )
    sync = PolicySync(cfg)
    result = sync.pull_http_feed(force=True)
    assert result.ok is True
    assert result.tenant_id == "sensel-platform"


def test_pull_http_feed_skips_without_tenant(tmp_path: Path) -> None:
    cfg = _config(tmp_path, tenant_id="default")
    cfg = cfg.model_copy(update={"northbound_mqtt": cfg.northbound_mqtt.model_copy(update={"require_tenant": True})})
    sync = PolicySync(cfg)
    result = sync.pull_http_feed(force=True)
    assert result.ok is False
    assert "tenant_id unresolved" in (result.error or "")
