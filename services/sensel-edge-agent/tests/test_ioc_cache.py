"""Tests for IoC cache normalization."""

from __future__ import annotations

from pathlib import Path

from src.policy.ioc_cache import build_cache_from_artifact, load_cache, write_cache


def test_build_cache_from_artifact_filters_revoked_and_types() -> None:
    artifact = {
        "tenant_id": "company-test",
        "version": "20260601-001",
        "ttl_default_seconds": 3600,
        "manifest": {"sha256": "abc123"},
        "items": [
            {
                "item_id": "i1",
                "ioc_type": "ipv4",
                "value": "203.0.113.10",
                "confidence": 80,
                "revoke": False,
            },
            {
                "item_id": "i2",
                "ioc_type": "domain",
                "value": "Evil.EXAMPLE.com",
                "confidence": 70,
                "revoke": False,
            },
            {
                "item_id": "i3",
                "ioc_type": "ipv4",
                "value": "198.51.100.1",
                "confidence": 90,
                "revoke": True,
            },
            {
                "item_id": "i4",
                "ioc_type": "url",
                "value": "http://ignored.example",
                "revoke": False,
            },
        ],
    }
    cache = build_cache_from_artifact(artifact, tenant_id="company-test", etag="abc123")
    assert cache["tenant_id"] == "company-test"
    assert cache["artifact_version"] == "20260601-001"
    assert cache["etag"] == "abc123"
    assert cache["item_count"] == 2
    assert "203.0.113.10" in cache["ipv4"]
    assert cache["domain"]["evil.example.com"]["item_id"] == "i2"
    assert "198.51.100.1" not in cache["ipv4"]


def test_write_and_load_cache_roundtrip(tmp_path: Path) -> None:
    cache_path = tmp_path / "ioc-cache.json"
    payload = {
        "schema_version": "1.0",
        "tenant_id": "t1",
        "artifact_version": "v1",
        "updated_at": "2026-06-01T00:00:00+00:00",
        "etag": "etag1",
        "ipv4": {},
        "domain": {},
        "hash": {},
        "item_count": 0,
    }
    write_cache(cache_path, payload)
    loaded = load_cache(cache_path)
    assert loaded == payload
