"""Tests for MQTT policy blacklist subscriber (Track B-S5)."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

from src.config.settings import (
    AppConfig,
    LoggingConfig,
    NorthboundMqttConfig,
    PolicySyncConfig,
    SensorIdentity,
    SenselConfig,
)
from src.policy.ioc_cache import load_cache
from src.policy.mqtt_subscriber import PolicyMqttSubscriber
from src.policy.sync import PolicySync


def _config(tmp_path: Path, *, tenant_id: str = "sensel-platform") -> AppConfig:
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
            mqtt_enabled=True,
            mqtt_host="192.168.1.203",
            mqtt_port=1883,
            cache_path=str(tmp_path / "ioc-cache.json"),
            stamp_path=str(tmp_path / "ioc-cache.stamp"),
            feed_tenant_id=tenant_id,
        ),
        logging=LoggingConfig(),
    )


def _artifact(version: str, sha: str, ip: str = "203.0.113.77") -> dict:
    return {
        "tenant_id": "sensel-platform",
        "version": version,
        "ttl_default_seconds": 86400,
        "manifest": {"sha256": sha},
        "items": [
            {
                "item_id": f"item-{ip}",
                "ioc_type": "ipv4",
                "value": ip,
                "confidence": 88,
                "revoke": False,
            }
        ],
    }


def test_apply_artifact_skips_duplicate_etag(tmp_path: Path) -> None:
    sync = PolicySync(_config(tmp_path))
    first = sync.apply_artifact(
        _artifact("20260601-010", "sha-dup"),
        tenant_id="sensel-platform",
        etag="sha-dup",
        source="mqtt",
    )
    assert first.changed is True

    second = sync.apply_artifact(
        _artifact("20260601-010", "sha-dup"),
        tenant_id="sensel-platform",
        etag="sha-dup",
        source="mqtt",
    )
    assert second.ok is True
    assert second.changed is False


def test_mqtt_subscriber_applies_message(tmp_path: Path) -> None:
    cfg = _config(tmp_path)
    sync = PolicySync(cfg)
    subscriber = PolicyMqttSubscriber(cfg, sync)

    payload = json.dumps(_artifact("20260601-mqtt-001", "sha-mqtt-1"))
    message = SimpleNamespace(topic="sensel/sensel-platform/policy/blacklist", payload=payload.encode())
    subscriber._on_message(None, None, message)

    cache = load_cache(tmp_path / "ioc-cache.json")
    assert cache is not None
    assert cache["artifact_version"] == "20260601-mqtt-001"
    assert "203.0.113.77" in cache["ipv4"]
    assert subscriber.messages_received == 1


def test_mqtt_subscriber_enabled_requires_host(tmp_path: Path) -> None:
    cfg = _config(tmp_path)
    cfg = cfg.model_copy(
        update={
            "policy_sync": cfg.policy_sync.model_copy(update={"mqtt_enabled": True, "mqtt_host": ""})
        }
    )
    subscriber = PolicyMqttSubscriber(cfg, PolicySync(cfg))
    assert subscriber.enabled is False
