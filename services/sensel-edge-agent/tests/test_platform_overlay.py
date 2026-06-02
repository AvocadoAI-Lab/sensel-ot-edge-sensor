"""Tests for platform.json overlay in edge agent."""

import json
from pathlib import Path

from src.config.platform_overlay import apply_platform_overlay, load_platform_raw
from src.config.settings import AppConfig, LoggingConfig, NorthboundMqttConfig, SensorIdentity, SenselConfig


def test_apply_platform_overlay(monkeypatch, tmp_path: Path) -> None:
    platform = {
        "sensor_id": "ot-edge-pi-test",
        "site_id": "site-a",
        "sensel_api_url": "http://192.168.1.108:8081",
        "sensel_api_key": "key-123",
        "registration_token": "invite-abc",
        "mqtt_host": "192.168.1.203",
        "mqtt_tenant_id": "company-test",
        "last_register_tenant_id": "company-test",
    }
    path = tmp_path / "platform.json"
    path.write_text(json.dumps(platform), encoding="utf-8")
    monkeypatch.setenv("PLATFORM_CONFIG_PATH", str(path))

    base = AppConfig(
        sensor=SensorIdentity(id="old", site_id="old-site"),
        sensel=SenselConfig(api_url="http://mock", api_key="old"),
        northbound_mqtt=NorthboundMqttConfig(host="", tenant_id="default"),
        logging=LoggingConfig(),
    )
    merged = apply_platform_overlay(base)
    assert merged.sensor.id == "ot-edge-pi-test"
    assert merged.sensel.api_url == "http://192.168.1.108:8081"
    assert merged.sensel.registration_token == "invite-abc"
    assert merged.northbound_mqtt.tenant_id == "company-test"
    assert merged.northbound_mqtt.require_tenant is False
    assert load_platform_raw()["sensor_id"] == "ot-edge-pi-test"


def test_apply_platform_overlay_intel_api_key(monkeypatch, tmp_path: Path) -> None:
    from src.config.settings import PolicySyncConfig

    path = tmp_path / "platform.json"
    path.write_text(
        json.dumps({"smb_intel_api_key": "intel-key-xyz"}),
        encoding="utf-8",
    )
    monkeypatch.setenv("PLATFORM_CONFIG_PATH", str(path))
    base = AppConfig(
        sensor=SensorIdentity(id="s1", site_id="site"),
        sensel=SenselConfig(api_url="http://108", api_key="k"),
        northbound_mqtt=NorthboundMqttConfig(host="203", tenant_id="company-test"),
        policy_sync=PolicySyncConfig(),
        logging=LoggingConfig(),
    )
    merged = apply_platform_overlay(base)
    assert merged.policy_sync.smb_intel_api_key == "intel-key-xyz"


def test_apply_platform_overlay_requires_tenant_when_default(monkeypatch, tmp_path: Path) -> None:
    path = tmp_path / "platform.json"
    path.write_text(json.dumps({"mqtt_tenant_id": "default", "mqtt_enabled": True}), encoding="utf-8")
    monkeypatch.setenv("PLATFORM_CONFIG_PATH", str(path))
    base = AppConfig(
        sensor=SensorIdentity(id="s1", site_id="site"),
        sensel=SenselConfig(api_url="http://108", api_key="k"),
        northbound_mqtt=NorthboundMqttConfig(host="203", enabled=True, tenant_id="default"),
        logging=LoggingConfig(),
    )
    merged = apply_platform_overlay(base)
    assert merged.northbound_mqtt.require_tenant is True
