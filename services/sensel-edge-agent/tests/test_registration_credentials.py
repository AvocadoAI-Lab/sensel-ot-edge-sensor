"""Registration auto-lands Control-Plane-issued MQTT credentials (P4)."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from src.config.settings import (
    AppConfig,
    LoggingConfig,
    NorthboundMqttConfig,
    PolicySyncConfig,
    SensorIdentity,
    SenselConfig,
)
from src.runtime.mqtt_credentials import load_persisted_credentials
from src.runtime.registration import RegistrationState, attempt_registration


def _config() -> AppConfig:
    return AppConfig(
        sensor=SensorIdentity(id="ndr-x", site_id="plant1", type="ot-edge-sensor", capabilities=["mqtt"]),
        sensel=SenselConfig(api_url="http://cp:8081", api_key="key", verify_tls=False),
        northbound_mqtt=NorthboundMqttConfig(enabled=True, host="broker", tenant_id="default"),
        policy_sync=PolicySyncConfig(),
        logging=LoggingConfig(),
    )


@pytest.fixture(autouse=True)
def _isolate_paths(tmp_path, monkeypatch):
    monkeypatch.setenv("MQTT_CREDENTIALS_PATH", str(tmp_path / "mqtt-credentials.json"))
    monkeypatch.setenv("AGENT_RUNTIME_PATH", str(tmp_path / "agent-runtime.json"))


def test_registration_applies_and_persists_credentials(tmp_path) -> None:
    config = _config()
    state = RegistrationState()
    client = MagicMock()
    client.register.return_value = {
        "tenant_id": "tenant-acme",
        "mqtt_username": "ndr-tenant-acme-ndr-x",
        "mqtt_password": "p4ss",
        "mqtt_host": "edge-broker.example",
        "mqtt_port": 1883,
        "mqtt_acl_version": 1,
    }
    mqtt = MagicMock()
    mqtt.enabled = True
    mqtt.connected = False

    assert attempt_registration(
        client=client, config=config, mqtt=mqtt, policy_mqtt=None, state=state, force=True
    ) is True

    # Live config mutated for both publisher and subscriber credential reads.
    assert config.northbound_mqtt.username == "ndr-tenant-acme-ndr-x"
    assert config.northbound_mqtt.password == "p4ss"
    assert config.policy_sync.mqtt_username == "ndr-tenant-acme-ndr-x"
    assert config.policy_sync.mqtt_password == "p4ss"

    mqtt.update_credentials.assert_called_once_with("ndr-tenant-acme-ndr-x", "p4ss")
    mqtt.update_endpoint_if_unset.assert_called_once_with("edge-broker.example", 1883)

    # Persisted for the next boot.
    persisted = load_persisted_credentials(tmp_path / "mqtt-credentials.json")
    assert persisted is not None
    assert persisted["username"] == "ndr-tenant-acme-ndr-x"
    assert persisted["tenant_id"] == "tenant-acme"


def test_registration_without_credentials_is_noop(tmp_path) -> None:
    config = _config()
    state = RegistrationState()
    client = MagicMock()
    client.register.return_value = {"tenant_id": "tenant-acme"}
    mqtt = MagicMock()
    mqtt.enabled = True
    mqtt.connected = False

    assert attempt_registration(
        client=client, config=config, mqtt=mqtt, policy_mqtt=None, state=state, force=True
    ) is True

    mqtt.update_credentials.assert_not_called()
    assert config.northbound_mqtt.username == ""
    assert load_persisted_credentials(tmp_path / "mqtt-credentials.json") is None
