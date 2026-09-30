"""Tests for periodic registration retry."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from src.config.settings import (
    AppConfig,
    LoggingConfig,
    NorthboundMqttConfig,
    SensorIdentity,
    SenselConfig,
)
from src.runtime.registration import RegistrationState, attempt_registration


def _config(register_retry_sec: int = 60) -> AppConfig:
    return AppConfig(
        sensor=SensorIdentity(
            id="ot-edge-001",
            site_id="site-a",
            type="ot-edge-sensor",
            capabilities=["mqtt"],
        ),
        sensel=SenselConfig(
            api_url="http://192.168.1.108:8081",
            api_key="key",
            verify_tls=False,
            register_retry_sec=register_retry_sec,
        ),
        northbound_mqtt=NorthboundMqttConfig(enabled=True, host="203", tenant_id="default"),
        logging=LoggingConfig(),
    )


def test_attempt_registration_retries_until_success(monkeypatch: pytest.MonkeyPatch) -> None:
    config = _config(register_retry_sec=120)
    state = RegistrationState()
    client = MagicMock()
    client.register.side_effect = [
        RuntimeError("portal down"),
        {"tenant_id": "company-abc"},
    ]
    mqtt = MagicMock()
    mqtt.enabled = True

    assert attempt_registration(
        client=client, config=config, mqtt=mqtt, policy_mqtt=None, state=state, force=True
    ) is False
    assert state.complete is False

    assert attempt_registration(
        client=client, config=config, mqtt=mqtt, policy_mqtt=None, state=state, force=True
    ) is True
    assert state.complete is True
    assert state.tenant_id == "company-abc"
    mqtt.update_tenant_id.assert_called_with("company-abc")
    mqtt.publish_state.assert_called_once()


def test_attempt_registration_skips_when_complete_and_not_due() -> None:
    config = _config()
    state = RegistrationState(complete=True, tenant_id="company-abc")
    client = MagicMock()

    assert attempt_registration(
        client=client, config=config, mqtt=MagicMock(), policy_mqtt=None, state=state
    ) is True
    client.register.assert_not_called()
