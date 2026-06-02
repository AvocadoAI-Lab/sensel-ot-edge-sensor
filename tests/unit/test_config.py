"""Config loader unit tests."""

from __future__ import annotations

from pathlib import Path

import pytest

from service_loader import import_from_service


def _import_packet_config():
    return import_from_service("packet-sensor", "src.config.settings").load_config


def test_packet_sensor_config_loads(
    sensor_config_file: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("CAPTURE_INTERFACE", "lo")
    load_config = _import_packet_config()
    config = load_config(sensor_config_file)
    assert config.sensor.id == "test-sensor-001"
    assert config.capture.interface == "lo"
    assert config.capture.promiscuous is False
