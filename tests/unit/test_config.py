"""Config loader unit tests."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
AGENT_SRC = str(ROOT / "services" / "sensel-edge-agent")
PACKET_SRC = str(ROOT / "services" / "packet-sensor")


def _isolate_service_path(service_src: str) -> None:
    for key in list(sys.modules):
        if key == "src" or key.startswith("src."):
            del sys.modules[key]
    sys.path[:] = [
        p for p in sys.path if p not in (AGENT_SRC, PACKET_SRC, str(ROOT))
    ]
    sys.path.insert(0, service_src)


def _import_packet_config():
    _isolate_service_path(PACKET_SRC)
    from src.config.settings import load_config

    return load_config


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
