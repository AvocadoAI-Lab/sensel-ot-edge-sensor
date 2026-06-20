"""Edge Agent ↔ SenseL mock integration tests."""

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


def _import_agent_modules():
    _isolate_service_path(AGENT_SRC)
    from src.api.client import SenseLClient
    from src.config.settings import load_config
    from src.health.collector import collect_health
    from src.upload.buffer import UploadBuffer

    return SenseLClient, load_config, collect_health, UploadBuffer


from tests.integration.mock_sensel_server import start_mock_sensel  # noqa: E402


def test_register_and_health_upload(
    sensor_config_file: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    SenseLClient, load_config, collect_health, _UploadBuffer = _import_agent_modules()
    server, state, base_url = start_mock_sensel()
    monkeypatch.setenv("SENSEL_API_URL", base_url)
    monkeypatch.setenv("SENSEL_API_KEY", "test-key")
    monkeypatch.setenv("SENSEL_VERIFY_TLS", "false")

    config = load_config(sensor_config_file)
    client = SenseLClient(config)

    try:
        client.register()
        health = collect_health(config)
        client.upload_health(health)
    finally:
        client.close()
        server.shutdown()

    assert len(state.registrations) == 1
    assert state.registrations[0]["sensor_id"] == "test-sensor-001"
    assert state.registrations[0]["site_id"] == "test-site-001"

    assert len(state.health_reports) == 1
    report = state.health_reports[0]
    assert report["sensor_id"] == "test-sensor-001"
    assert report["agent_status"] == "running"
    assert "cpu_usage" in report
    assert "timestamp" in report


def test_health_buffer_retry(
    sensor_config_file: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _SenseLClient, load_config, collect_health, UploadBuffer = _import_agent_modules()
    monkeypatch.setenv("SENSEL_API_URL", "http://127.0.0.1:1")
    monkeypatch.setenv("SENSEL_API_KEY", "test-key")
    monkeypatch.setenv("SENSEL_VERIFY_TLS", "false")

    config = load_config(sensor_config_file)
    buffer = UploadBuffer(config.sensel.buffer.db_path)
    health = collect_health(config)
    buffer.enqueue("health", health)

    pending = buffer.pending()
    assert len(pending) == 1
    assert pending[0][1] == "health"
    assert pending[0][2]["sensor_id"] == "test-sensor-001"
    buffer.close()
