"""Edge Agent ↔ SenseL mock integration tests."""

from __future__ import annotations

from pathlib import Path

import pytest

from service_loader import import_from_service

ROOT = Path(__file__).resolve().parents[2]


def _import_agent_modules():
    client, settings, collector, buffer = import_from_service(
        "sensel-edge-agent",
        "src.api.client",
        "src.config.settings",
        "src.health.collector",
        "src.upload.buffer",
    )
    return client.SenseLClient, settings.load_config, collector.collect_health, buffer.UploadBuffer


from integration.mock_sensel_server import start_mock_sensel  # noqa: E402


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
