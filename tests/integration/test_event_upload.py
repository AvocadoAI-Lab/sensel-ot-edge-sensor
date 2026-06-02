"""Edge Agent security event upload integration test."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from service_loader import import_from_service

ROOT = Path(__file__).resolve().parents[2]


def _import_agent_modules():
    client, settings, buffer, events = import_from_service(
        "sensel-edge-agent",
        "src.api.client",
        "src.config.settings",
        "src.upload.buffer",
        "src.upload.events",
    )
    return client.SenseLClient, settings.load_config, buffer.UploadBuffer, events.SecurityEventTailer


from integration.mock_sensel_server import start_mock_sensel  # noqa: E402


def test_security_event_upload(
    sensor_config_file: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    SenseLClient, load_config, UploadBuffer, SecurityEventTailer = _import_agent_modules()
    server, state, base_url = start_mock_sensel()
    monkeypatch.setenv("SENSEL_API_URL", base_url)
    monkeypatch.setenv("SENSEL_API_KEY", "test-key")
    monkeypatch.setenv("SENSEL_VERIFY_TLS", "false")

    events_file = tmp_path / "security-events.jsonl"
    offset_file = tmp_path / "security-events.offset"
    sample = {
        "event_id": "evt-test-00001",
        "site_id": "test-site-001",
        "sensor_id": "test-sensor-001",
        "event_type": "MODBUS_WRITE_ANOMALY",
        "severity": "high",
        "rule_id": "OT-007",
        "protocol": "modbus-tcp",
        "description": "Unexpected Modbus write",
        "timestamp": "2026-05-30T12:00:03+00:00",
        "evidence_ref": "local-ringbuffer://2026-05-30T12:00:02+00:00",
    }
    events_file.write_text(json.dumps(sample) + "\n", encoding="utf-8")

    monkeypatch.setenv("SECURITY_EVENTS_PATH", str(events_file))
    monkeypatch.setenv("SECURITY_EVENTS_OFFSET", str(offset_file))

    config = load_config(sensor_config_file)
    client = SenseLClient(config)
    tailer = SecurityEventTailer(
        config.sensel.events.watch_path,
        config.sensel.events.offset_path,
    )

    try:
        pending = tailer.pending_events()
        assert len(pending) == 1
        client.upload_security_event(pending[0])
        assert tailer.pending_events() == []
    finally:
        client.close()
        server.shutdown()

    assert len(state.events) == 1
    assert state.events[0]["rule_id"] == "OT-007"
    assert state.events[0]["evidence_ref"].startswith("local-ringbuffer://")
