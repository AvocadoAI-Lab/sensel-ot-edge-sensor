"""Edge Agent security event upload integration test."""

from __future__ import annotations

import json
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
    from src.upload.buffer import UploadBuffer
    from src.upload.events import SecurityEventTailer

    return SenseLClient, load_config, UploadBuffer, SecurityEventTailer


from tests.integration.mock_sensel_server import start_mock_sensel  # noqa: E402


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
