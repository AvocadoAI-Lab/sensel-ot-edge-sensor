"""Config loader unit tests."""

from __future__ import annotations

import sys
import textwrap
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


def _import_agent_config():
    _isolate_service_path(AGENT_SRC)
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


def test_edge_agent_events_ingest_path_can_be_overridden(
    sensor_config_file: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("SENSEL_API_URL", "http://127.0.0.1:8081")
    monkeypatch.setenv("SENSEL_API_KEY", "secret")
    monkeypatch.setenv("SENSEL_EVENTS_INGEST_PATH", "/api/v1/internal/ndr/ot-evidence")
    load_config = _import_agent_config()

    config = load_config(sensor_config_file)

    assert config.sensel.upload.events_path == "/api/v1/internal/ndr/ot-evidence"


def test_edge_agent_event_file_paths_can_be_overridden(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config_path = tmp_path / "agent.yaml"
    config_path.write_text(
        textwrap.dedent(
            """
            sensor:
              id: test-sensor-001
              site_id: test-site-001
            sensel:
              api_url: ${SENSEL_API_URL}
              api_key: ${SENSEL_API_KEY}
              events:
                watch_path: /app/data/assets/security-events.jsonl
                offset_path: /app/data/security-events.offset
              buffer:
                db_path: ${BUFFER_DB_PATH}
            """
        ).strip(),
        encoding="utf-8",
    )
    monkeypatch.setenv("BUFFER_DB_PATH", str(tmp_path / "buffer.db"))
    monkeypatch.setenv("SENSEL_API_URL", "http://127.0.0.1:8081")
    monkeypatch.setenv("SENSEL_API_KEY", "secret")
    monkeypatch.setenv("SECURITY_EVENTS_PATH", "/srv/sensel/security-events.jsonl")
    monkeypatch.setenv("SECURITY_EVENTS_OFFSET", "/srv/sensel/security-events.offset")
    load_config = _import_agent_config()

    config = load_config(config_path)

    assert config.sensel.events.watch_path == "/srv/sensel/security-events.jsonl"
    assert config.sensel.events.offset_path == "/srv/sensel/security-events.offset"
