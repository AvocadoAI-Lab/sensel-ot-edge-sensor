"""Root pytest fixtures shared by unit and integration tests."""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest


@pytest.fixture
def sensor_config_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    config_path = tmp_path / "sensor.yaml"
    config_path.write_text(
        textwrap.dedent(
            """
            sensor:
              id: test-sensor-001
              site_id: test-site-001
              type: ot-edge-sensor
              hardware: ubuntu
              software_version: "0.1.0"
              capabilities:
                - packet-capture

            sensel:
              api_url: ${SENSEL_API_URL}
              api_key: ${SENSEL_API_KEY}
              upload:
                register_path: /api/v1/edge-sensors/register
                health_path: /api/v1/edge-sensors/health
              buffer:
                db_path: ${BUFFER_DB_PATH}

            capture:
              interface: lo
              promiscuous: false
              bpf_filter: ""
              health_check_interval_sec: 1
              stats_log_interval_sec: 1
            """
        ).strip()
    )
    monkeypatch.setenv("BUFFER_DB_PATH", str(tmp_path / "buffer.db"))
    return config_path
