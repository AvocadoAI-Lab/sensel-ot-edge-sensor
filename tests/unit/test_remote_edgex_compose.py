from __future__ import annotations

from pathlib import Path

import yaml


def test_remote_edgex_agent_uses_controlplane_mqtt_network() -> None:
    compose_path = Path(__file__).resolve().parents[2] / "docker-compose.remote-edgex.yml"
    compose = yaml.safe_load(compose_path.read_text(encoding="utf-8"))
    agent = compose["services"]["sensel-edge-agent"]
    env = dict(item.split("=", maxsplit=1) for item in agent["environment"])

    assert env["CONTROL_PLANE_MQTT_HOST"] == "${CONTROL_PLANE_MQTT_HOST:-emqx}"
    assert "controlplane_net" in agent["networks"]
    assert compose["networks"]["controlplane_net"]["external"] is True
