"""EdgeX service unit tests."""

from __future__ import annotations

import json
from pathlib import Path

import httpx
import pytest

from src import edgex_service as svc


def test_unwrap_list_variants():
    assert svc._unwrap_list([{"a": 1}]) == [{"a": 1}]
    assert svc._unwrap_list({"devices": [{"n": "x"}]}, "devices") == [{"n": "x"}]
    assert svc._unwrap_list({"device": {"name": "d1"}}, "device") == [{"name": "d1"}]


def test_parse_device_names_from_yaml(tmp_path: Path):
    yml = tmp_path / "dev.yaml"
    yml.write_text(
        "deviceList:\n  - name: relay-01\n    profileName: X\n  - name: feat-01\n",
        encoding="utf-8",
    )
    assert svc._parse_device_names_from_yaml(yml) == ["relay-01", "feat-01"]


def test_devices_from_config_files(tmp_path: Path, monkeypatch):
    devices_dir = tmp_path / "devices"
    devices_dir.mkdir()
    (devices_dir / "a.yaml").write_text("deviceList:\n  - name: relay-01\n", encoding="utf-8")
    monkeypatch.setenv("EDGEX_DEVICES_DIR", str(devices_dir))
    out = svc._devices_from_config_files()
    assert len(out) == 1
    assert out[0]["name"] == "relay-01"
    assert out[0]["source"] == "config"


def test_list_devices_metadata(monkeypatch):
    def fake_get(url, **kwargs):
        assert "device/all" in url
        return httpx.Response(200, json={"devices": [{"name": "relay-01", "operatingState": "UP", "protocols": {"modbus-tcp": {"Address": "sim", "Port": "1502"}}}]})

    monkeypatch.setattr(httpx, "get", fake_get)
    monkeypatch.setattr(svc, "_latest_event_time", lambda _n: "2026-01-01T00:00:00Z")

    payload = svc.list_devices()
    assert payload["count"] == 1
    assert payload["source"] == "metadata"
    assert payload["devices"][0]["protocol"] == "MODBUS TCP"
    assert payload["devices"][0]["endpoint"] == "sim:1502"


def test_build_protocol_matrix(monkeypatch):
    monkeypatch.setattr(
        svc,
        "build_platform",
        lambda: {"services": [{"id": "device-modbus", "docker": {"running": True}}, {"id": "device-mqtt", "docker": {"running": True}}]},
    )
    monkeypatch.setattr(
        svc,
        "list_devices",
        lambda **_: {"devices": [{"protocol": "MODBUS TCP"}, {"protocol": "MQTT"}]},
    )
    monkeypatch.setattr(svc, "_docker_status", lambda _c: {"running": True, "status": "running"})

    out = svc.build_protocol_matrix()
    ids = {p["id"]: p["enabled"] for p in out["protocols"]}
    assert ids["modbus"] is True
    assert ids["mqtt"] is True
    assert ids["opcua"] is False


def test_restart_edgex_container_denied(monkeypatch):
    monkeypatch.setenv("EDGE_CONSOLE_DOCKER_RESTART", "false")
    ok, msg = svc.restart_edgex_container("edgex-device-modbus")
    assert ok is False
    assert "disabled" in msg.lower()


def test_restart_edgex_container_not_whitelisted(monkeypatch):
    monkeypatch.setenv("EDGE_CONSOLE_DOCKER_RESTART", "true")
    ok, msg = svc.restart_edgex_container("malicious-container")
    assert ok is False
    assert "not allowed" in msg.lower()
