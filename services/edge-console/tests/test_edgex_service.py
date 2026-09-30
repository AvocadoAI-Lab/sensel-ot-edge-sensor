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


def test_container_allowed_scope():
    assert svc._container_allowed("sensel-suricata") is True
    assert svc._container_allowed("sensel-snort") is True
    assert svc._container_allowed("edgex-core-data") is True
    assert svc._container_allowed("malicious-container") is False


def test_is_sensel_container():
    assert svc._is_sensel_container("sensel-suricata") is True
    assert svc._is_sensel_container("suricata") is True
    assert svc._is_sensel_container("edgex-core-data") is False


def test_service_row_for_discovered_sensel(monkeypatch):
    monkeypatch.setattr(
        svc, "_docker_status",
        lambda _c: {"container": _c, "status": "running", "running": True, "started_at": "2026-06-19T10:00:00Z", "image": "jasonish/suricata:latest"},
    )
    spec = {"id": "sensel-suricata", "label": "Suricata IDS", "container": "sensel-suricata", "port": None, "optional": True, "group": "sensel"}
    row, docker = svc._service_row(spec, {"sensel-suricata": {"cpu_pct": 1.2, "mem_mb": 80.0}})
    assert row["group"] == "sensel"
    assert row["api"] is None  # no HTTP ping for IDS sidecars
    assert row["ok"] is True
    assert row["cpu_pct"] == 1.2 and row["mem_mb"] == 80.0
    assert docker["running"] is True


def test_build_platform_includes_discovered(monkeypatch):
    monkeypatch.setattr(svc, "_docker_stats_all", lambda: {})
    monkeypatch.setattr(svc, "_docker_status", lambda c: {"container": c, "status": "running", "running": True})
    monkeypatch.setattr(svc, "_ping_service", lambda *a, **k: {"ok": True, "status_code": 200, "latency_ms": 1, "url": "x"})
    monkeypatch.setattr(svc, "_service_version", lambda *a, **k: None)
    monkeypatch.setattr(
        svc, "_discover_extra_containers",
        lambda exclude: [{"id": "sensel-suricata", "label": "Suricata IDS", "container": "sensel-suricata", "port": None, "optional": True, "group": "sensel"}],
    )
    platform = svc.build_platform()
    by_container = {s["container"]: s for s in platform["services"]}
    assert "sensel-suricata" in by_container
    assert by_container["sensel-suricata"]["group"] == "sensel"
    # Curated EdgeX rows still present.
    assert "edgex-core-data" in by_container
