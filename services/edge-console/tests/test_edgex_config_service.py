"""Phase 2 config service tests."""

from __future__ import annotations

from pathlib import Path

import pytest

from src.edgex_config_service import (
    delete_config_device,
    probe_connectivity,
    upsert_config_device,
    _validate_name,
)


def test_validate_name():
    assert _validate_name("plc-01") == "plc-01"
    with pytest.raises(ValueError):
        _validate_name("bad name")


def test_upsert_modbus_device(tmp_path: Path, monkeypatch):
    devices = tmp_path / "devices"
    profiles = tmp_path / "profiles"
    devices.mkdir()
    profiles.mkdir()
    monkeypatch.setenv("EDGEX_DEVICES_DIR", str(devices))
    monkeypatch.setenv("EDGEX_PROFILES_DIR", str(profiles))
    monkeypatch.setattr(
        "src.edgex_config_service._docker_status",
        lambda _c: {"running": False},
    )

    r = upsert_config_device(
        {"protocol": "modbus", "name": "relay-02", "host": "10.0.0.5", "port": 502}
    )
    assert r["ok"] is True
    path = devices / r["file"]
    assert path.is_file()
    assert "relay-02" in path.read_text(encoding="utf-8")


def test_delete_device(tmp_path: Path, monkeypatch):
    devices = tmp_path / "devices"
    devices.mkdir()
    (devices / "modbus-x.yaml").write_text(
        "deviceList:\n  - name: relay-x\n", encoding="utf-8"
    )
    monkeypatch.setenv("EDGEX_DEVICES_DIR", str(devices))
    r = delete_config_device("relay-x")
    assert r["ok"] is True
    assert not (devices / "modbus-x.yaml").exists()


def test_probe_connectivity_fail():
    r = probe_connectivity("modbus", "192.0.2.1", 1502, timeout=0.5)
    assert r["ok"] is False
