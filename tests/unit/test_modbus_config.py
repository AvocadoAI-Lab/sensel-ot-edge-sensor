"""Modbus lab config validation (S1-02)."""

from __future__ import annotations

from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
PROFILE = ROOT / "config" / "edgex/profiles/modbus-relay.yaml"
DEVICE = ROOT / "config" / "edgex/devices/modbus-relay.yaml"


def test_modbus_profile_has_register_attributes() -> None:
    profile = yaml.safe_load(PROFILE.read_text())
    resources = {r["name"]: r for r in profile["deviceResources"]}
    assert "Voltage" in resources
    assert resources["Voltage"]["attributes"]["primaryTable"] == "INPUT_REGISTERS"
    assert resources["Voltage"]["attributes"]["startingAddress"] == 5
    assert resources["Voltage"]["properties"]["valueType"] == "Float32"


def test_modbus_device_points_at_simulator() -> None:
    raw = yaml.safe_load(DEVICE.read_text())
    device = raw["deviceList"][0]
    modbus = device["protocols"]["modbus-tcp"]
    assert modbus["Address"] == "modbus-simulator"
    assert modbus["Port"] == "1502"
    assert device["autoEvents"][0]["sourceName"] == "Status"
    assert device["autoEvents"][0]["interval"] == "10s"
