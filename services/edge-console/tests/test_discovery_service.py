"""Discovery and event enrichment tests."""

from __future__ import annotations

from src.discovery_service import build_ip_device_map, enrich_event


def test_build_ip_device_map():
    devices = [{"name": "relay-01", "endpoint": "modbus-simulator:1502"}]
    m = build_ip_device_map(devices)
    assert m["modbus-simulator"] == "relay-01"


def test_enrich_event_matched():
    ip_map = {"192.168.10.88": "packet-sensor-features"}
    ev = enrich_event({"src_ip": "192.168.10.88", "rule_id": "OT-01"}, ip_map)
    assert ev["matched_device"] == "packet-sensor-features"
    assert ev["asset_source"] == "edgex"


def test_enrich_event_mirror_only():
    ev = enrich_event({"src_ip": "10.0.0.99"}, {})
    assert ev["asset_source"] == "mirror"
    assert ev["asset_label"] == "10.0.0.99"
