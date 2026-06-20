"""Tests for the standalone Suricata EVE northbound forwarder."""

from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))


def test_alert_maps_to_normalized_modbus_ndr_event():
    from forward_suricata_ndr import map_alert

    record = {
        "timestamp": "2026-06-20T09:45:00.123456+0800",
        "flow_id": 123456,
        "event_type": "alert",
        "src_ip": "192.168.80.131",
        "src_port": 41000,
        "dest_ip": "192.168.80.130",
        "dest_port": 1502,
        "proto": "TCP",
        "app_proto": "modbus",
        "alert": {
            "gid": 1,
            "signature_id": 1000120,
            "rev": 1,
            "signature": "SENSEL LAB NDR Kali to EdgeX Modbus probe",
            "category": "Attempted Information Leak",
            "severity": 2,
        },
    }

    event = map_alert(
        record,
        tenant_id="mssp-enterprise",
        workspace_id="1",
        site_id="factory-lab-001",
        sensor_id="ndr-suricata-01",
    )

    assert event is not None
    assert event["schema_version"] == "ndr_event.normalized.v1"
    assert event["source_ip"] == "192.168.80.131"
    assert event["destination_ip"] == "192.168.80.130"
    assert event["target_ip"] == "192.168.80.130"
    assert event["protocol"] == "modbus-tcp"
    assert event["site_id"] == "factory-lab-001"
    assert event["workspace_id"] == "1"
    assert event["rule_id"] == "suricata-1-1000120"
    assert event["raw_ref"] == "suricata:eve:flow_id=123456"
    assert event["evidence"]["raw_event"] == record


def test_non_alert_is_not_forwarded():
    from forward_suricata_ndr import map_alert

    assert (
        map_alert(
            {"event_type": "flow"},
            tenant_id="t",
            workspace_id="1",
            site_id="s",
            sensor_id="n",
        )
        is None
    )
