from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[2]
BRIDGE_SRC = ROOT / "services" / "edgex-event-bridge" / "src"
sys.path.insert(0, str(BRIDGE_SRC))


def test_edgex_event_becomes_security_event():
    from edgex_event_bridge import build_security_event

    event = {
        "id": "event-123",
        "deviceName": "relay-01",
        "profileName": "modbus-relay",
        "origin": 1780000000000000000,
        "readings": [
            {
                "id": "reading-1",
                "resourceName": "Voltage",
                "value": "120.5",
                "valueType": "Float64",
            },
            {
                "id": "reading-2",
                "resourceName": "AlarmStatus",
                "value": "0",
                "valueType": "Int16",
            },
        ],
    }

    out = build_security_event(
        event,
        site_id="factory-lab-001",
        sensor_id="ot-edge-001",
        source_host="192.168.80.130",
    )

    assert out["event_id"] == "edgex-event-123"
    assert out["site_id"] == "factory-lab-001"
    assert out["sensor_id"] == "ot-edge-001"
    # Normalized OT evidence contract (PRD 6.2).
    assert out["event_type"] == "OT_READING_OBSERVED"
    assert out["schema_version"] == "ot_evidence.normalized.v1"
    assert out["severity"] == "medium"
    assert out["rule_id"] == "OT-EDGEX-001"
    assert out["protocol"] == "modbus-tcp"
    assert out["device_id"] == "relay-01"
    assert out["target_ip"] == "192.168.80.130"
    assert out["reading_name"] == "Voltage"
    assert out["value"] == "120.5"
    # Legacy aliases retained for the tailer / console.
    assert out["asset_id"] == "relay-01"
    assert out["src_ip"] == "192.168.80.130"
    assert out["evidence_ref"] == "edgex://event/event-123"
    assert out["raw_payload"]["device_name"] == "relay-01"
    assert out["raw_payload"]["profile_name"] == "modbus-relay"
    assert out["raw_payload"]["readings"][0]["resourceName"] == "Voltage"
