"""Tests for the EdgeX -> normalized OT evidence bridge (PRD EDGE-2.1 / EDGE-2.2)."""

from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[2]
BRIDGE_SRC = ROOT / "services" / "edgex-event-bridge" / "src"
sys.path.insert(0, str(BRIDGE_SRC))


_FAN_EVENT = {
    "id": "evt-fan-001",
    "deviceName": "ot-fan-relay",
    "profileName": "modbus-relay",
    "sourceName": "FanRPM",
    "origin": 1780000000000000000,
    "readings": [
        {
            "id": "r1",
            "resourceName": "FanRPM",
            "value": "1450",
            "units": "rpm",
            "valueType": "Int32",
        },
        {
            "id": "r2",
            "resourceName": "Temperature",
            "value": "41.2",
            "units": "C",
            "valueType": "Float64",
        },
    ],
}


def test_build_ot_evidence_carries_correlation_fields():
    from edgex_event_bridge import build_ot_evidence

    out = build_ot_evidence(
        _FAN_EVENT,
        site_id="lab-ot-site",
        sensor_id="ot-edge-001",
        source_host="192.168.80.130",
        tenant_id="lab-tenant",
        workspace_id="ws-lab-1",
        purdue_level="L1",
    )

    assert out["schema_version"] == "ot_evidence.normalized.v1"
    assert out["event_id"] == "edgex-evt-fan-001"
    assert out["tenant_id"] == "lab-tenant"
    assert out["workspace_id"] == "ws-lab-1"
    assert out["site_id"] == "lab-ot-site"
    assert out["sensor_id"] == "ot-edge-001"
    # PRD EDGE-2.2: device_id / source_name / reading / protocol / target_ip / purdue
    assert out["device_id"] == "ot-fan-relay"
    assert out["source_name"] == "FanRPM"
    assert out["reading_name"] == "FanRPM"
    assert out["value"] == "1450"
    assert out["unit"] == "rpm"
    assert out["event_type"] == "OT_READING_OBSERVED"
    assert out["protocol"] == "modbus-tcp"
    assert out["target_ip"] == "192.168.80.130"
    assert out["purdue_level"] == "L1"
    # Raw payload retains all readings for replay (EDGE-2.4).
    assert len(out["raw_payload"]["readings"]) == 2


def test_workspace_defaults_to_tenant_when_blank():
    from edgex_event_bridge import build_ot_evidence

    out = build_ot_evidence(
        _FAN_EVENT,
        site_id="lab-ot-site",
        sensor_id="ot-edge-001",
        source_host="192.168.80.130",
        tenant_id="lab-tenant",
        workspace_id="",
    )
    assert out["workspace_id"] == "lab-tenant"


def test_event_without_readings_still_valid():
    from edgex_event_bridge import build_ot_evidence

    out = build_ot_evidence(
        {"id": "x", "deviceName": "d"},
        site_id="s",
        sensor_id="n",
        source_host="10.0.0.1",
    )
    assert out["device_id"] == "d"
    assert out["reading_name"] is None
    assert out["value"] is None
    assert out["event_type"] == "OT_READING_OBSERVED"
    assert out["protocol"] == "edgex"
