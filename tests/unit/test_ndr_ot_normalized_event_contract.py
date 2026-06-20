"""Validate edge producers against the shared normalized NDR/OT contract (PRD 6.1/6.2)."""

from __future__ import annotations

import json
from pathlib import Path
import sys

import pytest

ROOT = Path(__file__).resolve().parents[2]
PACKET_SENSOR = ROOT / "services" / "packet-sensor"
BRIDGE_SRC = ROOT / "services" / "edgex-event-bridge" / "src"
SCHEMAS = ROOT / "schemas"
FIXTURES = ROOT / "tests" / "fixtures" / "ndr_ot"

for path in (PACKET_SENSOR, BRIDGE_SRC):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

jsonschema = pytest.importorskip("jsonschema")


def _validator(schema_name: str):
    schema = json.loads((SCHEMAS / schema_name).read_text(encoding="utf-8"))
    return jsonschema.Draft202012Validator(schema)


NDR_VALIDATOR = _validator("ndr-event.normalized.v1.schema.json")
OT_VALIDATOR = _validator("ot-evidence.normalized.v1.schema.json")


def test_suricata_alert_normalizes_to_contract():
    from src.detection.external_engine.eve_selector import EveRecordMapper
    from src.detection.external_engine.normalize import normalize_ndr_event

    mapper = EveRecordMapper(site_id="lab-ot-site", sensor_id="ndr-edge-001")
    alert = {
        "timestamp": "2026-06-19T03:30:00.000000+0000",
        "flow_id": 99,
        "event_type": "alert",
        "src_ip": "192.168.80.131",
        "dest_ip": "192.168.80.130",
        "dest_port": 80,
        "proto": "TCP",
        "app_proto": "http",
        "alert": {"gid": 1, "signature_id": 2100498, "signature": "GPL ATTACK", "severity": 1},
    }
    engine_event = mapper.map(alert).to_dict()
    normalized = normalize_ndr_event(engine_event, tenant_id="lab-tenant", workspace_id="ws-lab-1")

    NDR_VALIDATOR.validate(normalized)  # raises on contract violation
    assert normalized["engine"] == "suricata"
    assert normalized["target_ip"] == "192.168.80.130"
    assert normalized["source_ip"] == "192.168.80.131"
    assert normalized["protocol"] == "http"
    assert normalized["event_id"] == "ndr-edge-001:suricata:" + engine_event["event_id"]


def test_suricata_http_observed_normalizes_to_contract():
    from src.detection.external_engine.eve_selector import EveRecordMapper
    from src.detection.external_engine.normalize import normalize_ndr_event

    mapper = EveRecordMapper(site_id="lab-ot-site", sensor_id="ndr-edge-001")
    http = {
        "timestamp": "2026-06-19T03:30:05.000000+0000",
        "flow_id": 100,
        "event_type": "http",
        "src_ip": "192.168.80.131",
        "dest_ip": "192.168.80.130",
        "dest_port": 80,
        "proto": "TCP",
        "app_proto": "http",
        "http": {"hostname": "192.168.80.130", "http_method": "GET", "url": "/"},
    }
    normalized = normalize_ndr_event(
        mapper.map(http).to_dict(), tenant_id="lab-tenant", workspace_id="ws-lab-1"
    )
    NDR_VALIDATOR.validate(normalized)
    assert normalized["event_type"] == "NDR_HTTP_OBSERVED"
    assert normalized["protocol"] == "http"


def test_edgex_ot_evidence_matches_contract():
    from edgex_event_bridge import build_ot_evidence

    event = {
        "id": "evt-fan-002",
        "deviceName": "ot-fan-relay",
        "profileName": "modbus-relay",
        "sourceName": "FanRPM",
        "origin": 1780000000000000000,
        "readings": [{"resourceName": "FanRPM", "value": "1500", "units": "rpm"}],
    }
    out = build_ot_evidence(
        event,
        site_id="lab-ot-site",
        sensor_id="ot-edge-001",
        source_host="192.168.80.130",
        tenant_id="lab-tenant",
        workspace_id="ws-lab-1",
    )
    OT_VALIDATOR.validate(out)
    assert out["device_id"] == "ot-fan-relay"
    assert out["target_ip"] == "192.168.80.130"


def test_shared_fixtures_conform_to_contract():
    ndr_fixture = json.loads((FIXTURES / "ndr_event.suricata_http.json").read_text(encoding="utf-8"))
    ot_fixture = json.loads((FIXTURES / "ot_evidence.edgex_fan_rpm.json").read_text(encoding="utf-8"))
    NDR_VALIDATOR.validate(ndr_fixture)
    OT_VALIDATOR.validate(ot_fixture)
    # Both fixtures describe the same lab target -> correlatable.
    assert ndr_fixture["target_ip"] == ot_fixture["target_ip"] == "192.168.80.130"
    assert ndr_fixture["site_id"] == ot_fixture["site_id"] == "lab-ot-site"
