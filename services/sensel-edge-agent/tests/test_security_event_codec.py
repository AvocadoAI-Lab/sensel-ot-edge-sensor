from __future__ import annotations

import pytest

from src.contracts.security_event_codec import decode_security_event, encode_security_event


def _event() -> dict:
    return {
        "event_id": "evt-20260618-snort-00001",
        "asset_id": "asset-plc-001",
        "event_type": "SNORT_ALERT",
        "severity": "high",
        "rule_id": "snort-1-9000001",
        "protocol": "tcp",
        "description": "SENSEL CTI C2 beacon",
        "timestamp": "2026-06-18T10:30:00Z",
        "risk_score": 85,
        "src_ip": "10.10.1.20",
        "dst_ip": "203.0.113.10",
        "dst_port": 443,
        "evidence": {
            "engine": "snort",
            "sid": 9000001,
            "mirror_passive": True,
            "context": {"direction": "egress", "tags": ["cti", "c2"]},
        },
        "feature_contract_id": "flow-v1",
    }


def _identity() -> dict:
    return {
        "tenant_id": "tenant-a",
        "site_id": "factory-lab-001",
        "sensor_id": "ot-edge-001",
        "producer_version": "0.5.0",
        "trace_id": "trace-001",
    }


def test_security_event_round_trip_preserves_legacy_fields() -> None:
    encoded = encode_security_event(_event(), **_identity())
    decoded = decode_security_event(encoded)

    assert decoded["event_id"] == "evt-20260618-snort-00001"
    assert decoded["tenant_id"] == "tenant-a"
    assert decoded["site_id"] == "factory-lab-001"
    assert decoded["sensor_id"] == "ot-edge-001"
    assert decoded["timestamp"] == "2026-06-18T10:30:00+00:00"
    assert decoded["severity"] == "high"
    assert decoded["risk_score"] == 85
    assert decoded["dst_port"] == 443
    assert decoded["evidence"] == _event()["evidence"]


def test_security_event_encoding_is_deterministic() -> None:
    first = encode_security_event(_event(), **_identity())
    second = encode_security_event(_event(), **_identity())

    assert first == second


def test_security_event_requires_stable_event_id() -> None:
    event = _event()
    event.pop("event_id")

    with pytest.raises(ValueError, match="requires event_id"):
        encode_security_event(event, **_identity())


def test_security_event_requires_event_type() -> None:
    event = _event()
    event.pop("event_type")

    with pytest.raises(ValueError, match="requires event_type"):
        encode_security_event(event, **_identity())


@pytest.mark.parametrize("risk_score", [-1, 101])
def test_security_event_rejects_out_of_range_risk_score(risk_score: int) -> None:
    event = _event()
    event["risk_score"] = risk_score

    with pytest.raises(ValueError, match="between 0 and 100"):
        encode_security_event(event, **_identity())
