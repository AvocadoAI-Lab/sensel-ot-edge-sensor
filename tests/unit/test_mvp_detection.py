"""MVP detection and Modbus parser unit tests (Sprint 2)."""

from __future__ import annotations

import tempfile
from pathlib import Path

from service_loader import import_from_service

ROOT = Path(__file__).resolve().parents[2]


def _import_packet_modules():
    from scapy.all import IP, Raw, TCP

    modbus, processor = import_from_service(
        "packet-sensor", "src.parser.l7.modbus.tcp", "src.pipeline.processor"
    )
    return IP, Raw, TCP, modbus.parse_modbus_tcp, processor.PacketPipeline


def _pipeline(tmp_path: Path):
    _, _, _, _, PacketPipeline = _import_packet_modules()
    policy = ROOT / "config/policy/baseline.example.json"
    return PacketPipeline(
        sensor_id="test-sensor",
        site_id="factory-lab-001",
        policy_path=str(policy),
        assets_dir=str(tmp_path),
        rules_enabled=[
            "OT-001",
            "OT-002",
            "OT-004",
            "OT-007",
            "OT-010",
        ],
    )


def _modbus_write_packet(src: str, dst: str, function_code: int = 16):
    IP, Raw, TCP, _, _ = _import_packet_modules()
    trans_id = b"\x00\x01"
    proto = b"\x00\x00"
    length = b"\x00\x06"
    unit_id = b"\x01"
    fc = bytes([function_code])
    payload = trans_id + proto + length + unit_id + fc + b"\x00\x01\x00\x02"
    return IP(src=src, dst=dst) / TCP(sport=40000, dport=502, flags="PA") / Raw(payload)


def test_parse_modbus_write() -> None:
    _, _, _, parse_modbus_tcp, _ = _import_packet_modules()
    frame = parse_modbus_tcp(_modbus_write_packet("192.168.10.88", "192.168.10.20"))
    assert frame is not None
    assert frame.is_write is True
    assert frame.function_code == 16


def test_ot007_unexpected_modbus_write() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        pipeline = _pipeline(Path(tmp))
        pipeline.process(_modbus_write_packet("192.168.10.88", "192.168.10.20"))
        events = pipeline.event_store.read_recent()
        assert any(event["rule_id"] == "OT-007" for event in events)


def test_ot001_ot002_on_first_observation() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        pipeline = _pipeline(Path(tmp))
        IP, Raw, TCP, _, _ = _import_packet_modules()
        from scapy.all import Ether

        packet = (
            Ether(src="aa:bb:cc:dd:ee:ff")
            / IP(src="192.168.10.99", dst="192.168.10.20")
            / TCP(sport=1234, dport=502)
            / Raw(b"test")
        )
        pipeline.process(packet)
        rule_ids = {event["rule_id"] for event in pipeline.event_store.read_recent()}
        assert "OT-001" in rule_ids
        assert "OT-002" in rule_ids


def test_event_has_evidence_ref() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        pipeline = _pipeline(Path(tmp))
        pipeline.process(_modbus_write_packet("192.168.10.88", "192.168.10.20"))
        events = pipeline.event_store.read_recent()
        assert events
        assert events[0].get("evidence_ref", "").startswith("local-ringbuffer://")
