"""ARP parsing + OT-003 (MAC/IP mapping change & ARP spoofing) unit tests."""

from __future__ import annotations

import tempfile
from pathlib import Path

from service_loader import import_from_service

ROOT = Path(__file__).resolve().parents[2]


def _import_packet_modules():
    from scapy.all import ARP, Ether, IP, TCP

    arp, processor = import_from_service(
        "packet-sensor", "src.parser.l3.arp", "src.pipeline.processor"
    )
    return ARP, Ether, IP, TCP, arp.parse_arp, processor.PacketPipeline


def _pipeline(tmp_path: Path):
    *_, PacketPipeline = _import_packet_modules()
    policy = ROOT / "config/policy/baseline.example.json"
    return PacketPipeline(
        sensor_id="test-sensor",
        site_id="factory-lab-001",
        policy_path=str(policy),
        assets_dir=str(tmp_path),
        rules_enabled=["OT-001", "OT-002", "OT-003"],
    )


def test_parse_arp_extracts_binding() -> None:
    ARP, Ether, _, _, parse_arp, _ = _import_packet_modules()
    frame = Ether(src="02:11:11:11:11:11") / ARP(
        op=2, hwsrc="02:11:11:11:11:11", psrc="192.168.10.77", pdst="192.168.10.1"
    )
    arp = parse_arp(frame)
    assert arp is not None
    assert arp.sender_ip == "192.168.10.77"
    assert arp.sender_mac == "02:11:11:11:11:11"
    assert arp.is_reply is True


def test_parse_arp_none_for_non_arp() -> None:
    _, Ether, IP, TCP, parse_arp, _ = _import_packet_modules()
    assert parse_arp(IP(src="1.1.1.1", dst="2.2.2.2") / TCP()) is None


def test_ot003_arp_spoofing_fires_on_binding_flip() -> None:
    """Same IP announced by two different MACs → ARP spoofing → OT-003."""
    with tempfile.TemporaryDirectory() as tmp:
        pipeline = _pipeline(Path(tmp))
        ARP, Ether, *_ = _import_packet_modules()
        ip = "192.168.10.77"
        pipeline.process(Ether(src="02:11:11:11:11:11") / ARP(op=2, hwsrc="02:11:11:11:11:11", psrc=ip, pdst=ip))
        pipeline.process(Ether(src="02:22:22:22:22:22") / ARP(op=2, hwsrc="02:22:22:22:22:22", psrc=ip, pdst=ip))
        events = pipeline.event_store.read_recent(limit=50)
        ot003 = [e for e in events if e["rule_id"] == "OT-003"]
        assert ot003, "expected OT-003 to fire on ARP binding flip"
        assert ot003[-1]["evidence"]["indicator"] == "arp_spoofing"
        assert ot003[-1]["evidence"]["previous_mac"] == "02:11:11:11:11:11"


def test_ot003_no_alert_for_stable_binding() -> None:
    """A repeated, unchanged binding must NOT raise OT-003 (regression guard)."""
    with tempfile.TemporaryDirectory() as tmp:
        pipeline = _pipeline(Path(tmp))
        ARP, Ether, *_ = _import_packet_modules()
        ip = "192.168.10.77"
        for _ in range(3):
            pipeline.process(Ether(src="02:11:11:11:11:11") / ARP(op=2, hwsrc="02:11:11:11:11:11", psrc=ip, pdst=ip))
        events = pipeline.event_store.read_recent(limit=50)
        assert not [e for e in events if e["rule_id"] == "OT-003"]


def test_ot003_mac_ip_change_over_ip_traffic() -> None:
    """The MAC->IP path (non-ARP) must also fire after the ordering fix."""
    with tempfile.TemporaryDirectory() as tmp:
        pipeline = _pipeline(Path(tmp))
        _, Ether, IP, TCP, *_ = _import_packet_modules()
        mac = "02:ab:cd:ef:00:01"
        pipeline.process(Ether(src=mac) / IP(src="192.168.10.60", dst="192.168.10.20") / TCP(dport=502))
        pipeline.process(Ether(src=mac) / IP(src="192.168.10.61", dst="192.168.10.20") / TCP(dport=502))
        events = pipeline.event_store.read_recent(limit=50)
        ot003 = [e for e in events if e["rule_id"] == "OT-003"]
        assert ot003, "expected OT-003 when one MAC changes its IP"
        assert ot003[-1]["evidence"]["previous_ip"] == "192.168.10.60"
