"""Integration: serialize attack packets to a real .pcap, read them back via
scapy, and run them through the full PacketPipeline — exercising the
capture→parse→detect chain end-to-end without needing a live interface/root.
"""

from __future__ import annotations

import tempfile
from pathlib import Path

from service_loader import import_from_service

ROOT = Path(__file__).resolve().parents[2]


def _import():
    from scapy.all import ARP, Ether, IP, Raw, TCP, rdpcap, wrpcap

    goose, mms, processor = import_from_service(
        "packet-sensor",
        "src.parser.l7.iec61850.goose",
        "src.parser.l7.iec61850.mms",
        "src.pipeline.processor",
    )
    return {
        "ARP": ARP, "Ether": Ether, "IP": IP, "Raw": Raw, "TCP": TCP,
        "rdpcap": rdpcap, "wrpcap": wrpcap,
        "GOOSE_ETHERTYPE": goose.GOOSE_ETHERTYPE,
        "build_goose_wire": goose.build_goose_wire,
        "build_mms_write_probe": mms.build_mms_write_probe,
        "PacketPipeline": processor.PacketPipeline,
    }


def _build_attack_packets(ns: dict):
    ARP, Ether, IP, TCP, Raw = ns["ARP"], ns["Ether"], ns["IP"], ns["TCP"], ns["Raw"]
    build_goose_wire, build_mms_write_probe = ns["build_goose_wire"], ns["build_mms_write_probe"]
    GOOSE_ETHERTYPE = ns["GOOSE_ETHERTYPE"]
    modbus = b"\x00\x01\x00\x00\x00\x06\x01\x10\x00\x01\x00\x02"  # FC16 write
    return [
        # OT-003 ARP spoof: one IP, two MACs
        Ether(src="02:11:11:11:11:11") / ARP(op=2, hwsrc="02:11:11:11:11:11", psrc="192.168.10.77", pdst="192.168.10.77"),
        Ether(src="02:22:22:22:22:22") / ARP(op=2, hwsrc="02:22:22:22:22:22", psrc="192.168.10.77", pdst="192.168.10.77"),
        # OT-007 Modbus write from a non-baselined host
        Ether(src="02:aa:bb:cc:dd:ee") / IP(src="192.168.10.231", dst="192.168.10.20") / TCP(sport=40001, dport=502, flags="PA") / Raw(modbus),
        # OT-011 rogue GOOSE publisher
        Ether(dst="01:0c:cd:01:00:01", src="02:de:ad:be:ef:11", type=GOOSE_ETHERTYPE) / Raw(build_goose_wire(0x3FFF, "rogue/LLN0.gcbBad", "rogue", 1, 1)),
        # OT-016 rogue MMS write to a baselined IED
        Ether(src="02:aa:bb:cc:dd:ee") / IP(src="192.168.10.231", dst="192.168.10.50") / TCP(sport=45001, dport=102, flags="PA") / Raw(build_mms_write_probe()),
    ]


def test_pcap_replay_through_pipeline() -> None:
    ns = _import()
    wrpcap, rdpcap, PacketPipeline = ns["wrpcap"], ns["rdpcap"], ns["PacketPipeline"]
    policy = ROOT / "config/policy/baseline.example.json"

    with tempfile.TemporaryDirectory() as tmp:
        pcap_path = str(Path(tmp) / "attacks.pcap")
        wrpcap(pcap_path, _build_attack_packets(ns))

        # Read the packets back from disk — this is the realistic capture path.
        replayed = rdpcap(pcap_path)
        assert len(replayed) == 5

        pipeline = PacketPipeline(
            sensor_id="it-001",
            site_id="factory-lab-001",
            policy_path=str(policy),
            assets_dir=tmp,
            rules_enabled=[f"OT-{i:03d}" for i in range(1, 19)],
        )
        for packet in replayed:
            pipeline.process(packet)

        rules = {e["rule_id"] for e in pipeline.event_store.read_recent(limit=200)}
        for expected in ("OT-003", "OT-007", "OT-011", "OT-016", "OT-018"):
            assert expected in rules, f"{expected} not detected from replayed pcap; got {sorted(rules)}"
