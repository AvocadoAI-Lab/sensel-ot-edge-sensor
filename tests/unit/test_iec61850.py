"""IEC 61850 parser and detection unit tests."""

from __future__ import annotations

import tempfile
from pathlib import Path

from service_loader import import_from_service

ROOT = Path(__file__).resolve().parents[2]


def _import_packet_modules():
    from scapy.all import Ether, IP, Raw, TCP

    goose, mms, processor = import_from_service(
        "packet-sensor",
        "src.parser.l7.iec61850.goose",
        "src.parser.l7.iec61850.mms",
        "src.pipeline.processor",
    )
    return (
        Ether,
        IP,
        Raw,
        TCP,
        goose.build_goose_wire,
        goose.parse_goose_wire,
        mms.build_mms_write_probe,
        mms.classify_mms_payload,
        goose.GOOSE_ETHERTYPE,
        processor.PacketPipeline,
    )


def test_parse_goose_wire_roundtrip() -> None:
    _, _, _, _, build_goose_wire, parse_goose_wire, _, _, _, _ = _import_packet_modules()
    raw = build_goose_wire(1000, "ied/LLN0.gcb", "goLab", 3, 7)
    frame = parse_goose_wire(raw)
    assert frame is not None
    assert frame.appid == 1000
    assert frame.gocb_ref == "ied/LLN0.gcb"
    assert frame.st_num == 3
    assert frame.sq_num == 7


def test_classify_mms_write_payload() -> None:
    _, _, _, _, _, _, build_mms_write_probe, classify_mms_payload, _, _ = _import_packet_modules()
    assert classify_mms_payload(build_mms_write_probe()) == "write"


def test_pipeline_generates_ot011_ot016() -> None:
    (
        Ether,
        IP,
        Raw,
        TCP,
        build_goose_wire,
        _parse_goose_wire,
        build_mms_write_probe,
        _classify_mms_payload,
        GOOSE_ETHERTYPE,
        PacketPipeline,
    ) = _import_packet_modules()

    policy = ROOT / "config/policy/baseline.example.json"
    with tempfile.TemporaryDirectory() as tmp:
        pipeline = PacketPipeline(
            sensor_id="ut-001",
            site_id="factory-lab-001",
            policy_path=str(policy),
            assets_dir=tmp,
        )
        goose_payload = build_goose_wire(
            1000,
            "simpleIOGenericIO/LLN0.gcbEvents",
            "lab",
            1,
            1,
        )
        goose_pkt = Ether(
            dst="01:0c:cd:01:00:01",
            src="00:99:88:77:66:55",
            type=GOOSE_ETHERTYPE,
        ) / Raw(goose_payload)
        mms_pkt = (
            IP(src="192.168.10.88", dst="192.168.10.50")
            / TCP(sport=40001, dport=102)
            / Raw(build_mms_write_probe())
        )
        pipeline.process(goose_pkt)
        pipeline.process(mms_pkt)
        pipeline.flush_features()

        events = pipeline.event_store.read_recent()
        rules = {e["rule_id"] for e in events}
        assert "OT-011" in rules
        assert "OT-016" in rules
        assert (Path(tmp) / "iec61850-goose-summary.json").is_file()
