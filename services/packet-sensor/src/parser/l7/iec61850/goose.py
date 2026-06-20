"""IEC 61850 GOOSE passive parser (L2 EtherType 0x88B8)."""

from __future__ import annotations

from dataclasses import dataclass, field

from scapy.layers.l2 import Ether

from src.parser.l7.iec61850 import ber

GOOSE_ETHERTYPE = 0x88B8


@dataclass
class GooseFrame:
    publisher_mac: str
    appid: int
    gocb_ref: str
    go_id: str
    st_num: int
    sq_num: int
    test: bool
    conf_rev: int
    raw_length: int


@dataclass
class GooseStats:
    message_count: int = 0
    stnum_changes: int = 0
    test_flag_count: int = 0
    publishers: dict[str, GooseFrame] = field(default_factory=dict)
    _last_stnum: dict[str, int] = field(default_factory=dict)


def _extract_l2_payload(packet) -> tuple[str, bytes] | None:
    if not packet.haslayer(Ether):
        return None
    eth: Ether = packet[Ether]
    payload = bytes(eth.payload)
    offset = 0
    ethertype = eth.type
    if eth.type == 0x8100 and len(payload) >= 4:
        ethertype = int.from_bytes(payload[2:4], "big")
        offset = 4
    if ethertype != GOOSE_ETHERTYPE:
        return None
    return str(eth.src), payload[offset:]


def parse_goose_pdu(pdu: bytes) -> dict:
    fields: dict = {}
    if pdu and pdu[0] == 0x61:
        _, content, _ = ber.read_tlv(pdu, 0)
        offset = 0
        while offset < len(content):
            tag, value, offset = ber.read_tlv(content, offset)
            if tag == 0x80:
                fields["gocb_ref"] = ber.decode_visible_string(value)
            elif tag == 0x83:
                fields["go_id"] = ber.decode_visible_string(value)
            elif tag == 0x85:
                fields["st_num"] = ber.decode_integer(value)
            elif tag == 0x86:
                fields["sq_num"] = ber.decode_integer(value)
            elif tag == 0x87:
                fields["test"] = value == b"\xff"
            elif tag == 0x88:
                fields["conf_rev"] = ber.decode_integer(value)
        return fields

    offset = 0
    while offset < len(pdu):
        tag, value, offset = ber.read_tlv(pdu, offset)
        if tag == 0x80:
            fields["gocb_ref"] = ber.decode_visible_string(value)
        elif tag == 0x83:
            fields["go_id"] = ber.decode_visible_string(value)
        elif tag == 0x85:
            fields["st_num"] = ber.decode_integer(value)
        elif tag == 0x86:
            fields["sq_num"] = ber.decode_integer(value)
        elif tag == 0x87:
            fields["test"] = value == b"\xff"
        elif tag == 0x88:
            fields["conf_rev"] = ber.decode_integer(value)
    return fields


def parse_goose_wire(raw: bytes) -> GooseFrame | None:
    if len(raw) < 8:
        return None
    appid = int.from_bytes(raw[0:2], "big")
    length = int.from_bytes(raw[2:4], "big")
    pdu = raw[8 : 8 + max(0, length - 8)] if length >= 8 else raw[8:]
    if not pdu:
        pdu = raw[8:]
    fields = parse_goose_pdu(pdu)
    if "gocb_ref" not in fields:
        return None
    return GooseFrame(
        publisher_mac="",
        appid=appid,
        gocb_ref=fields.get("gocb_ref", ""),
        go_id=fields.get("go_id", ""),
        st_num=int(fields.get("st_num", 0)),
        sq_num=int(fields.get("sq_num", 0)),
        test=bool(fields.get("test", False)),
        conf_rev=int(fields.get("conf_rev", 0)),
        raw_length=len(raw),
    )


def parse_goose_packet(packet) -> GooseFrame | None:
    extracted = _extract_l2_payload(packet)
    if not extracted:
        return None
    src_mac, payload = extracted
    frame = parse_goose_wire(payload)
    if frame is None:
        return None
    frame.publisher_mac = src_mac
    return frame


def build_goose_wire(
    appid: int,
    gocb_ref: str,
    go_id: str,
    st_num: int,
    sq_num: int,
    *,
    test: bool = False,
    conf_rev: int = 1,
) -> bytes:
    body = b"".join(
        [
            ber.encode_visible_string(0x80, gocb_ref),
            ber.encode_integer(0x81, 1000),
            ber.encode_visible_string(0x82, "labDataset"),
            ber.encode_visible_string(0x83, go_id),
            ber.encode_integer(0x85, st_num),
            ber.encode_integer(0x86, sq_num),
            ber.encode_boolean(0x87, test),
            ber.encode_integer(0x88, conf_rev),
        ]
    )
    apdu = bytes([0x61]) + ber.encode_length(len(body)) + body
    length = len(apdu) + 8
    header = appid.to_bytes(2, "big") + length.to_bytes(2, "big") + b"\x00" * 4
    return header + apdu


def record_goose(stats: GooseStats, frame: GooseFrame) -> None:
    stats.message_count += 1
    if frame.test:
        stats.test_flag_count += 1
    key = f"{frame.publisher_mac}|{frame.appid}|{frame.gocb_ref}"
    prev = stats._last_stnum.get(key)
    if prev is not None and frame.st_num != prev:
        stats.stnum_changes += 1
    stats._last_stnum[key] = frame.st_num
    stats.publishers[key] = frame
