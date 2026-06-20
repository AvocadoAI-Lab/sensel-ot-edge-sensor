"""IEC 61850 MMS passive parser (TCP/102 heuristics)."""

from __future__ import annotations

from dataclasses import dataclass, field

from scapy.layers.inet import IP, TCP

MMS_PORT = 102


@dataclass
class MmsObservation:
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    pdu_type: str
    payload_len: int


@dataclass
class MmsStats:
    session_keys: set[str] = field(default_factory=set)
    read_count: int = 0
    write_count: int = 0
    report_count: int = 0
    other_count: int = 0
    observations: list[MmsObservation] = field(default_factory=list)


def _session_key(src_ip: str, src_port: int, dst_ip: str, dst_port: int) -> str:
    return f"{src_ip}:{src_port}->{dst_ip}:{dst_port}"


def classify_mms_payload(payload: bytes) -> str:
    if len(payload) < 8:
        return "other"
    if payload[0] != 0x03:
        return "other"
    tpkt_len = int.from_bytes(payload[2:4], "big")
    body = payload[4:tpkt_len] if tpkt_len <= len(payload) else payload[4:]
    haystack = body if body else payload
    if b"write" in haystack.lower():
        return "write"
    if b"read" in haystack.lower():
        return "read"
    if b"report" in haystack.lower():
        return "report"
    if b"getNameList" in haystack or b"GetNameList" in haystack:
        return "getNameList"
    if any(marker in haystack for marker in (b"\xa0", b"\xa1", b"\xa2")):
        if b"\xa4" in haystack or b"\x04" in haystack[-16:]:
            return "write"
        return "read"
    return "other"


def parse_mms_packet(packet) -> MmsObservation | None:
    if not packet.haslayer(IP) or not packet.haslayer(TCP):
        return None
    ip = packet[IP]
    tcp = packet[TCP]
    if MMS_PORT not in (int(tcp.sport), int(tcp.dport)):
        return None
    payload = bytes(tcp.payload)
    if not payload:
        return None
    pdu_type = classify_mms_payload(payload)
    return MmsObservation(
        src_ip=str(ip.src),
        dst_ip=str(ip.dst),
        src_port=int(tcp.sport),
        dst_port=int(tcp.dport),
        pdu_type=pdu_type,
        payload_len=len(payload),
    )


def build_mms_write_probe() -> bytes:
    tpkt = b"\x03\x00\x00\x2a"
    cotp = b"\x02\xf0\x80"
    mms_hint = b"confirmedRequest write service"
    return tpkt + cotp + mms_hint


def record_mms(stats: MmsStats, obs: MmsObservation) -> None:
    stats.session_keys.add(
        _session_key(obs.src_ip, obs.src_port, obs.dst_ip, obs.dst_port)
    )
    stats.observations.append(obs)
    if obs.pdu_type == "read":
        stats.read_count += 1
    elif obs.pdu_type == "write":
        stats.write_count += 1
    elif obs.pdu_type == "report":
        stats.report_count += 1
    else:
        stats.other_count += 1
