"""IEC 61850 MMS passive parser (TCP/102).

Decodes the TPKT/COTP envelope and walks the MMS PDU with BER to classify the
service (read / write / report / getNameList), tolerating an intervening ISO
session/presentation layer. Falls back to a byte-signature / plaintext heuristic
so simplified lab probes and odd vendor stacks still classify. This is a passive
*classifier*, not a full ISO-9506 decoder (PRD non-goal).
"""

from __future__ import annotations

from dataclasses import dataclass, field

from scapy.layers.inet import IP, TCP

from src.parser.l7.iec61850 import ber

MMS_PORT = 102

# MMS PDU outer tags — MMSpdu ::= CHOICE, context [n] constructed.
_PDU_CONFIRMED_REQUEST = 0xA0   # [0]
_PDU_CONFIRMED_RESPONSE = 0xA1  # [1]
_PDU_CONFIRMED_ERROR = 0xA2     # [2]
_PDU_UNCONFIRMED = 0xA3         # [3]
_MMS_PDU_TAGS = frozenset(
    {_PDU_CONFIRMED_REQUEST, _PDU_CONFIRMED_RESPONSE, _PDU_CONFIRMED_ERROR, _PDU_UNCONFIRMED}
)

# ConfirmedServiceRequest CHOICE context tags (subset we care about).
_SVC_GETNAMELIST = 0xA1  # [1]
_SVC_READ = 0xA4         # [4]
_SVC_WRITE = 0xA5        # [5]


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


def _strip_tpkt_cotp(payload: bytes) -> bytes | None:
    """Return the bytes after the TPKT(RFC1006) + COTP header, or None."""
    if len(payload) < 7 or payload[0] != 0x03:
        return None
    tpkt_len = int.from_bytes(payload[2:4], "big")
    body = payload[4:tpkt_len] if 4 < tpkt_len <= len(payload) else payload[4:]
    if not body:
        return None
    cotp_li = body[0]  # length indicator = octets following this one
    if 0 < cotp_li + 1 <= len(body):
        return body[cotp_li + 1 :]
    return body


def _confirmed_service_kind(content: bytes) -> str:
    """Within a Confirmed-RequestPDU, find the service CHOICE tag."""
    offset = 0
    while offset < len(content):
        try:
            tag, _value, offset = ber.read_tlv(content, offset)
        except ValueError:
            break
        if tag == _SVC_WRITE:
            return "write"
        if tag == _SVC_READ:
            return "read"
        if tag == _SVC_GETNAMELIST:
            return "getNameList"
    return "confirmed-other"


def _candidate_starts(rest: bytes):
    """Offsets to attempt an MMS PDU BER read — 0 first, then any MMS PDU tag
    byte (handles a leading ISO session/presentation wrapper)."""
    yield 0
    for index, octet in enumerate(rest):
        if index and octet in _MMS_PDU_TAGS:
            yield index


def _mms_ber_kind(rest: bytes) -> str:
    for start in _candidate_starts(rest):
        try:
            tag, value, _end = ber.read_tlv(rest, start)
        except ValueError:
            continue
        if tag == _PDU_CONFIRMED_REQUEST:
            return _confirmed_service_kind(value)
        if tag == _PDU_UNCONFIRMED:
            return "report"  # informationReport
        if tag == _PDU_CONFIRMED_RESPONSE:
            return "response"
        if tag == _PDU_CONFIRMED_ERROR:
            return "error"
    return "other"


def _text_fallback(payload: bytes) -> str:
    low = payload.lower()
    if b"getnamelist" in low:
        return "getNameList"
    if b"write" in low:
        return "write"
    if b"read" in low:
        return "read"
    if b"report" in low:
        return "report"
    return "other"


def classify_mms_payload(payload: bytes) -> str:
    if len(payload) < 8:
        return "other"

    rest = _strip_tpkt_cotp(payload)
    ber_kind = _mms_ber_kind(rest) if rest is not None else "other"
    if ber_kind in ("write", "read", "report", "getNameList"):
        return ber_kind

    text_kind = _text_fallback(payload)
    if text_kind != "other":
        return text_kind

    # response/error/confirmed-other carry less detection value than a request,
    # but are still more informative than "other".
    return ber_kind if ber_kind != "other" else "other"


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


# --------------------------------------------------------------------------- #
# Builders — emit *real* BER-encoded MMS PDUs for the lab / tests.
# --------------------------------------------------------------------------- #
def _wrap_tpkt_cotp(mms_pdu: bytes) -> bytes:
    cotp = b"\x02\xf0\x80"  # COTP DT data, EOT
    inner = cotp + mms_pdu
    tpkt = b"\x03\x00" + (len(inner) + 4).to_bytes(2, "big")
    return tpkt + inner


def _confirmed_request(invoke_id: int, service_tag: int, service_body: bytes) -> bytes:
    service = bytes([service_tag]) + ber.encode_length(len(service_body)) + service_body
    seq = ber.encode_integer(0x02, invoke_id) + service
    return bytes([_PDU_CONFIRMED_REQUEST]) + ber.encode_length(len(seq)) + seq


def build_mms_write_probe(invoke_id: int = 42) -> bytes:
    """A genuine MMS confirmed Write-Request over TPKT/COTP."""
    # write [5] { variableAccessSpecification, listOfData } — minimal stub body.
    var_spec = bytes([0x84, 0x03, 0x80, 0x00, 0x01])  # objectName / alternate-access stub
    list_of_data = bytes([0xA0, 0x03, 0x84, 0x01, 0x01])
    return _wrap_tpkt_cotp(_confirmed_request(invoke_id, _SVC_WRITE, var_spec + list_of_data))


def build_mms_read_probe(invoke_id: int = 7) -> bytes:
    """A genuine MMS confirmed Read-Request over TPKT/COTP."""
    var_spec = bytes([0xA0, 0x03, 0x84, 0x01, 0x01])
    return _wrap_tpkt_cotp(_confirmed_request(invoke_id, _SVC_READ, var_spec))


def build_mms_report() -> bytes:
    """An unconfirmed informationReport PDU over TPKT/COTP."""
    info_report = bytes([0xA0, 0x02, 0x80, 0x00])  # informationReport [0] stub
    pdu = bytes([_PDU_UNCONFIRMED]) + ber.encode_length(len(info_report)) + info_report
    return _wrap_tpkt_cotp(pdu)


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
