"""Unit tests for the Modbus FC43 device-identification parser."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.probe.device_probe import parse_device_id_response


def _build_response(objs: dict[int, bytes]) -> bytes:
    # PDU body: FC 2B, MEI 0E, readcode 01, conformity 01, more 00, nextid 00, count N, then objects
    body = bytes([0x2B, 0x0E, 0x01, 0x01, 0x00, 0x00, len(objs)])
    for oid, val in objs.items():
        body += bytes([oid, len(val)]) + val
    length = len(body) + 1  # + unit id
    mbap = b"\x00\x01\x00\x00" + length.to_bytes(2, "big") + b"\x01"
    return mbap + body


def test_parse_basic_device_identification():
    resp = _build_response({0x00: b"Schneider", 0x01: b"BMXP58", 0x02: b"V2.70"})
    parsed = parse_device_id_response(resp)
    assert parsed == {"vendor": "Schneider", "product": "BMXP58", "revision": "V2.70"}


def test_parse_rejects_non_fc43():
    # A normal read-holding-registers response, not FC43
    resp = b"\x00\x01\x00\x00\x00\x05\x01\x03\x02\x00\x0a"
    assert parse_device_id_response(resp) is None


def test_parse_handles_partial_objects():
    resp = _build_response({0x00: b"ABB"})
    parsed = parse_device_id_response(resp)
    assert parsed["vendor"] == "ABB"
    assert parsed["product"] is None
