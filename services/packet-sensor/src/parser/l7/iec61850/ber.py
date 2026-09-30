"""Minimal BER helpers for IEC 61850 GOOSE/MMS passive parsing."""

from __future__ import annotations


def read_length(data: bytes, offset: int) -> tuple[int, int]:
    if offset >= len(data):
        raise ValueError("offset out of range")
    first = data[offset]
    offset += 1
    if first & 0x80 == 0:
        return first, offset
    num_octets = first & 0x7F
    if num_octets == 0 or offset + num_octets > len(data):
        raise ValueError("invalid BER length")
    value = int.from_bytes(data[offset : offset + num_octets], "big")
    return value, offset + num_octets


def read_tlv(data: bytes, offset: int) -> tuple[int, bytes, int]:
    if offset >= len(data):
        raise ValueError("offset out of range")
    tag = data[offset]
    offset += 1
    length, offset = read_length(data, offset)
    end = offset + length
    if end > len(data):
        raise ValueError("TLV exceeds buffer")
    return tag, data[offset:end], end


def encode_length(length: int) -> bytes:
    if length < 0x80:
        return bytes([length])
    if length <= 0xFF:
        return bytes([0x81, length])
    return bytes([0x82, (length >> 8) & 0xFF, length & 0xFF])


def encode_integer(tag: int, value: int) -> bytes:
    if value == 0:
        body = b"\x00"
    else:
        nbytes = max(1, (value.bit_length() + 8) // 8)
        body = value.to_bytes(nbytes, "big", signed=True)
    return bytes([tag]) + encode_length(len(body)) + body


def encode_visible_string(tag: int, text: str) -> bytes:
    body = text.encode("ascii")
    return bytes([tag]) + encode_length(len(body)) + body


def encode_boolean(tag: int, value: bool) -> bytes:
    body = b"\xff" if value else b"\x00"
    return bytes([tag]) + encode_length(len(body)) + body


def decode_integer(raw: bytes) -> int:
    if not raw:
        return 0
    return int.from_bytes(raw, "big", signed=True)


def decode_visible_string(raw: bytes) -> str:
    return raw.decode("ascii", errors="replace")
