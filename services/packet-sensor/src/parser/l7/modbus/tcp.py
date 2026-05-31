"""L7: Modbus TCP function code and read/write classification."""

from __future__ import annotations

from dataclasses import dataclass

from src.parser.l4.transport import FlowTuple, parse_transport

MODBUS_PORT = 502

# Common Modbus write function codes (MVP subset)
WRITE_FUNCTION_CODES = frozenset({5, 6, 15, 16, 22, 23, 24})
READ_FUNCTION_CODES = frozenset({1, 2, 3, 4, 20, 21, 43})


@dataclass(frozen=True)
class ModbusFrame:
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    transaction_id: int
    unit_id: int
    function_code: int
    is_write: bool


def _parse_modbus_payload(raw: bytes) -> tuple[int, int, int, bool] | None:
    if len(raw) < 8:
        return None
    trans_id = int.from_bytes(raw[0:2], "big")
    length = int.from_bytes(raw[4:6], "big")
    if length < 2 or len(raw) < 6 + length:
        return None
    unit_id = raw[6]
    function_code = raw[7]
    is_write = function_code in WRITE_FUNCTION_CODES
    return trans_id, unit_id, function_code, is_write


def parse_modbus_tcp(packet) -> ModbusFrame | None:
    """Parse Modbus TCP ADU from a Scapy packet."""
    flow = parse_transport(packet)
    if flow is None or flow.protocol != "tcp":
        return None
    if flow.dst_port != MODBUS_PORT and flow.src_port != MODBUS_PORT:
        return None

    raw = bytes(packet["TCP"].payload)
    parsed = _parse_modbus_payload(raw)
    if parsed is None:
        return None

    trans_id, unit_id, function_code, is_write = parsed
    return ModbusFrame(
        src_ip=flow.src_ip,
        dst_ip=flow.dst_ip,
        src_port=flow.src_port,
        dst_port=flow.dst_port,
        transaction_id=trans_id,
        unit_id=unit_id,
        function_code=function_code,
        is_write=is_write,
    )
