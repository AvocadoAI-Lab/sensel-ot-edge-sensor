"""Read-only active device probe: TCP port fingerprint + Modbus device ID.

Deliberately conservative: a plain TCP connect to known OT ports (no payload
except the standardised, read-only Modbus FC43 Read Device Identification).
Never writes to a device. Intended to be invoked one-shot via ``docker exec``.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import socket
import sys
import tempfile
import time
from datetime import datetime, timezone

# Common OT / management ports to fingerprint (label shown in UI).
OT_PORTS: dict[int, str] = {
    102: "IEC 61850 MMS",
    502: "Modbus TCP",
    4840: "OPC UA",
    44818: "EtherNet/IP",
    20000: "DNP3",
    2404: "IEC 60870-5-104",
    80: "HTTP",
    443: "HTTPS",
    22: "SSH",
}


def _now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _tcp_open(ip: str, port: int, timeout: float) -> bool:
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except (OSError, ValueError):
        return False


def parse_device_id_response(resp: bytes) -> dict | None:
    """Parse a Modbus FC43/MEI14 Read Device Identification response."""
    # Need at least MBAP(7) + FC + MEI + readcode + conformity + more + nextid + count
    if len(resp) < 14 or resp[7] != 0x2B or resp[8] != 0x0E:
        return None
    num_objects = resp[13]
    idx = 14
    objects: dict[int, str] = {}
    for _ in range(num_objects):
        if idx + 2 > len(resp):
            break
        obj_id = resp[idx]
        obj_len = resp[idx + 1]
        start = idx + 2
        value = resp[start:start + obj_len]
        idx = start + obj_len
        objects[obj_id] = value.decode("ascii", errors="replace").strip()
    if not objects:
        return None
    return {
        "vendor": objects.get(0x00),
        "product": objects.get(0x01),
        "revision": objects.get(0x02),
    }


def modbus_device_id(ip: str, *, unit: int = 1, timeout: float = 2.0) -> dict | None:
    """Modbus FC 0x2B / MEI 0x0E Read Device Identification (read-only)."""
    # MBAP(trans=1, proto=0, len=5, unit) + PDU(FC=2B, MEI=0E, readcode=01 basic, objid=00)
    req = b"\x00\x01\x00\x00\x00\x05" + bytes([unit & 0xFF]) + b"\x2b\x0e\x01\x00"
    try:
        with socket.create_connection((ip, 502), timeout=timeout) as sock:
            sock.settimeout(timeout)
            sock.sendall(req)
            resp = sock.recv(512)
    except (OSError, ValueError):
        return None
    return parse_device_id_response(resp)


def probe_host(ip: str, *, timeout: float = 2.0) -> dict:
    ipaddress.ip_address(ip)  # raises ValueError on malformed input
    started = time.time()
    open_ports: list[dict] = []
    for port, label in OT_PORTS.items():
        if _tcp_open(ip, port, timeout=min(timeout, 1.5)):
            open_ports.append({"port": port, "service": label})

    modbus = None
    if any(p["port"] == 502 for p in open_ports):
        modbus = modbus_device_id(ip, timeout=timeout)

    identity: dict[str, str | None] = {"vendor": None, "model": None, "firmware": None}
    if modbus:
        identity = {
            "vendor": modbus.get("vendor"),
            "model": modbus.get("product"),
            "firmware": modbus.get("revision"),
        }

    return {
        "ip": ip,
        "reachable": bool(open_ports),
        "open_ports": open_ports,
        "modbus_identity": modbus,
        "identity": identity,
        "identity_source": "modbus_fc43" if modbus else None,
        "probed_at": _now_iso(),
        "elapsed_sec": round(time.time() - started, 2),
    }


def _atomic_write(path: str, payload: dict) -> None:
    parent = os.path.dirname(path) or "."
    os.makedirs(parent, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=parent, suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, ensure_ascii=False, indent=2)
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="probe.device_probe")
    parser.add_argument("--ip", required=True)
    parser.add_argument("--out", required=True)
    parser.add_argument("--timeout", type=float, default=2.0)
    args = parser.parse_args(argv)
    try:
        result = probe_host(args.ip, timeout=args.timeout)
    except ValueError:
        print(json.dumps({"ok": False, "error": f"invalid ip: {args.ip}"}))
        return 2
    _atomic_write(args.out, result)
    print(json.dumps({"ok": True, "out": args.out, "reachable": result["reachable"], "identity": result["identity"]}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
