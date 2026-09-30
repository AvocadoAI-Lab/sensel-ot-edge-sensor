#!/usr/bin/env python3
"""Offline MVP detection self-test (OT-001~010 paths, no live capture)."""

from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "services" / "packet-sensor"))

from scapy.all import IP, Raw, TCP

from src.pipeline.processor import PacketPipeline

POLICY = ROOT / "config/policy/baseline.example.json"


def _modbus_write(src: str, dst: str, fc: int = 16):
    payload = b"\x00\x01\x00\x00\x00\x06\x01" + bytes([fc]) + b"\x00\x01\x00\x02"
    return IP(src=src, dst=dst) / TCP(sport=40001, dport=502, flags="PA") / Raw(payload)


def main() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        pipeline = PacketPipeline(
            sensor_id="test-sensor",
            site_id="factory-lab-001",
            policy_path=str(POLICY),
            assets_dir=tmp,
            rules_enabled=[f"OT-{i:03d}" for i in range(1, 11)],
        )

        pipeline.process(_modbus_write("192.168.10.88", "192.168.10.20"))
        pipeline.process(
            IP(src="192.168.10.99", dst="192.168.10.20")
            / TCP(sport=50000, dport=502, flags="S")
        )
        pipeline.flush_features()

        events = pipeline.event_store.read_recent(limit=50)
        rule_ids = sorted({event["rule_id"] for event in events})
        print("MVP self-test OK")
        print("events:", ", ".join(rule_ids) or "none")
        if events:
            print("sample:", json.dumps(events[0], indent=2)[:400])
        if not any(event["rule_id"] == "OT-007" for event in events):
            print("ERROR: expected OT-007 Modbus write anomaly", file=sys.stderr)
            return 1
        if not any(event.get("evidence_ref") for event in events):
            print("ERROR: expected evidence_ref on events", file=sys.stderr)
            return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
