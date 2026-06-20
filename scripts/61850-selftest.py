#!/usr/bin/env python3
"""Offline IEC 61850 parser self-test (no live capture required)."""

from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "services" / "packet-sensor"))

from scapy.all import Ether, IP, Raw, TCP
from scapy.layers.l2 import Ether as EtherLayer

from src.parser.l7.iec61850.goose import GOOSE_ETHERTYPE, build_goose_wire
from src.parser.l7.iec61850.mms import build_mms_write_probe
from src.pipeline.processor import PacketPipeline

POLICY = ROOT / "config/policy/baseline.example.json"


def _goose_packet(*, test: bool = False):
    payload = build_goose_wire(
        1000,
        "simpleIOGenericIO/LLN0.gcbEvents",
        "labEvents",
        1,
        1,
        test=test,
    )
    return Ether(dst="01:0c:cd:01:00:01", src="00:22:33:44:55:66", type=GOOSE_ETHERTYPE) / Raw(payload)


def _mms_packet():
    return (
        IP(src="192.168.10.88", dst="192.168.10.50")
        / TCP(sport=45000, dport=102, flags="PA")
        / Raw(build_mms_write_probe())
    )


def main() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        pipeline = PacketPipeline(
            sensor_id="test-sensor",
            site_id="factory-lab-001",
            policy_path=str(POLICY),
            assets_dir=tmp,
        )
        pipeline.process(_goose_packet())
        pipeline.process(_goose_packet(test=True))
        pipeline.process(_mms_packet())
        pipeline.flush_features()

        events = pipeline.event_store.read_recent()
        goose_summary = Path(tmp) / "iec61850-goose-summary.json"
        mms_summary = Path(tmp) / "iec61850-mms-summary.json"

        errors = []
        if not events:
            errors.append("no security events generated")
        rule_ids = {event.get("rule_id") for event in events}
        for expected in ("OT-011", "OT-012", "OT-016"):
            if expected not in rule_ids:
                errors.append(f"missing event rule {expected}")
        if not goose_summary.is_file():
            errors.append("missing goose feature summary")
        if not mms_summary.is_file():
            errors.append("missing mms feature summary")
        else:
            mms_data = json.loads(mms_summary.read_text())
            if mms_data.get("mms_write_count", 0) < 1:
                errors.append("mms_write_count expected >= 1")

        if errors:
            print("61850 self-test FAILED:")
            for err in errors:
                print(f"  - {err}")
            print("events:", json.dumps(events, indent=2))
            return 1

        print("61850 self-test OK")
        print("events:", ", ".join(sorted(rule_ids)))
        print("goose_summary:", goose_summary.read_text()[:200])
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
