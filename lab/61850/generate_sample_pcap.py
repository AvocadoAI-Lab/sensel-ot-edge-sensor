#!/usr/bin/env python3
"""Generate sample GOOSE pcap for lab replay."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "services" / "packet-sensor"))

from scapy.all import Ether, Raw, wrpcap
from scapy.layers.l2 import Ether as EtherLayer

from src.parser.l7.iec61850.goose import GOOSE_ETHERTYPE, build_goose_wire

OUT = Path(__file__).resolve().parent / "pcap" / "goose_sample.pcap"


def main() -> None:
    frames = []
    for st, sq in ((1, 1), (1, 2), (2, 1)):
        payload = build_goose_wire(
            1000,
            "simpleIOGenericIO/LLN0.gcbEvents",
            "labEvents",
            st,
            sq,
        )
        frames.append(
            Ether(dst="01:0c:cd:01:00:01", src="00:22:33:44:55:66", type=GOOSE_ETHERTYPE)
            / Raw(payload)
        )
    OUT.parent.mkdir(parents=True, exist_ok=True)
    wrpcap(str(OUT), frames)
    print(f"Wrote {OUT} ({len(frames)} frames)")


if __name__ == "__main__":
    main()
