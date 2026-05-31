#!/usr/bin/env python3
"""Lab GOOSE publisher — sends IEC 61850 GOOSE frames via Scapy."""

from __future__ import annotations

import os
import time

from scapy.all import Ether, Raw, sendp
from scapy.layers.l2 import Ether as EtherLayer

from src.parser.l7.iec61850.goose import GOOSE_ETHERTYPE, build_goose_wire

GOOSE_DST = os.environ.get("GOOSE_DST_MAC", "01:0c:cd:01:00:01")
GOOSE_SRC = os.environ.get("GOOSE_SRC_MAC", "00:11:22:33:44:55")
GOOSE_APPID = int(os.environ.get("GOOSE_APPID", "1000"))
GOOSE_GOCB = os.environ.get("GOOSE_GOCB_REF", "simpleIOGenericIO/LLN0.gcbEvents")
GOOSE_GO_ID = os.environ.get("GOOSE_GO_ID", "labEvents")
GOOSE_IFACE = os.environ.get("GOOSE_INTERFACE", "eth0")
GOOSE_INTERVAL = float(os.environ.get("GOOSE_INTERVAL_SEC", "1"))
GOOSE_TEST = os.environ.get("GOOSE_TEST", "false").lower() in ("1", "true", "yes")


def main() -> None:
    st_num = 1
    sq_num = 1
    while True:
        payload = build_goose_wire(
            GOOSE_APPID,
            GOOSE_GOCB,
            GOOSE_GO_ID,
            st_num,
            sq_num,
            test=GOOSE_TEST,
        )
        frame = Ether(dst=GOOSE_DST, src=GOOSE_SRC, type=GOOSE_ETHERTYPE) / Raw(payload)
        sendp(frame, iface=GOOSE_IFACE, verbose=False)
        sq_num += 1
        if sq_num % 10 == 0:
            st_num += 1
        time.sleep(GOOSE_INTERVAL)


if __name__ == "__main__":
    main()
