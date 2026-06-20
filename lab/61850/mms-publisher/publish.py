#!/usr/bin/env python3
"""Lab MMS traffic publisher — sends IEC 61850-style TCP/102 probes via Scapy (ARM-safe)."""

from __future__ import annotations

import os
import time

from scapy.all import Ether, IP, Raw, TCP, get_if_hwaddr, sendp

from src.parser.l7.iec61850.mms import build_mms_write_probe

MMS_IFACE = os.environ.get("MMS_INTERFACE", "eth0")
MMS_SRC_IP = os.environ.get("MMS_SRC_IP", "192.168.10.88")
MMS_DST_IP = os.environ.get("MMS_DST_IP", "192.168.10.50")
MMS_SRC_MAC = os.environ.get("MMS_SRC_MAC", "")
MMS_DST_MAC = os.environ.get("MMS_DST_MAC", "00:11:22:33:44:66")
MMS_INTERVAL = float(os.environ.get("MMS_INTERVAL_SEC", "2"))
MMS_SPORT_BASE = int(os.environ.get("MMS_SPORT_BASE", "45000"))


def main() -> None:
    src_mac = MMS_SRC_MAC or get_if_hwaddr(MMS_IFACE)
    payload = build_mms_write_probe()
    seq = 0
    while True:
        sport = MMS_SPORT_BASE + (seq % 1000)
        frame = (
            Ether(dst=MMS_DST_MAC, src=src_mac)
            / IP(src=MMS_SRC_IP, dst=MMS_DST_IP)
            / TCP(sport=sport, dport=102, flags="PA")
            / Raw(payload)
        )
        sendp(frame, iface=MMS_IFACE, verbose=False)
        seq += 1
        time.sleep(MMS_INTERVAL)


if __name__ == "__main__":
    main()
