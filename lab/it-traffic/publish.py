#!/usr/bin/env python3
"""Lab IT traffic — DNS/LDAP probes for topology IT-dependencies (PRD §5.6 / §7.5)."""

from __future__ import annotations

import os
import time

from scapy.all import DNS, DNSQR, Ether, IP, Raw, TCP, UDP, get_if_hwaddr, sendp

IT_IFACE = os.environ.get("IT_INTERFACE", "eth0")
IT_SRC_IP = os.environ.get("IT_SRC_IP", "192.168.10.88")
IT_SRC_IP_2 = os.environ.get("IT_SRC_IP_2", "192.168.10.50")
IT_DNS_IP = os.environ.get("IT_DNS_IP", "192.168.10.10")
IT_LDAP_IP = os.environ.get("IT_LDAP_IP", "192.168.10.10")
IT_EXTERNAL_DNS_IP = os.environ.get("IT_EXTERNAL_DNS_IP", "8.8.8.8")
IT_INTERVAL = float(os.environ.get("IT_INTERVAL_SEC", "3"))
IT_SRC_MAC = os.environ.get("IT_SRC_MAC", "")
IT_DST_MAC = os.environ.get("IT_DST_MAC", "00:11:22:33:44:77")


def _dns_query(src_ip: str, dst_ip: str, qname: str, sport: int) -> None:
    frame = (
        Ether(dst=IT_DST_MAC, src=IT_SRC_MAC)
        / IP(src=src_ip, dst=dst_ip)
        / UDP(sport=sport, dport=53)
        / DNS(rd=1, qd=DNSQR(qname=qname))
    )
    sendp(frame, iface=IT_IFACE, verbose=False)


def _ldap_probe(src_ip: str, dst_ip: str, sport: int) -> None:
    # Minimal LDAP bindRequest prefix (BER) — enough for passive port-389 fingerprint.
    payload = bytes([0x30, 0x0c, 0x02, 0x01, 0x01, 0x60, 0x07, 0x02, 0x01, 0x03, 0x04, 0x00, 0x80, 0x00])
    frame = (
        Ether(dst=IT_DST_MAC, src=IT_SRC_MAC)
        / IP(src=src_ip, dst=dst_ip)
        / TCP(sport=sport, dport=389, flags="PA")
        / Raw(load=payload)
    )
    sendp(frame, iface=IT_IFACE, verbose=False)


def main() -> None:
    global IT_SRC_MAC
    IT_SRC_MAC = IT_SRC_MAC or get_if_hwaddr(IT_IFACE)
    seq = 0
    while True:
        sport = 52000 + (seq % 500)
        ldap_src = IT_SRC_IP if seq % 2 == 0 else IT_SRC_IP_2
        _dns_query(IT_SRC_IP, IT_DNS_IP, "lab.local.", sport)
        _ldap_probe(ldap_src, IT_LDAP_IP, sport + 1)
        if seq % 2 == 0:
            _dns_query(IT_SRC_IP, IT_EXTERNAL_DNS_IP, "google.com.", sport + 2)
        seq += 1
        time.sleep(IT_INTERVAL)


if __name__ == "__main__":
    main()
