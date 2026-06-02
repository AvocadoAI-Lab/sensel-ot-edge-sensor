#!/usr/bin/env python3
"""Offline attack-coverage self-test.

Feeds crafted-but-real packets through the *actual* PacketPipeline and asserts
that every implemented detection rule fires. This is the deterministic backbone
behind `make verify-attacks` — it proves the detection logic responds to each
attack class without needing a live capture interface.

Implemented rules: OT-001 ~ OT-018 (full coverage).
"""

from __future__ import annotations

import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "services" / "packet-sensor"))

from scapy.all import ARP, Ether, IP, Raw, TCP  # noqa: E402

from src.parser.l7.iec61850.goose import GOOSE_ETHERTYPE, build_goose_wire  # noqa: E402
from src.parser.l7.iec61850.mms import build_mms_write_probe  # noqa: E402
from src.pipeline.processor import PacketPipeline  # noqa: E402

POLICY = ROOT / "config/policy/baseline.example.json"
RELAY = "192.168.10.20"      # baseline asset relay-01
IED = "192.168.10.50"        # baseline mms IED
ROGUE = "192.168.10.231"     # non-baselined attacker
ALL_RULES = [f"OT-{i:03d}" for i in range(1, 19)]
EXPECTED = set(ALL_RULES)  # OT-001 ~ OT-018, full coverage


def _modbus_write(fc: int = 16) -> bytes:
    return b"\x00\x01\x00\x00\x00\x06\x01" + bytes([fc]) + b"\x00\x01\x00\x02"


def _goose(src_mac, appid, gocb, go_id, st, sq, test=False):
    payload = build_goose_wire(appid, gocb, go_id, st, sq, test=test)
    return Ether(dst="01:0c:cd:01:00:01", src=src_mac, type=GOOSE_ETHERTYPE) / Raw(payload)


def _new_pipeline(tmp: str, window_sec: int = 1) -> PacketPipeline:
    return PacketPipeline(
        sensor_id="selftest",
        site_id="factory-lab-001",
        policy_path=str(POLICY),
        assets_dir=tmp,
        rules_enabled=ALL_RULES,
        feature_window_sec=window_sec,
    )


def _run_packet_attacks(p: PacketPipeline) -> None:
    # OT-001 New MAC / OT-002 New IP / OT-004 pair / OT-005 port / OT-010 relay
    p.process(
        Ether(src="02:aa:bb:cc:dd:ee")
        / IP(src=ROGUE, dst=RELAY)
        / TCP(sport=40001, dport=8080, flags="S")
    )

    # OT-003 ARP spoofing — same IP, two different MACs
    p.process(Ether(src="02:11:11:11:11:11") / ARP(op=2, hwsrc="02:11:11:11:11:11", psrc="192.168.10.77", pdst="192.168.10.77"))
    p.process(Ether(src="02:22:22:22:22:22") / ARP(op=2, hwsrc="02:22:22:22:22:22", psrc="192.168.10.77", pdst="192.168.10.77"))

    # OT-006 Port scan — >10 unique dst ports from one source
    for port in range(1000, 1016):
        p.process(IP(src=ROGUE, dst=RELAY) / TCP(sport=50000 + port, dport=port, flags="S"))

    # OT-007 Modbus write from non-baselined host (+OT-010)
    p.process(
        Ether(src="02:aa:bb:cc:dd:ee")
        / IP(src=ROGUE, dst=RELAY)
        / TCP(sport=40002, dport=502, flags="PA")
        / Raw(_modbus_write(16))
    )

    # OT-011 Rogue GOOSE publisher (mac/appid not in baseline)
    p.process(_goose("02:de:ad:be:ef:11", 0x3FFF, "rogue/LLN0.gcbBad", "rogue", st=1, sq=1))

    # OT-012 GOOSE test bit on the baselined production publisher
    p.process(_goose("00:11:22:33:44:55", 1000, "simpleIOGenericIO/LLN0.gcbEvents", "labEvents", st=10, sq=1, test=True))

    # OT-013 GOOSE stNum rollback on an established publisher
    p.process(_goose("00:33:44:55:66:77", 2000, "prodIO/LLN0.gcb", "prod", st=50, sq=1))
    p.process(_goose("00:33:44:55:66:77", 2000, "prodIO/LLN0.gcb", "prod", st=2, sq=2))

    # OT-014 + OT-016 + OT-018 Rogue MMS client write to a baselined IED
    p.process(
        Ether(src="02:aa:bb:cc:dd:ee")
        / IP(src=ROGUE, dst=IED)
        / TCP(sport=45001, dport=102, flags="PA")
        / Raw(build_mms_write_probe())
    )

    # OT-015 MMS session-rate — a burst of new client sessions to the IED
    for i in range(25):
        p.process(
            IP(src=f"10.9.0.{i}", dst=IED)
            / TCP(sport=46000 + i, dport=102, flags="PA")
            / Raw(build_mms_write_probe())
        )

    # OT-008 Abnormal traffic rate — flood the relay, then close the window
    for _ in range(40):
        p.process(IP(src=ROGUE, dst=RELAY) / TCP(sport=40003, dport=502, flags="A"))
    p.flush_features()


def _run_offline_absence(tmp: str) -> set[str]:
    """Absence-based rules: OT-009 (relay offline) and OT-017 (GOOSE silence).

    A fresh pipeline whose monotonic start is back-dated past the silence window
    fires RELAY_OFFLINE; a baselined GOOSE seen once then queried far in the
    future fires GOOSE_SILENCE.
    """
    p = _new_pipeline(tmp, window_sec=1)
    p._mvp._started_at = time.time() - 300.0  # noqa: SLF001 — test hook

    # Seed a baselined GOOSE publisher (ied-01) so OT-017 has a last-seen anchor.
    p.process(_goose("00:11:22:33:44:55", 1000, "simpleIOGenericIO/LLN0.gcbEvents", "labEvents", st=1, sq=1))

    fired = {e["rule_id"] for e in p.event_store.read_recent(limit=200)}
    p.flush_features()  # OT-009 fires (back-dated start, relay never seen)
    fired |= {e["rule_id"] for e in p.event_store.read_recent(limit=200)}
    # OT-017 — query the detector past the publisher's max_silence_sec.
    silence = p._detector.evaluate_goose_silence(now=time.time() + 600)  # noqa: SLF001
    fired |= {e.rule_id for e in silence}
    return fired


def main() -> int:
    fired: set[str] = set()
    with tempfile.TemporaryDirectory() as tmp:
        p = _new_pipeline(tmp)
        _run_packet_attacks(p)
        fired |= {e["rule_id"] for e in p.event_store.read_recent(limit=500)}
    with tempfile.TemporaryDirectory() as tmp2:
        fired |= _run_offline_absence(tmp2)

    print("attacks self-test — rule coverage")
    for rule in ALL_RULES:
        mark = "PASS" if rule in fired else "FAIL"
        print(f"  {rule}: {mark}")
    missing = EXPECTED - fired
    if missing:
        print(f"\nERROR: expected rules did not fire: {sorted(missing)}", file=sys.stderr)
        return 1
    print(f"\nOK — all {len(EXPECTED)} implemented rules fired")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
