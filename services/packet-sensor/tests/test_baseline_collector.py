"""Unit tests for the baseline learning collector."""

from __future__ import annotations

import sys
from pathlib import Path

from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether
from scapy.packet import Raw

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.baseline.collector import BaselineCollector
from src.parser.l7.iec61850.goose import build_goose_wire


def _goose_pkt(src_mac: str, appid: int, gocb: str, st_num: int, test: bool = False):
    wire = build_goose_wire(appid, gocb, "IED1/LLN0$GO$gcb", st_num, 0, test=test, conf_rev=1)
    return Ether(src=src_mac, dst="01:0c:cd:01:00:01", type=0x88B8) / Raw(load=wire)


def _modbus_pkt(src_ip: str, dst_ip: str, unit: int, func: int):
    adu = bytes([0x00, 0x01, 0x00, 0x00, 0x00, 0x06, unit, func, 0x00, 0x00, 0x00, 0x0A])
    return Ether() / IP(src=src_ip, dst=dst_ip) / TCP(sport=40000, dport=502) / Raw(load=adu)


def _mms_pkt(src_ip: str, dst_ip: str, dport: int = 102):
    payload = b"\x03\x00\x00\x16\x02\xf0\x80confirmedRequest read"
    return Ether() / IP(src=src_ip, dst=dst_ip) / TCP(sport=50000, dport=dport) / Raw(load=payload)


def test_collector_learns_goose_publishers():
    c = BaselineCollector()
    for sn in range(5):
        c.observe(_goose_pkt("00:11:22:33:44:55", 1000, "IED1/LLN0.gcbEvents", sn))
    pubs = c.goose_publishers()
    assert len(pubs) == 1
    p = pubs[0]
    assert p["publisher_mac"] == "00:11:22:33:44:55"
    assert p["appid"] == 1000
    assert p["gocb_ref"] == "IED1/LLN0.gcbEvents"
    assert p["production"] is True
    assert p["observed_frames"] == 5


def test_collector_learns_mms_ied_clients():
    c = BaselineCollector()
    c.observe(_mms_pkt("192.168.10.10", "192.168.10.50"))
    c.observe(_mms_pkt("192.168.10.11", "192.168.10.50"))
    ieds = c.mms_ieds()
    assert len(ieds) == 1
    assert ieds[0]["ied_ip"] == "192.168.10.50"
    assert ieds[0]["allowed_mms_clients"] == ["192.168.10.10", "192.168.10.11"]


def test_collector_learns_modbus_servers():
    c = BaselineCollector()
    c.observe(_modbus_pkt("192.168.10.10", "192.168.10.20", unit=1, func=3))
    c.observe(_modbus_pkt("192.168.10.10", "192.168.10.20", unit=1, func=6))
    servers = c.modbus_servers()
    assert len(servers) == 1
    assert servers[0]["server_ip"] == "192.168.10.20"
    assert servers[0]["unit_ids"] == [1]
    assert set(servers[0]["function_codes"]) == {3, 6}


def test_feed_path_counts_packets_via_note_packet():
    c = BaselineCollector()
    c.note_packet()
    c.feed_endpoints("00:11:22:33:44:55", "192.168.10.10", "192.168.10.20")
    c.note_packet()
    c.feed_endpoints("00:11:22:33:44:55", "192.168.10.10", "192.168.10.21")
    assert c.summary()["packets"] == 2
    assert c.summary()["unique_ips"] == 3
    assert c.summary()["comm_pairs"] == 2


def test_candidate_schema_matches_detector_shape():
    c = BaselineCollector()
    c.observe(_goose_pkt("00:11:22:33:44:55", 1000, "IED1/LLN0.gcbEvents", 1))
    c.observe(_mms_pkt("192.168.10.10", "192.168.10.50"))
    cand = c.to_candidate(source="pcap_import", source_ref="lab.pcap")
    assert cand["schema"] == "sensel.baseline/1"
    assert cand["source_ref"] == "lab.pcap"
    iec = cand["observed"]["iec61850"]
    assert "goose_publishers" in iec and "mms_ieds" in iec
    assert cand["stats"]["goose_publishers"] == 1
    assert cand["stats"]["mms_ieds"] == 1
    assert cand["stats"]["packets"] == 2


def test_test_only_goose_marked_non_production():
    c = BaselineCollector()
    c.observe(_goose_pkt("aa:bb:cc:dd:ee:ff", 2000, "IED2/LLN0.gcbTest", 1, test=True))
    pubs = c.goose_publishers()
    assert pubs[0]["production"] is False


def test_rolling_window_ages_out_stale_publishers():
    import time

    c = BaselineCollector()
    c.observe(_goose_pkt("00:11:22:33:44:55", 1000, "g1", 1))
    c.observe(_goose_pkt("aa:bb:cc:dd:ee:ff", 2000, "g2", 1))
    # Age the first publisher far into the past.
    stale_key = next(k for k, o in c._goose.items() if o.appid == 1000)
    c._goose[stale_key].last_seen = time.monotonic() - 10_000

    # With a tight window only the fresh publisher remains...
    windowed = c.to_candidate(window_sec=60)
    assert windowed["stats"]["goose_publishers"] == 1
    assert windowed["observed"]["iec61850"]["goose_publishers"][0]["appid"] == 2000
    # ...but the unwindowed (pcap) path keeps everything.
    full = c.to_candidate()
    assert full["stats"]["goose_publishers"] == 2


def test_rolling_window_ages_out_stale_mms_clients():
    import time

    c = BaselineCollector()
    c.observe(_mms_pkt("192.168.10.10", "192.168.10.50"))
    c.observe(_mms_pkt("192.168.10.11", "192.168.10.50"))
    rec = c._mms["192.168.10.50"]
    rec.clients["192.168.10.10"] = time.monotonic() - 10_000  # stale client
    ieds = c.mms_ieds(cutoff=time.monotonic() - 60)
    assert ieds[0]["allowed_mms_clients"] == ["192.168.10.11"]
