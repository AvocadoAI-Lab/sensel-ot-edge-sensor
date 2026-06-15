"""Unit tests for IT protocol hints and Purdue classifier (PRD §5.6)."""

from __future__ import annotations

import sys
from pathlib import Path

from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.baseline.collector import BaselineCollector
from src.topology.protocol_hints import hint_for_port
from src.topology.purdue_classifier import build_observed_topology


def _tcp(src_ip: str, dst_ip: str, sport: int, dport: int):
    return Ether() / IP(src=src_ip, dst=dst_ip) / TCP(sport=sport, dport=dport)


def test_hint_for_port_it_services():
    assert hint_for_port(445) == "smb"
    assert hint_for_port(389) == "ldap"
    assert hint_for_port(53) == "dns"
    assert hint_for_port(502) is None


def test_collector_records_smb_and_ldap_hints():
    c = BaselineCollector(tenant_id="tenant-a", sensor_id="sensor-1")
    c.observe(_tcp("192.168.1.20", "192.168.1.108", 49152, 445))
    c.observe(_tcp("192.168.1.20", "192.168.1.109", 49153, 389))
    c.observe(_tcp("192.168.1.21", "192.168.1.109", 49154, 389))
    hints = c.port_hint_index()
    assert "smb" in hints["192.168.1.108"]["hints"]
    assert hints["192.168.1.109"]["ldap_clients"] == 2
    assert hints["192.168.1.109"]["ldap_server"] is True


def test_build_topology_windows_hmi_from_smb():
    observed = {
        "modbus_servers": [
            {"server_ip": "192.168.1.10", "allowed_clients": ["192.168.1.20"]}
        ],
        "comm_pairs": [],
    }
    port_hints = {
        "192.168.1.20": {"hints": ["smb", "rdp"], "ldap_clients": 0, "dns_clients": 0},
    }
    topo = build_observed_topology(
        observed,
        tenant_id="tenant-a",
        sensor_id="sensor-1",
        port_hints=port_hints,
    )
    hmi = next(a for a in topo["assets"] if a["ip"] == "192.168.1.20")
    assert hmi["asset_type"] == "hmi"
    assert hmi["purdue_level"] == "L2"
    assert hmi["os_family"] == "windows"
    assert "it_protocol_fingerprint" in hmi["evidence_sources"]
    assert topo["assets"]


def test_build_topology_it_conduits_and_external():
    observed = {
        "modbus_servers": [
            {"server_ip": "192.168.1.10", "allowed_clients": ["192.168.1.20"]}
        ],
        "comm_pairs": [
            {"src": "192.168.1.20", "dst": "8.8.8.8"},
        ],
    }
    port_hints = {
        "192.168.1.20": {
            "hints": ["dns"],
            "ldap_clients": 0,
            "dns_clients": 0,
            "ldap_client_ips": [],
            "dns_client_ips": [],
        },
        "192.168.1.109": {
            "hints": ["ldap"],
            "ldap_clients": 2,
            "dns_clients": 1,
            "ldap_client_ips": ["192.168.1.20", "192.168.1.21"],
            "dns_client_ips": ["192.168.1.20"],
            "ldap_server": True,
            "dns_server": True,
        },
    }
    topo = build_observed_topology(
        observed,
        tenant_id="tenant-a",
        sensor_id="sensor-1",
        port_hints=port_hints,
    )
    l4 = [a for a in topo["assets"] if a.get("purdue_level") == "L4"]
    assert len(l4) >= 1
    it_edges = [c for c in topo["conduits"] if c.get("dst_level") == "L4"]
    assert len(it_edges) >= 1
    assert len(topo.get("external_entities") or []) == 1
    assert topo["external_entities"][0]["ip"] == "8.8.8.8"


def _modbus_pkt(src_ip: str, dst_ip: str, unit: int = 1, func: int = 3):
    adu = bytes([0x00, 0x01, 0x00, 0x00, 0x00, 0x06, unit, func, 0x00, 0x00, 0x00, 0x0A])
    return Ether() / IP(src=src_ip, dst=dst_ip) / TCP(sport=40000, dport=502) / __import__("scapy.packet", fromlist=["Raw"]).Raw(load=adu)


def test_to_candidate_includes_observed_topology():
    c = BaselineCollector(tenant_id="tenant-a", sensor_id="sensor-1")
    c.observe(_modbus_pkt("192.168.1.20", "192.168.1.10"))
    cand = c.to_candidate()
    topo = cand["observed"].get("topology")
    assert isinstance(topo, dict)
    assert topo.get("schema") == "sensel.ot_topology.snapshot.v1"
    assert len(topo.get("assets") or []) >= 1
