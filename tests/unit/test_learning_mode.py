"""Commissioning (learning) mode: observe + persist, raise no alerts."""

from __future__ import annotations

from pathlib import Path

from service_loader import import_from_service

ROOT = Path(__file__).resolve().parents[2]
POLICY = ROOT / "config/policy/baseline.example.json"


def _deps():
    from scapy.all import Ether, IP, TCP

    processor = import_from_service("packet-sensor", "src.pipeline.processor")
    return Ether, IP, TCP, processor.PacketPipeline


def _pipeline(PacketPipeline, assets_dir: Path, state_db: Path, mode: str):
    return PacketPipeline(
        sensor_id="s", site_id="factory-lab-001", policy_path=str(POLICY),
        assets_dir=str(assets_dir), rules_enabled=["OT-001", "OT-002"],
        state_db=str(state_db), mode=mode,
    )


def _mac_pkt(Ether, IP, TCP, mac, ip):
    return Ether(src=mac) / IP(src=ip, dst="192.168.10.20") / TCP(dport=502)


def test_learning_suppresses_alerts_but_persists_then_monitoring_uses_it(tmp_path: Path) -> None:
    Ether, IP, TCP, PacketPipeline = _deps()
    db = tmp_path / "state.db"

    # Learning: observe host A, raise nothing.
    learn = _pipeline(PacketPipeline, tmp_path / "learn", db, "learning")
    learn.process(_mac_pkt(Ether, IP, TCP, "02:aa:aa:aa:aa:aa", "192.168.10.91"))
    assert learn.event_store.read_recent() == []   # no alerts during commissioning
    learn.close()                                   # persists what it learned

    # Monitoring: host A was learned -> no alert; a NEW host B -> alert.
    mon = _pipeline(PacketPipeline, tmp_path / "mon", db, "monitoring")
    mon.process(_mac_pkt(Ether, IP, TCP, "02:aa:aa:aa:aa:aa", "192.168.10.91"))
    assert {e["rule_id"] for e in mon.event_store.read_recent()} == set()  # learned, silent
    mon.process(_mac_pkt(Ether, IP, TCP, "02:bb:bb:bb:bb:bb", "192.168.10.92"))
    rules = {e["rule_id"] for e in mon.event_store.read_recent()}
    assert "OT-001" in rules and "OT-002" in rules  # genuinely new -> alert
    mon.close()
