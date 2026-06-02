"""Learned-state persistence — survives restart, no novelty re-alert."""

from __future__ import annotations

from pathlib import Path

from service_loader import import_from_service

ROOT = Path(__file__).resolve().parents[2]
POLICY = ROOT / "config/policy/baseline.example.json"


def _deps():
    from scapy.all import ARP, Ether, IP, TCP

    processor, store = import_from_service(
        "packet-sensor", "src.pipeline.processor", "src.assets.store"
    )
    return ARP, Ether, IP, TCP, processor.PacketPipeline, store.StateStore


def _pipeline(PacketPipeline, assets_dir: Path, state_db: Path):
    return PacketPipeline(
        sensor_id="s", site_id="factory-lab-001", policy_path=str(POLICY),
        assets_dir=str(assets_dir), rules_enabled=["OT-001", "OT-002"],
        state_db=str(state_db),
    )


def test_restart_does_not_realert_known_mac(tmp_path: Path) -> None:
    ARP, Ether, IP, TCP, PacketPipeline, _ = _deps()
    db = tmp_path / "state.db"
    pkt = Ether(src="02:ab:cd:ef:00:01") / IP(src="192.168.10.99", dst="192.168.10.20") / TCP(dport=502)

    p1 = _pipeline(PacketPipeline, tmp_path / "a1", db)
    p1.process(pkt)
    rules1 = {e["rule_id"] for e in p1.event_store.read_recent()}
    assert "OT-001" in rules1 and "OT-002" in rules1
    p1.close()  # persists learned state

    # Restart: a fresh pipeline backed by the same state DB must NOT re-alert.
    p2 = _pipeline(PacketPipeline, tmp_path / "a2", db)
    p2.process(pkt)
    rules2 = {e["rule_id"] for e in p2.event_store.read_recent()}
    assert "OT-001" not in rules2
    assert "OT-002" not in rules2
    p2.close()


def test_store_roundtrip(tmp_path: Path) -> None:
    *_, StateStore = _deps()
    inv_mod, iec_mod = import_from_service(
        "packet-sensor", "src.assets.inventory", "src.detection.iec61850"
    )

    inv = inv_mod.AssetInventory()
    inv.known_macs.update({"aa:bb:cc:dd:ee:ff"})
    inv.known_ips.update({"10.0.0.5"})
    inv.mac_to_ip["aa:bb:cc:dd:ee:ff"] = "10.0.0.5"
    iec = iec_mod.Iec61850Detector(site_id="s", sensor_id="x", policy={})
    iec.known_goose.add("mac|1000|gcb")
    iec.known_mms_pairs.add("10.0.0.9->10.0.0.5:102")

    db = tmp_path / "s.db"
    store = StateStore(str(db))
    store.save(inv, iec)
    store.close()

    inv2 = inv_mod.AssetInventory()
    iec2 = iec_mod.Iec61850Detector(site_id="s", sensor_id="x", policy={})
    store2 = StateStore(str(db))
    store2.load(inv2, iec2)
    store2.close()

    assert inv2.known_macs == {"aa:bb:cc:dd:ee:ff"}
    assert inv2.mac_to_ip == {"aa:bb:cc:dd:ee:ff": "10.0.0.5"}
    assert iec2.known_goose == {"mac|1000|gcb"}
    assert iec2.known_mms_pairs == {"10.0.0.9->10.0.0.5:102"}
