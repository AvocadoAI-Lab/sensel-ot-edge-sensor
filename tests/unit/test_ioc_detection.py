"""IoC cache and OT-019 detection tests."""

from __future__ import annotations

import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PACKET_SRC = ROOT / "services" / "packet-sensor"


def _import_modules():
    for key in list(sys.modules):
        if key == "src" or key.startswith("src."):
            del sys.modules[key]
    sys.path[:] = [p for p in sys.path if p != str(PACKET_SRC)]
    sys.path.insert(0, str(PACKET_SRC))
    from scapy.all import IP, TCP

    from src.detection.ioc import IocMatcher
    from src.policy.ioc_cache import IocCacheStore

    return IP, TCP, IocMatcher, IocCacheStore


def _write_cache(tmp_path: Path, ips: list[str]) -> tuple[Path, Path]:
    cache_path = tmp_path / "ioc-cache.json"
    stamp_path = tmp_path / "ioc-cache.stamp"
    expires = (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()
    payload = {
        "schema_version": "1.0",
        "tenant_id": "sensel-platform",
        "artifact_version": "20260601-001",
        "updated_at": datetime.now(timezone.utc).isoformat(),
        "etag": "etag-test",
        "ipv4": {
            ip: {
                "item_id": f"item-{ip}",
                "confidence": 85,
                "expires_at": expires,
                "revoke": False,
            }
            for ip in ips
        },
        "domain": {},
        "hash": {},
        "item_count": len(ips),
    }
    cache_path.write_text(json.dumps(payload), encoding="utf-8")
    stamp_path.write_text(payload["updated_at"] + "\n", encoding="utf-8")
    return cache_path, stamp_path


def test_ioc_cache_store_loads_entries(tmp_path: Path) -> None:
    _, _, _, IocCacheStore = _import_modules()
    cache_path, stamp_path = _write_cache(tmp_path, ["203.0.113.99"])
    store = IocCacheStore(cache_path=cache_path, stamp_path=stamp_path, reload_check_sec=0)
    store.maybe_reload(force=True)
    entry = store.lookup_ipv4("203.0.113.99")
    assert entry is not None
    assert entry.item_id == "item-203.0.113.99"
    assert store.lookup_ipv4("198.51.100.1") is None


def test_ioc_matcher_emits_ot_019_event(tmp_path: Path) -> None:
    _, _, IocMatcher, IocCacheStore = _import_modules()
    cache_path, stamp_path = _write_cache(tmp_path, ["203.0.113.99"])
    store = IocCacheStore(cache_path=cache_path, stamp_path=stamp_path, reload_check_sec=0)
    matcher = IocMatcher(
        site_id="factory-lab-001",
        sensor_id="ot-edge-001",
        cache=store,
        policy={"global_allowlists": {"ip": []}},
        cooldown_sec=300,
    )
    events = matcher.evaluate(
        src_ip="203.0.113.99",
        dst_ip="192.168.10.50",
        dst_port=102,
        protocol="tcp",
    )
    assert len(events) == 1
    event = events[0]
    assert event.rule_id == "OT-019"
    assert event.event_type == "CTI_IOC_OBSERVED"
    assert event.evidence["ioc_value"] == "203.0.113.99"
    assert event.evidence["direction"] == "src"


def test_ioc_matcher_whitelist_suppresses_ot019(tmp_path: Path) -> None:
    _, _, IocMatcher, IocCacheStore = _import_modules()
    from src.policy.managed_listfile_enforcement import ManagedListfileEnforcer

    cache_path, stamp_path = _write_cache(tmp_path, ["203.0.113.99"])
    listfile_cache = tmp_path / "managed-listfiles.json"
    listfile_stamp = tmp_path / "managed-listfiles.stamp"
    listfile_cache.write_text(
        json.dumps(
            {
                "allow": {"ip": ["203.0.113.99"], "cidr": [], "domain": [], "hash": []},
                "deny": {"ip": [], "cidr": [], "domain": [], "hash": []},
            }
        ),
        encoding="utf-8",
    )
    listfile_stamp.write_text("stamp\n", encoding="utf-8")
    store = IocCacheStore(cache_path=cache_path, stamp_path=stamp_path, reload_check_sec=0)
    enforcer = ManagedListfileEnforcer(listfile_cache, listfile_stamp, reload_check_sec=0)
    enforcer.maybe_reload(force=True)
    matcher = IocMatcher(
        site_id="factory-lab-001",
        sensor_id="ot-edge-001",
        cache=store,
        policy={"global_allowlists": {"ip": []}},
        listfile_enforcer=enforcer,
        cooldown_sec=300,
    )
    events = matcher.evaluate(
        src_ip="203.0.113.99",
        dst_ip="192.168.10.50",
        dst_port=102,
        protocol="tcp",
    )
    assert events == []


def test_ioc_matcher_respects_cooldown(tmp_path: Path) -> None:
    _, _, IocMatcher, IocCacheStore = _import_modules()
    cache_path, stamp_path = _write_cache(tmp_path, ["203.0.113.99"])
    store = IocCacheStore(cache_path=cache_path, stamp_path=stamp_path, reload_check_sec=0)
    matcher = IocMatcher(
        site_id="site",
        sensor_id="sensor",
        cache=store,
        policy={},
        cooldown_sec=300,
    )
    first = matcher.evaluate(src_ip="203.0.113.99", dst_ip="10.0.0.1")
    second = matcher.evaluate(src_ip="203.0.113.99", dst_ip="10.0.0.1")
    assert len(first) == 1
    assert len(second) == 0


def test_pipeline_processes_ioc_packet(tmp_path: Path) -> None:
    IP, TCP, _, _ = _import_modules()
    from src.pipeline.processor import PacketPipeline

    cache_path, stamp_path = _write_cache(tmp_path, ["203.0.113.55"])
    policy = ROOT / "config/policy/baseline.example.json"
    pipeline = PacketPipeline(
        sensor_id="test-sensor",
        site_id="factory-lab-001",
        policy_path=str(policy),
        assets_dir=str(tmp_path / "assets"),
        ioc_enabled=True,
        ioc_cache_path=str(cache_path),
        ioc_stamp_path=str(stamp_path),
        ioc_reload_check_sec=0,
    )
    packet = IP(src="203.0.113.55", dst="192.168.10.50") / TCP(sport=40000, dport=102)
    pipeline.process(packet)
    recent = pipeline.event_store.read_recent(limit=5)
    assert any(ev.get("rule_id") == "OT-019" for ev in recent)
