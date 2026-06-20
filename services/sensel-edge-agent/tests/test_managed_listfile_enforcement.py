"""Managed whitelist enforcement before detection / northbound (G6)."""

from __future__ import annotations

import json
from pathlib import Path

from src.policy.managed_listfile_enforcement import ManagedListfileEnforcer

CACHE = {
    "schema_version": "ot_managed_listfile.v1",
    "tenant_id": "tenant-a",
    "allow": {
        "ip": ["10.0.0.5"],
        "cidr": ["192.168.10.0/24"],
        "domain": ["trusted.example"],
        "hash": ["abc123"],
    },
    "deny": {"ip": ["203.0.113.10"]},
}


def _write_cache(tmp_path: Path) -> tuple[Path, Path]:
    cache_path = tmp_path / "managed-listfiles.json"
    stamp_path = tmp_path / "managed-listfiles.stamp"
    cache_path.write_text(json.dumps(CACHE), encoding="utf-8")
    stamp_path.write_text("2026-06-20T00:00:00Z\n", encoding="utf-8")
    return cache_path, stamp_path


def test_enforcer_loads_allow_buckets(tmp_path: Path) -> None:
    cache_path, stamp_path = _write_cache(tmp_path)
    enf = ManagedListfileEnforcer(cache_path, stamp_path, reload_check_sec=0)
    enf.maybe_reload(force=True)
    assert enf.is_ip_whitelisted("10.0.0.5")
    assert enf.is_ip_whitelisted("192.168.10.88")
    assert not enf.is_ip_whitelisted("203.0.113.99")
    assert enf.is_domain_whitelisted("trusted.example")
    assert enf.is_hash_whitelisted("abc123")


def test_is_event_whitelisted_matches_src_dst_and_evidence(tmp_path: Path) -> None:
    cache_path, stamp_path = _write_cache(tmp_path)
    enf = ManagedListfileEnforcer(cache_path, stamp_path, reload_check_sec=0)
    enf.maybe_reload(force=True)
    assert enf.is_event_whitelisted({"src_ip": "10.0.0.5", "rule_id": "OT-019"})
    assert enf.is_event_whitelisted(
        {
            "dst_ip": "192.168.10.50",
            "evidence": {"ioc_type": "ipv4", "ioc_value": "203.0.113.55"},
        }
    )
    assert not enf.is_event_whitelisted(
        {"src_ip": "203.0.113.99", "evidence": {"ioc_type": "ipv4", "ioc_value": "203.0.113.99"}}
    )
