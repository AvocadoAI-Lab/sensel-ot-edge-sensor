"""Policy gauge scoring tests."""

from __future__ import annotations

from src.config_store import PlatformConfig
from src.status_service import _policy_gauge


def test_policy_gauge_high_when_ready():
    cfg = PlatformConfig(
        configured=True,
        last_register_ok=True,
    )
    baseline = {"loaded": True, "assets": 5, "comm_pairs": 2}
    traffic = {"live": True, "metrics": {"ioc_entries": 10}}
    out = _policy_gauge(cfg, baseline, events_24h=2, traffic=traffic, mqtt_ok=True)
    assert out["percent"] >= 85


def test_policy_gauge_low_when_empty():
    cfg = PlatformConfig(configured=False)
    out = _policy_gauge(
        cfg,
        {"loaded": False},
        events_24h=0,
        traffic={"live": False, "metrics": {}},
        mqtt_ok=False,
    )
    assert out["percent"] < 50
