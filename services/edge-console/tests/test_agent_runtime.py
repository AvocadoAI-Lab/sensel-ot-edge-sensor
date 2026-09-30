"""Tests for agent runtime northbound status."""

from __future__ import annotations

from src.agent_runtime import northbound_mqtt_ok


def test_northbound_ok_when_connected_and_fresh() -> None:
    ok, detail = northbound_mqtt_ok(
        True,
        "192.168.1.203",
        1883,
        {
            "mqtt_connected": True,
            "tenant_id": "company-abc",
            "updated_at": "2099-01-01T00:00:00+00:00",
            "last_mqtt_publish_at": "2099-01-01T00:00:01+00:00",
        },
    )
    assert ok is True
    assert "company-abc" in detail


def test_northbound_fail_when_disconnected() -> None:
    ok, _detail = northbound_mqtt_ok(
        True,
        "192.168.1.203",
        1883,
        {"mqtt_connected": False, "tenant_id": "company-abc"},
    )
    assert ok is False
