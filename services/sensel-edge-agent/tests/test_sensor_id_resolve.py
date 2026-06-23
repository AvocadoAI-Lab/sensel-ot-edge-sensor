"""Tests for hostname-based sensor_id resolution."""

import src.config.sensor_id_resolve as sid


def _reset_cache() -> None:
    sid.get_hostname.cache_clear()


def test_sensor_id_from_hostname_prefixes_unknown_host(monkeypatch) -> None:
    monkeypatch.setattr(sid, "get_hostname", lambda: "castle-lab-edge-10")
    assert sid.sensor_id_from_hostname() == "ot-edge-castle-lab-edge-10"


def test_sensor_id_from_hostname_keeps_existing_prefix(monkeypatch) -> None:
    monkeypatch.setattr(sid, "get_hostname", lambda: "ot-edge-010")
    assert sid.sensor_id_from_hostname() == "ot-edge-010"


def test_resolve_prefers_explicit_env(monkeypatch) -> None:
    monkeypatch.setattr(sid, "get_hostname", lambda: "host-a")
    assert sid.resolve_sensor_id(env_id="ot-edge-custom") == "ot-edge-custom"


def test_resolve_skips_placeholder_yaml_uses_hostname(monkeypatch) -> None:
    monkeypatch.setattr(sid, "get_hostname", lambda: "lab-edge-2")
    assert sid.resolve_sensor_id(yaml_id="ot-edge-001") == "ot-edge-lab-edge-2"


def test_resolve_platform_beats_yaml(monkeypatch) -> None:
    monkeypatch.setattr(sid, "get_hostname", lambda: "ignored")
    assert sid.resolve_sensor_id(yaml_id="ot-edge-001", platform_id="ot-edge-010") == "ot-edge-010"


def test_resolve_with_source(monkeypatch) -> None:
    monkeypatch.setattr(sid, "get_hostname", lambda: "pi4-lab")
    sensor_id, source = sid.resolve_sensor_id_with_source(yaml_id="ot-edge-001")
    assert sensor_id == "ot-edge-pi4-lab"
    assert source == "hostname"


def test_fallback_unknown_when_hostname_empty(monkeypatch) -> None:
    monkeypatch.setattr(sid, "get_hostname", lambda: "")
    assert sid.sensor_id_from_hostname() == "ot-edge-unknown"


def test_sanitize_hostname_dots(monkeypatch) -> None:
    monkeypatch.setattr(sid, "get_hostname", lambda: "edge.lab")
    assert sid.sensor_id_from_hostname() == "ot-edge-edge-lab"
