"""Tests for Edge Console hostname-based sensor_id defaults."""

from pathlib import Path

from src.config_store import ConfigStore, PlatformConfig


def test_load_without_platform_json_uses_hostname(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(
        "src.config_store.resolve_sensor_id_with_source",
        lambda **kwargs: ("ot-edge-lab-edge-10", "hostname"),
    )
    store = ConfigStore(tmp_path / "missing.json")
    cfg = store.load()
    assert cfg.sensor_id == "ot-edge-lab-edge-10"


def test_load_upgrades_unregistered_placeholder(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(
        "src.config_store.resolve_sensor_id_with_source",
        lambda **kwargs: ("ot-edge-lab-edge-11", "hostname"),
    )
    path = tmp_path / "platform.json"
    path.write_text('{"sensor_id":"ot-edge-001","configured":false}', encoding="utf-8")
    cfg = ConfigStore(path).load()
    assert cfg.sensor_id == "ot-edge-lab-edge-11"


def test_load_keeps_registered_placeholder(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(
        "src.config_store.resolve_sensor_id_with_source",
        lambda **kwargs: ("ot-edge-new-host", "hostname"),
    )
    path = tmp_path / "platform.json"
    path.write_text(
        '{"sensor_id":"ot-edge-001","configured":true,"last_register_ok":true}',
        encoding="utf-8",
    )
    cfg = ConfigStore(path).load()
    assert cfg.sensor_id == "ot-edge-001"


def test_sync_env_writes_sensor_id(tmp_path: Path) -> None:
    path = tmp_path / "platform.json"
    store = ConfigStore(path)
    cfg = PlatformConfig(configured=True, sensor_id="ot-edge-host-a")
    store.save(cfg)
    store.sync_env_file(cfg)
    capture_env = path.parent / "capture.env"
    assert "SENSOR_ID=ot-edge-host-a" in capture_env.read_text(encoding="utf-8")


def test_public_view_includes_hostname_hint(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr("src.config_store.get_hostname", lambda: "edge-box")
    monkeypatch.setattr("src.config_store.sensor_id_from_hostname", lambda: "ot-edge-edge-box")
    monkeypatch.setattr(
        "src.config_store.resolve_sensor_id_with_source",
        lambda **kwargs: ("ot-edge-edge-box", "hostname"),
    )
    store = ConfigStore(tmp_path / "platform.json")
    cfg = store.load()
    public = store.public_view(cfg)
    assert public["hostname"] == "edge-box"
    assert public["sensor_id_suggested"] == "ot-edge-edge-box"
    assert public["sensor_id_source"] == "hostname"
