"""Live traffic reader for Edge Console."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from src.config_store import ConfigStore
from src.traffic_service import read_live_traffic


def test_read_live_traffic_missing_file(tmp_path: Path, monkeypatch):
    assets = tmp_path / "assets"
    assets.mkdir()
    monkeypatch.setenv("ASSETS_DIR", str(assets))
    out = read_live_traffic()
    assert out["live"] is False
    assert "Packet Sensor" in out["message"]


def test_read_live_traffic_fresh_snapshot(tmp_path: Path, monkeypatch):
    assets = tmp_path / "assets"
    assets.mkdir()
    monkeypatch.setenv("ASSETS_DIR", str(assets))
    live_path = assets / "capture-live.json"
    live_path.write_text(
        json.dumps(
            {
                "updated_at": datetime.now(timezone.utc).isoformat(),
                "capture_interface": "eth0",
                "capture_backend": "scapy",
                "instant_rate": 12.5,
                "total_packets": 100,
                "recent_packets": [{"at": "12:00:01", "proto": "GOOSE", "size": 128}],
            }
        ),
        encoding="utf-8",
    )
    cfg_path = tmp_path / "platform.json"
    cfg_path.write_text(json.dumps({"configured": True}), encoding="utf-8")
    store = ConfigStore(cfg_path)
    out = read_live_traffic(store)
    assert out["live"] is True
    assert out["metrics"]["instant_rate"] == 12.5
    assert out["recent_packets"][0]["proto"] == "GOOSE"
