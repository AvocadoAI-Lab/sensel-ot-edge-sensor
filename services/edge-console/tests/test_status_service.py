"""Status service Sprint 4 metrics."""

from __future__ import annotations

import json
from pathlib import Path

from src.config_store import ConfigStore
from src.status_service import build_status, _rule_counts_24h


def test_rule_counts_24h(tmp_path: Path):
    events = tmp_path / "security-events.jsonl"
    events.write_text(
        json.dumps({"rule_id": "OT-016", "timestamp": "2099-01-01T00:00:00+00:00"}) + "\n"
        + json.dumps({"rule_id": "OT-016", "timestamp": "2099-01-01T01:00:00+00:00"}) + "\n",
        encoding="utf-8",
    )
    counts = _rule_counts_24h(events)
    assert counts.get("OT-016") == 2


def test_build_status_includes_baseline_card(tmp_path: Path, monkeypatch):
    cfg_path = tmp_path / "platform.json"
    cfg_path.write_text(json.dumps({"configured": True, "sensor_id": "ot-edge-001"}), encoding="utf-8")
    assets = tmp_path / "assets"
    assets.mkdir()
    (assets / "security-events.jsonl").write_text("", encoding="utf-8")
    monkeypatch.setenv("ASSETS_DIR", str(assets))
    store = ConfigStore(cfg_path)
    out = build_status(store)
    assert "baseline" in out["cards"]
    assert "rule_counts_24h" in out["metrics"]
