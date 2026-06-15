"""Operational mode hot-reload store tests."""

from __future__ import annotations

import json
from pathlib import Path

from src.policy.operational_mode_store import OperationalModeStore


def test_operational_mode_store_default_listen(tmp_path: Path):
    store = OperationalModeStore(
        mode_path=tmp_path / "operational-mode.json",
        stamp_path=tmp_path / "operational-mode.stamp",
        reload_check_sec=0,
    )
    assert store.mode == "listen"
    assert not store.alerts_enabled()
    assert not store.baseline_accumulation_enabled()


def test_operational_mode_store_reload(tmp_path: Path):
    mode_path = tmp_path / "operational-mode.json"
    stamp_path = tmp_path / "operational-mode.stamp"
    store = OperationalModeStore(
        mode_path=mode_path,
        stamp_path=stamp_path,
        reload_check_sec=0,
    )

    mode_path.write_text(json.dumps({"mode": "learning"}), encoding="utf-8")
    stamp_path.write_text("stamp-1\n", encoding="utf-8")
    store.maybe_reload(force=True)
    assert store.mode == "learning"
    assert store.baseline_accumulation_enabled()
    assert not store.alerts_enabled()

    mode_path.write_text(json.dumps({"mode": "detect"}), encoding="utf-8")
    stamp_path.write_text("stamp-2\n", encoding="utf-8")
    store.maybe_reload(force=True)
    assert store.mode == "detect"
    assert store.alerts_enabled()


def test_operational_mode_store_invalid_mode_fallback(tmp_path: Path):
    mode_path = tmp_path / "operational-mode.json"
    stamp_path = tmp_path / "operational-mode.stamp"
    store = OperationalModeStore(
        mode_path=mode_path,
        stamp_path=stamp_path,
        reload_check_sec=0,
    )
    mode_path.write_text(json.dumps({"mode": "bogus"}), encoding="utf-8")
    stamp_path.write_text("stamp-1\n", encoding="utf-8")
    store.maybe_reload(force=True)
    assert store.mode == "listen"
