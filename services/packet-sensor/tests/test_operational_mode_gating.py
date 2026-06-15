"""Operational mode pipeline gating tests."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock

from src.pipeline.processor import PacketPipeline


def _write_mode(tmp_path: Path, mode: str) -> tuple[Path, Path]:
    mode_path = tmp_path / "operational-mode.json"
    stamp_path = tmp_path / "operational-mode.stamp"
    mode_path.write_text(json.dumps({"mode": mode, "schema": "sensel.operational_mode.v1"}), encoding="utf-8")
    stamp_path.write_text(f"stamp-{mode}\n", encoding="utf-8")
    return mode_path, stamp_path


def _pipeline(tmp_path: Path, mode: str) -> PacketPipeline:
    fallback = tmp_path / "baseline.json"
    fallback.write_text('{"iec61850": {"mms_ieds": []}}', encoding="utf-8")
    mode_path, stamp_path = _write_mode(tmp_path, mode)
    return PacketPipeline(
        sensor_id="s1",
        site_id="site-1",
        policy_path=str(fallback),
        assets_dir=str(tmp_path / "assets"),
        rules_enabled=["OT-016"],
        ioc_enabled=False,
        coverage_enabled=False,
        operational_mode_path=str(mode_path),
        operational_mode_stamp_path=str(stamp_path),
        operational_mode_reload_sec=0,
    )


def test_learning_mode_suppresses_events(tmp_path: Path):
    pipe = _pipeline(tmp_path, "learning")
    packet = MagicMock()
    pipe.process(packet)
    assert not pipe.event_store.path.is_file() or pipe.event_store.read_recent() == []


def test_detect_mode_allows_emit_path(tmp_path: Path):
    pipe = _pipeline(tmp_path, "detect")
    assert pipe._mode_store.alerts_enabled()
