"""Operational mode service tests."""

from __future__ import annotations

import json
from pathlib import Path

from src.operational_mode_service import read_operational_mode


def test_read_operational_mode_idle_when_missing(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("OPERATIONAL_MODE_PATH", str(tmp_path / "missing.json"))
    monkeypatch.setenv("LEARNING_SESSION_PATH", str(tmp_path / "missing-session.json"))
    out = read_operational_mode()
    assert out["operational_mode"] == "idle"


def test_read_operational_mode_learning(tmp_path: Path, monkeypatch):
    mode_path = tmp_path / "operational-mode.json"
    session_path = tmp_path / "learning-session.json"
    monkeypatch.setenv("OPERATIONAL_MODE_PATH", str(mode_path))
    monkeypatch.setenv("LEARNING_SESSION_PATH", str(session_path))
    mode_path.write_text(
        json.dumps(
            {
                "mode": "learning",
                "session_id": "sess-1",
                "tenant_id": "tenant-a",
                "capture": {"interface": "eth0"},
            }
        ),
        encoding="utf-8",
    )
    session_path.write_text(
        json.dumps({"session_id": "sess-1", "status": "active", "session_kind": "learn"}),
        encoding="utf-8",
    )
    out = read_operational_mode()
    assert out["operational_mode"] == "learning"
    assert out["session_id"] == "sess-1"
    assert out["session_kind"] == "learn"
    assert out["capture_interface"] == "eth0"
    assert out["cloud_controlled"] is True
