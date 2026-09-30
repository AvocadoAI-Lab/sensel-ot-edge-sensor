"""Lab traffic control service tests."""

from __future__ import annotations

from pathlib import Path

import pytest

from src import lab_traffic_service as lab


def test_resolve_preset_lab_only():
    _, start, stop = lab._resolve_preset("lab_only")
    assert start == ["goose", "mms"]
    assert stop == ["capture"]


def test_resolve_preset_mirror_only():
    _, start, stop = lab._resolve_preset("mirror_only")
    assert stop == ["goose", "mms"]
    assert start == ["capture"]


def test_resolve_preset_unknown():
    with pytest.raises(ValueError, match="Unknown preset"):
        lab._resolve_preset("nope")


def test_build_status_disabled(monkeypatch):
    monkeypatch.setattr(lab, "_env_enabled", lambda: False)
    monkeypatch.setattr(lab, "_container_exists", lambda _c: False)
    monkeypatch.setattr(lab, "read_live_traffic", lambda _s=None: {"live": False, "metrics": {}})
    out = lab.build_lab_traffic_status()
    assert out["enabled"] is False
    assert out["mode"] == "production"


def test_build_status_enabled(monkeypatch):
    monkeypatch.setattr(lab, "_env_enabled", lambda: True)
    monkeypatch.setattr(lab, "_docker_status", lambda _c: {"status": "running", "running": True})
    monkeypatch.setattr(
        lab,
        "read_live_traffic",
        lambda _s=None: {
            "live": True,
            "capture_interface": "eth0",
            "capture_bpf": "tcp port 102",
            "age_sec": 1.0,
            "metrics": {"instant_rate": 2.5},
        },
    )
    monkeypatch.setattr(lab, "docker_control_enabled", lambda: True)
    monkeypatch.setattr(Path, "exists", lambda self: str(self) == "/var/run/docker.sock")
    out = lab.build_lab_traffic_status()
    assert out["enabled"] is True
    assert len(out["publishers"]) == 2
    assert out["capture"]["running"] is True


def test_apply_preset_all_off(monkeypatch):
    monkeypatch.setattr(lab, "docker_control_enabled", lambda: True)
    monkeypatch.setattr(Path, "exists", lambda self: str(self) == "/var/run/docker.sock")
    calls: list[tuple[str, str]] = []

    def fake_stop(container: str) -> tuple[bool, str]:
        calls.append(("stop", container))
        return True, "stopped"

    monkeypatch.setattr(lab, "_docker_stop", fake_stop)
    monkeypatch.setattr(lab, "_docker_start", lambda _c: (True, "started"))
    out = lab.apply_lab_traffic_action(preset="all_off")
    assert out["ok"] is True
    assert len(calls) == 3


def test_apply_start_targets(monkeypatch):
    monkeypatch.setattr(lab, "docker_control_enabled", lambda: True)
    monkeypatch.setattr(Path, "exists", lambda self: str(self) == "/var/run/docker.sock")
    started: list[str] = []
    monkeypatch.setattr(lab, "_docker_start", lambda c: (started.append(c) or True, "started"))
    monkeypatch.setattr(lab, "_docker_stop", lambda _c: (True, "stopped"))
    out = lab.apply_lab_traffic_action(action="start", targets=["goose"])
    assert out["ok"] is True
    assert started == ["sensel-goose-publisher"]


def test_apply_docker_disabled():
    monkeypatch = pytest.MonkeyPatch()
    monkeypatch.setattr(lab, "docker_control_enabled", lambda: False)
    out = lab.apply_lab_traffic_action(action="stop", targets=["goose"])
    assert out["ok"] is False
    monkeypatch.undo()
