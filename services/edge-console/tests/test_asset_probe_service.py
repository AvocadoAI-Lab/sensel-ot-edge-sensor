"""Tests for asset identity overrides + probe gating."""

from __future__ import annotations

import importlib
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


def _reload(monkeypatch, tmp_path, *, probe="false"):
    monkeypatch.setenv("DETECTION_POLICY_PATH", str(tmp_path / "agent" / "detection-policy.json"))
    monkeypatch.setenv("ASSETS_DIR", str(tmp_path / "assets"))
    monkeypatch.setenv("EDGE_CONSOLE_ACTIVE_PROBE", probe)
    import src.asset_probe_service as svc
    return importlib.reload(svc)


def test_manual_override_roundtrip(monkeypatch, tmp_path):
    svc = _reload(monkeypatch, tmp_path)
    r = svc.set_identity("192.168.10.10", vendor="ABB", model="REF615", firmware="5.0")
    assert r["ok"] is True
    inv = svc.get_inventory()
    entry = inv["entries"]["192.168.10.10"]
    assert entry["manual"] == {"vendor": "ABB", "model": "REF615", "firmware": "5.0"}
    assert inv["active_probe_enabled"] is False


def test_invalid_ip_rejected(monkeypatch, tmp_path):
    svc = _reload(monkeypatch, tmp_path)
    r = svc.set_identity("not-an-ip", vendor="X", model=None, firmware=None)
    assert r["ok"] is False and r["status"] == 400


def test_probe_blocked_when_disabled(monkeypatch, tmp_path):
    svc = _reload(monkeypatch, tmp_path, probe="false")
    r = svc.probe("192.168.10.10")
    assert r["ok"] is False and r["status"] == 403


def test_probe_enabled_flag(monkeypatch, tmp_path):
    svc = _reload(monkeypatch, tmp_path, probe="true")
    assert svc.active_probe_enabled() is True
