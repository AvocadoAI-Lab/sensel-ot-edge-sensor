"""Unit tests for baseline drift computation (live vs active)."""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


def _setup(tmp_path, monkeypatch, active_iec, live_iec):
    agent = tmp_path / "agent"
    assets = tmp_path / "assets"
    (assets / "baseline").mkdir(parents=True)
    agent.mkdir(parents=True)
    monkeypatch.setenv("DETECTION_POLICY_PATH", str(agent / "detection-policy.json"))
    monkeypatch.setenv("ASSETS_DIR", str(assets))
    (agent / "detection-policy.json").write_text(
        json.dumps({"version": "v1", "baseline": {"iec61850": active_iec}}), encoding="utf-8"
    )
    (assets / "baseline" / "live-observed.json").write_text(
        json.dumps({"generated_at": "2026-06-10T00:00:00+00:00", "observed": {"iec61850": live_iec}}),
        encoding="utf-8",
    )
    import importlib
    import src.baseline_service as bs
    return importlib.reload(bs)


def test_drift_detects_new_goose_and_client(tmp_path, monkeypatch):
    active = {
        "goose_publishers": [{"publisher_mac": "00:11:22:33:44:55", "appid": 1000, "gocb_ref": "g1", "production": True}],
        "mms_ieds": [{"ied_ip": "10.0.0.50", "allowed_mms_clients": ["10.0.0.10"]}],
    }
    live = {
        "goose_publishers": [
            {"publisher_mac": "00:11:22:33:44:55", "appid": 1000, "gocb_ref": "g1", "production": True},
            {"publisher_mac": "aa:bb:cc:dd:ee:ff", "appid": 2000, "gocb_ref": "g2", "production": True},
        ],
        "mms_ieds": [{"ied_ip": "10.0.0.50", "allowed_mms_clients": ["10.0.0.10", "10.0.0.99"]}],
    }
    bs = _setup(tmp_path, monkeypatch, active, live)
    d = bs.compute_drift()
    assert d["has_active"] and d["has_live"]
    assert len(d["goose"]["added"]) == 1
    assert d["goose"]["added"][0]["appid"] == 2000
    assert len(d["mms"]["client_changes"]) == 1
    assert d["mms"]["client_changes"][0]["added_clients"] == ["10.0.0.99"]
    assert d["summary"]["total"] == 2


def test_no_drift_when_identical(tmp_path, monkeypatch):
    iec = {
        "goose_publishers": [{"publisher_mac": "00:11:22:33:44:55", "appid": 1000, "gocb_ref": "g1", "production": True}],
        "mms_ieds": [{"ied_ip": "10.0.0.50", "allowed_mms_clients": ["10.0.0.10"]}],
    }
    bs = _setup(tmp_path, monkeypatch, iec, json.loads(json.dumps(iec)))
    d = bs.compute_drift()
    assert d["summary"]["total"] == 0


def test_state_becomes_drift(tmp_path, monkeypatch):
    active = {"goose_publishers": [{"publisher_mac": "m", "appid": 1, "gocb_ref": "g", "production": True}], "mms_ieds": []}
    live = {
        "goose_publishers": [
            {"publisher_mac": "m", "appid": 1, "gocb_ref": "g", "production": True},
            {"publisher_mac": "x", "appid": 9, "gocb_ref": "z", "production": True},
        ],
        "mms_ieds": [],
    }
    bs = _setup(tmp_path, monkeypatch, active, live)
    state = bs.get_state()
    assert state["state"] == "drift"
    assert state["drift"]["summary"]["total"] == 1
