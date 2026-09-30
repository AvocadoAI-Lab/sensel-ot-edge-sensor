"""Operational mode artifact apply tests."""

from __future__ import annotations

import json
from pathlib import Path

from src.config.settings import AppConfig, LoggingConfig, PolicySyncConfig, SenselConfig, SensorIdentity
from src.policy.operational_mode_sync import OperationalModeSync


def _config(tmp_path: Path) -> AppConfig:
    return AppConfig(
        sensor=SensorIdentity(id="s1", site_id="factory-lab-001"),
        sensel=SenselConfig(api_url="http://127.0.0.1:8081", api_key="k"),
        policy_sync=PolicySyncConfig(
            operational_mode_enabled=True,
            operational_mode_path=str(tmp_path / "operational-mode.json"),
            operational_mode_stamp_path=str(tmp_path / "operational-mode.stamp"),
            learning_session_path=str(tmp_path / "learning-session.json"),
        ),
        logging=LoggingConfig(),
    )


def test_apply_operational_mode_writes_files(tmp_path: Path):
    sync = OperationalModeSync(_config(tmp_path))
    artifact = {
        "schema": "sensel.operational_mode.v1",
        "tenant_id": "tenant-a",
        "sensor_id": "s1",
        "mode": "learning",
        "session_id": "sess-1",
        "capture": {"interface": "eth0", "bpf_filter": ""},
    }
    out = sync.apply_artifact(artifact, tenant_id="tenant-a", source="mqtt")
    assert out.ok and out.changed
    data = json.loads((tmp_path / "operational-mode.json").read_text(encoding="utf-8"))
    assert data["mode"] == "learning"
    assert data["session_id"] == "sess-1"
    assert (tmp_path / "operational-mode.stamp").is_file()
    session = json.loads((tmp_path / "learning-session.json").read_text(encoding="utf-8"))
    assert session["session_id"] == "sess-1"
    assert session["session_kind"] == "learn"


def test_apply_operational_mode_idempotent(tmp_path: Path):
    sync = OperationalModeSync(_config(tmp_path))
    artifact = {
        "version": "v1",
        "tenant_id": "tenant-a",
        "sensor_id": "s1",
        "mode": "listen",
        "session_id": "sess-2",
    }
    sync.apply_artifact(artifact, tenant_id="tenant-a")
    out = sync.apply_artifact(artifact, tenant_id="tenant-a")
    assert out.ok and not out.changed


def test_abort_session_clears_learning_session(tmp_path: Path):
    sync = OperationalModeSync(_config(tmp_path))
    sync.apply_artifact(
        {
            "tenant_id": "tenant-a",
            "sensor_id": "s1",
            "mode": "learning",
            "session_id": "sess-abort",
        },
        tenant_id="tenant-a",
    )
    assert (tmp_path / "learning-session.json").is_file()
    sync.apply_artifact(
        {
            "tenant_id": "tenant-a",
            "sensor_id": "s1",
            "mode": "listen",
            "abort_session_id": "sess-abort",
        },
        tenant_id="tenant-a",
    )
    assert not (tmp_path / "learning-session.json").is_file()


def test_ensure_defaults_writes_listen(tmp_path: Path):
    sync = OperationalModeSync(_config(tmp_path))
    assert sync.ensure_defaults()
    data = json.loads((tmp_path / "operational-mode.json").read_text(encoding="utf-8"))
    assert data["mode"] == "listen"
