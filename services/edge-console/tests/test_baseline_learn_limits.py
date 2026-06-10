"""Tests for baseline pcap learning limits + safe upload target."""

from __future__ import annotations

import importlib
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


def _reload(monkeypatch, tmp_path, **env):
    monkeypatch.setenv("DETECTION_POLICY_PATH", str(tmp_path / "agent" / "detection-policy.json"))
    monkeypatch.setenv("ASSETS_DIR", str(tmp_path / "assets"))
    for k, v in env.items():
        monkeypatch.setenv(k, v)
    import src.baseline_service as svc
    return importlib.reload(svc)


def test_max_pcap_bytes_default_and_override(monkeypatch, tmp_path):
    svc = _reload(monkeypatch, tmp_path)
    assert svc.max_pcap_bytes() == 100 * 1024 * 1024
    svc = _reload(monkeypatch, tmp_path, BASELINE_MAX_PCAP_MB="250")
    assert svc.max_pcap_bytes() == 250 * 1024 * 1024


def test_upload_target_sanitises_name(monkeypatch, tmp_path):
    svc = _reload(monkeypatch, tmp_path)
    host, fname = svc.upload_target("../../etc/passwd capture.pcapng")
    # Path separators and spaces are collapsed → no traversal possible.
    assert "/" not in fname and " " not in fname
    assert fname.endswith("etc_passwd_capture.pcapng")
    assert host.parent == svc._uploads_dir() and host.parent.is_dir()


def test_upload_target_forces_pcap_suffix(monkeypatch, tmp_path):
    svc = _reload(monkeypatch, tmp_path)
    _, fname = svc.upload_target("weird")
    assert fname.endswith(".pcap")


def test_run_learn_rejects_missing_file(monkeypatch, tmp_path):
    svc = _reload(monkeypatch, tmp_path)
    r = svc.run_learn("nope.pcap")
    assert r["ok"] is False and r["status"] == 400


def test_learn_from_pcap_rejects_oversize(monkeypatch, tmp_path):
    svc = _reload(monkeypatch, tmp_path, BASELINE_MAX_PCAP_MB="1")
    r = svc.learn_from_pcap(b"x" * (2 * 1024 * 1024), "big.pcap")
    assert r["ok"] is False and r["status"] == 413
