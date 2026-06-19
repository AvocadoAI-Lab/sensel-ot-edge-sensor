"""Tests for runtime hardware/platform detection."""

from pathlib import Path

import src.config.platform_detect as pd


def _reset_cache() -> None:
    pd.detect_hardware.cache_clear()


def test_raspberry_pi4_bare_metal(monkeypatch, tmp_path: Path) -> None:
    model = tmp_path / "model"
    model.write_text("Raspberry Pi 4 Model B Rev 1.4\x00", encoding="utf-8")
    monkeypatch.setattr(pd.platform, "system", lambda: "Linux")
    monkeypatch.setattr(pd, "_read_text", lambda p: model.read_text() if p == "/proc/device-tree/model" else "")
    monkeypatch.setattr(pd, "_in_container", lambda: False)
    _reset_cache()
    assert pd.detect_hardware() == "pi4"


def test_ubuntu_bare_metal(monkeypatch) -> None:
    monkeypatch.setattr(pd.platform, "system", lambda: "Linux")
    monkeypatch.setattr(pd, "_raspberry_pi_model", lambda: None)
    monkeypatch.setattr(pd, "_os_release_id", lambda: "ubuntu")
    monkeypatch.setattr(pd, "_in_container", lambda: False)
    _reset_cache()
    assert pd.detect_hardware() == "ubuntu"


def test_ubuntu_linux_container(monkeypatch) -> None:
    monkeypatch.setattr(pd.platform, "system", lambda: "Linux")
    monkeypatch.setattr(pd, "_raspberry_pi_model", lambda: None)
    monkeypatch.setattr(pd, "_os_release_id", lambda: "ubuntu")
    monkeypatch.setattr(pd, "_in_container", lambda: True)
    monkeypatch.setattr(pd, "_windows_host_under_linux_container", lambda: False)
    _reset_cache()
    assert pd.detect_hardware() == "ubuntu-docker"


def test_windows_docker_container_via_wsl(monkeypatch) -> None:
    monkeypatch.setattr(pd.platform, "system", lambda: "Linux")
    monkeypatch.setattr(pd, "_raspberry_pi_model", lambda: None)
    monkeypatch.setattr(pd, "_os_release_id", lambda: "ubuntu")
    monkeypatch.setattr(pd, "_in_container", lambda: True)
    monkeypatch.setattr(pd, "_windows_host_under_linux_container", lambda: True)
    _reset_cache()
    assert pd.detect_hardware() == "ubuntu-docker-win"


def test_never_raises(monkeypatch) -> None:
    def boom() -> str:
        raise RuntimeError("probe failed")

    monkeypatch.setattr(pd.platform, "system", boom)
    _reset_cache()
    assert pd.detect_hardware() == "unknown"
    _reset_cache()
