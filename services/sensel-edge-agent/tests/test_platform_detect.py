"""Tests for runtime hardware/platform detection."""

import src.config.platform_detect as pd


def _reset_cache() -> None:
    pd.detect_hardware.cache_clear()


def test_raspberry_pi4(monkeypatch) -> None:
    monkeypatch.setattr(pd.platform, "system", lambda: "Linux")
    monkeypatch.setattr(pd, "_raspberry_pi_model", lambda: "pi4")
    _reset_cache()
    assert pd.detect_hardware() == "pi4"


def test_ubuntu_host_from_kernel(monkeypatch) -> None:
    # Agent runs in a debian-based container, but the host kernel is Ubuntu's.
    monkeypatch.setattr(pd.platform, "system", lambda: "Linux")
    monkeypatch.setattr(pd, "_raspberry_pi_model", lambda: None)
    monkeypatch.setattr(pd.platform, "release", lambda: "7.0.0-22-generic")
    monkeypatch.setattr(
        pd,
        "_read_text",
        lambda p: "Linux version 7.0.0-22-generic (gcc Ubuntu 15.2.0-16ubuntu1)" if p == "/proc/version" else "",
    )
    _reset_cache()
    assert pd.detect_hardware() == "ubuntu"


def test_windows_docker_via_wsl(monkeypatch) -> None:
    monkeypatch.setattr(pd.platform, "system", lambda: "Linux")
    monkeypatch.setattr(pd, "_raspberry_pi_model", lambda: None)
    monkeypatch.setattr(pd.platform, "release", lambda: "5.15.0-microsoft-standard-WSL2")
    monkeypatch.setattr(
        pd,
        "_read_text",
        lambda p: "Linux version 5.15.0-microsoft-standard-WSL2" if p == "/proc/version" else "",
    )
    _reset_cache()
    assert pd.detect_hardware() == "windows-docker"


def test_falls_back_to_os_release(monkeypatch) -> None:
    monkeypatch.setattr(pd.platform, "system", lambda: "Linux")
    monkeypatch.setattr(pd, "_raspberry_pi_model", lambda: None)
    monkeypatch.setattr(pd, "_host_os_from_kernel", lambda: None)
    monkeypatch.setattr(pd, "_os_release_id", lambda: "alpine")
    _reset_cache()
    assert pd.detect_hardware() == "alpine"


def test_never_raises(monkeypatch) -> None:
    def boom() -> str:
        raise RuntimeError("probe failed")

    monkeypatch.setattr(pd.platform, "system", boom)
    _reset_cache()
    assert pd.detect_hardware() == "unknown"
    _reset_cache()
