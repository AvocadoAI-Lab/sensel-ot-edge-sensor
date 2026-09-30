"""Track A AF_XDP fallback and config tests."""

from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

ROOT = Path(__file__).resolve().parents[2]
PACKET_SRC = str(ROOT / "services" / "packet-sensor")


def _isolate_packet_path() -> None:
    for key in list(sys.modules):
        if key == "src" or key.startswith("src."):
            del sys.modules[key]
    sys.path[:] = [p for p in sys.path if p not in (PACKET_SRC, str(ROOT))]
    sys.path.insert(0, PACKET_SRC)


def _import_capture():
    _isolate_packet_path()
    from src.capture.interface import CaptureSession
    from src.capture.xdp_reader import XdpCaptureSession, try_open_xdp_session
    from src.config.settings import CaptureConfig, load_config

    return CaptureSession, XdpCaptureSession, try_open_xdp_session, CaptureConfig, load_config


def test_capture_backend_env_override(
    sensor_config_file: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, _, _, _, load_config = _import_capture()
    monkeypatch.setenv("CAPTURE_BACKEND", "af_xdp")
    monkeypatch.setenv("XDP_MODE", "generic")
    monkeypatch.setenv("XDP_QUEUE_ID", "2")
    config = load_config(sensor_config_file)
    assert config.capture.backend == "af_xdp"
    assert config.capture.xdp_mode == "generic"
    assert config.capture.xdp_queue_id == 2


def test_af_xdp_open_failure_falls_back_to_scapy(
    sensor_config_file: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    CaptureSession, _, _, _, load_config = _import_capture()
    monkeypatch.setenv("CAPTURE_BACKEND", "af_xdp")
    config = load_config(sensor_config_file)

    with patch("src.capture.interface.PacketPipeline"), patch(
        "src.capture.interface.try_open_xdp_session", return_value=None
    ), patch("src.capture.interface.sniff") as mock_sniff:
        mock_sniff.side_effect = lambda **kwargs: None
        session = CaptureSession(config)
        session.run(should_stop=lambda: True)

    assert session.capture_backend == "scapy"
    mock_sniff.assert_called_once()


def test_xdp_session_disabled_when_backend_scapy() -> None:
    _, XdpCaptureSession, try_open_xdp_session, CaptureConfig, _ = _import_capture()
    capture = CaptureConfig(backend="scapy")
    session = XdpCaptureSession(capture)
    assert session.open() is False
    assert try_open_xdp_session(capture) is None


def test_xdp_to_scapy_packet_parses_ether() -> None:
    _, XdpCaptureSession, _, CaptureConfig, _ = _import_capture()
    from scapy.layers.inet import IP, TCP
    from scapy.layers.l2 import Ether

    raw = bytes(Ether() / IP(dst="192.168.10.50") / TCP(dport=102))
    pkt = XdpCaptureSession._to_scapy_packet(raw)
    assert pkt is not None
    assert pkt.haslayer(IP)


def test_xdp_run_invokes_handler() -> None:
    _, XdpCaptureSession, _, CaptureConfig, _ = _import_capture()
    capture = CaptureConfig(backend="af_xdp")
    session = XdpCaptureSession(capture)
    session._active = True
    session._handle = MagicMock()
    session._lib = MagicMock()

    from scapy.layers.inet import IP, TCP
    from scapy.layers.l2 import Ether

    frame = bytes(Ether() / IP() / TCP(dport=102))
    session._lib.xdp_cap_recv.side_effect = [len(frame), 0, 0]

    seen: list[object] = []
    session.run(handle_packet=seen.append, should_stop=lambda: len(seen) >= 1)
    assert len(seen) == 1
