"""AF_XDP frame reader → Scapy Ether for PacketPipeline (Track A)."""

from __future__ import annotations

import ctypes
import logging
import time
from dataclasses import dataclass, field
from typing import Callable

from scapy.layers.l2 import Ether

from src.capture.xdp_loader import default_bpf_object_path, last_xdp_error, load_xdp_library
from src.config.settings import CaptureConfig

logger = logging.getLogger(__name__)

POLL_BATCH = 64
EMPTY_POLL_SLEEP_SEC = 0.001


@dataclass
class XdpCaptureStats:
    rx_frames: int = 0
    kernel_rx: int = 0
    kernel_redirected: int = 0
    kernel_pass: int = 0
    busy_poll_ms: float = 0.0
    umem_fill_ratio: float = 0.0
    started_at: float = field(default_factory=time.monotonic)


class XdpCaptureSession:
    """Poll AF_XDP UMEM frames and deliver Scapy packets to a handler."""

    def __init__(self, capture: CaptureConfig) -> None:
        self._capture = capture
        self._lib = load_xdp_library()
        self._handle: ctypes.c_void_p | None = None
        self.stats = XdpCaptureStats()
        self._active = False
        self._backend_label = "af_xdp"

    @property
    def enabled(self) -> bool:
        return self._capture.backend == "af_xdp"

    @property
    def active(self) -> bool:
        return self._active

    @property
    def backend_label(self) -> str:
        return self._backend_label

    def _try_open_once(self, xdp_mode: int) -> bool:
        assert self._lib is not None
        bpf_path = default_bpf_object_path()
        handle = self._lib.xdp_cap_open(
            self._capture.interface.encode(),
            int(self._capture.xdp_queue_id),
            str(bpf_path).encode(),
            xdp_mode,
            int(self._capture.af_xdp_frame_size),
            int(self._capture.af_xdp_num_frames),
        )
        if not handle:
            logger.warning(
                "xdp_cap_open failed iface=%s queue=%s mode=%s: %s",
                self._capture.interface,
                self._capture.xdp_queue_id,
                "generic" if xdp_mode else "native",
                last_xdp_error(),
            )
            return False
        self._handle = handle
        return True

    def open(self) -> bool:
        if not self.enabled:
            return False
        if self._lib is None:
            logger.warning("AF_XDP library unavailable; fallback to scapy")
            return False

        bpf_path = default_bpf_object_path()
        if not bpf_path.is_file():
            logger.warning("XDP BPF object missing at %s; fallback to scapy", bpf_path)
            return False

        modes: list[int] = []
        if self._capture.xdp_mode == "generic":
            modes = [1]
        else:
            modes = [0, 1]

        for mode in modes:
            if self._try_open_once(mode):
                self._active = True
                mode_label = "generic" if mode else "native"
                if mode == 1 and self._capture.xdp_mode != "generic":
                    self._backend_label = "af_xdp_generic"
                version = self._lib.xdp_cap_version()
                logger.info(
                    "AF_XDP session opened iface=%s queue=%s mode=%s lib=%s bpf=%s",
                    self._capture.interface,
                    self._capture.xdp_queue_id,
                    mode_label,
                    version.decode() if version else "?",
                    bpf_path,
                )
                return True

        return False

    def close(self) -> None:
        if self._handle and self._lib:
            self._lib.xdp_cap_close(self._handle)
        self._handle = None
        self._active = False

    def _refresh_stats(self) -> None:
        if not self._handle or not self._lib:
            return
        rx = ctypes.c_uint64(0)
        redirected = ctypes.c_uint64(0)
        passed = ctypes.c_uint64(0)
        user_rx = ctypes.c_uint64(0)
        if self._lib.xdp_cap_stats(
            self._handle,
            ctypes.byref(rx),
            ctypes.byref(redirected),
            ctypes.byref(passed),
            ctypes.byref(user_rx),
        ) != 0:
            return
        self.stats.kernel_rx = int(rx.value)
        self.stats.kernel_redirected = int(redirected.value)
        self.stats.kernel_pass = int(passed.value)
        self.stats.rx_frames = int(user_rx.value)
        if self._capture.af_xdp_num_frames > 0:
            self.stats.umem_fill_ratio = round(
                self.stats.rx_frames / float(self._capture.af_xdp_num_frames),
                4,
            )

    def snapshot(self) -> dict:
        self._refresh_stats()
        elapsed = max(time.monotonic() - self.stats.started_at, 1.0)
        return {
            "capture_backend": self._backend_label,
            "rx_frames": self.stats.rx_frames,
            "kernel_rx": self.stats.kernel_rx,
            "kernel_redirected": self.stats.kernel_redirected,
            "kernel_pass": self.stats.kernel_pass,
            "rx_rate": round(self.stats.rx_frames / elapsed, 2),
            "umem_fill_ratio": self.stats.umem_fill_ratio,
            "busy_poll_ms": round(self.stats.busy_poll_ms, 2),
        }

    @staticmethod
    def _to_scapy_packet(raw: bytes):
        try:
            return Ether(raw)
        except Exception:
            return None

    def run(
        self,
        handle_packet: Callable[[object], None],
        should_stop: Callable[[], bool],
    ) -> None:
        if not self._handle or not self._lib:
            raise RuntimeError("AF_XDP session not open")

        buf_size = max(int(self._capture.af_xdp_frame_size), 2048)
        buf = ctypes.create_string_buffer(buf_size)

        while not should_stop():
            batch = 0
            poll_start = time.monotonic()
            while batch < POLL_BATCH and not should_stop():
                length = self._lib.xdp_cap_recv(
                    self._handle,
                    buf,
                    buf_size,
                    1 if batch == 0 else 0,
                )
                if length <= 0:
                    break
                packet = self._to_scapy_packet(buf.raw[:length])
                if packet is not None:
                    handle_packet(packet)
                batch += 1

            self.stats.busy_poll_ms += (time.monotonic() - poll_start) * 1000.0

            if batch == 0:
                time.sleep(EMPTY_POLL_SLEEP_SEC)

        self._refresh_stats()
        logger.info("AF_XDP session stopped rx_frames=%s", self.stats.rx_frames)


def try_open_xdp_session(capture: CaptureConfig) -> XdpCaptureSession | None:
    session = XdpCaptureSession(capture)
    if session.open():
        return session
    session.close()
    return None
