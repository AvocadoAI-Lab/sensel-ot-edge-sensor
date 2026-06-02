"""Load libxdp_capture.so for AF_XDP (Track A)."""

from __future__ import annotations

import ctypes
import logging
import os
from pathlib import Path

logger = logging.getLogger(__name__)

_LIB: ctypes.CDLL | None = None
_LIB_PATH: Path | None = None


def default_lib_paths() -> list[Path]:
    env = os.environ.get("XDP_CAPTURE_LIB", "").strip()
    paths: list[Path] = []
    if env:
        paths.append(Path(env))
    paths.extend(
        [
            Path("/app/lib/libxdp_capture.so"),
            Path(__file__).resolve().parents[2] / "native" / "libxdp_capture.so",
        ]
    )
    return paths


def load_xdp_library(force: bool = False) -> ctypes.CDLL | None:
    global _LIB, _LIB_PATH
    if _LIB is not None and not force:
        return _LIB

    for candidate in default_lib_paths():
        if not candidate.is_file():
            continue
        try:
            lib = ctypes.CDLL(str(candidate))
        except OSError as exc:
            logger.debug("Cannot load %s: %s", candidate, exc)
            continue

        lib.xdp_cap_open.argtypes = [
            ctypes.c_char_p,
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_int,
            ctypes.c_int,
            ctypes.c_int,
        ]
        lib.xdp_cap_open.restype = ctypes.c_void_p

        lib.xdp_cap_recv.argtypes = [
            ctypes.c_void_p,
            ctypes.c_char_p,
            ctypes.c_int,
            ctypes.c_int,
        ]
        lib.xdp_cap_recv.restype = ctypes.c_int

        lib.xdp_cap_stats.argtypes = [
            ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_uint64),
            ctypes.POINTER(ctypes.c_uint64),
            ctypes.POINTER(ctypes.c_uint64),
            ctypes.POINTER(ctypes.c_uint64),
        ]
        lib.xdp_cap_stats.restype = ctypes.c_int

        lib.xdp_cap_close.argtypes = [ctypes.c_void_p]
        lib.xdp_cap_close.restype = None

        lib.xdp_cap_version.argtypes = []
        lib.xdp_cap_version.restype = ctypes.c_char_p

        lib.xdp_cap_last_error.argtypes = []
        lib.xdp_cap_last_error.restype = ctypes.c_char_p

        _LIB = lib
        _LIB_PATH = candidate
        logger.info("Loaded AF_XDP library from %s", candidate)
        return lib

    _LIB = None
    _LIB_PATH = None
    return None


def library_available() -> bool:
    return load_xdp_library() is not None


def last_xdp_error() -> str:
    lib = load_xdp_library()
    if lib is None:
        return "libxdp_capture unavailable"
    msg = lib.xdp_cap_last_error()
    return msg.decode() if msg else "unknown error"


def default_bpf_object_path() -> Path:
    env = os.environ.get("XDP_BPF_OBJECT", "").strip()
    if env:
        return Path(env)
    return Path("/app/bpf/xdp_redirect.bpf.o")
