"""PcapRingBuffer — in-memory windowing + rolling on-disk pcap persistence."""

from __future__ import annotations

import struct
import time
from pathlib import Path

from service_loader import import_from_service


def _import():
    ring = import_from_service("packet-sensor", "src.evidence.ring_buffer")
    return ring.PcapRingBuffer


def test_in_memory_only_writes_no_files(tmp_path: Path) -> None:
    PcapRingBuffer = _import()
    ring = PcapRingBuffer(max_packets=10)  # no storage_dir
    ref = ring.append(b"\x00" * 64)
    assert ref.startswith("local-ringbuffer://")
    assert ring.latest_segment == ""
    assert list(tmp_path.glob("*.pcap")) == []


def test_disk_persistence_writes_valid_pcap(tmp_path: Path) -> None:
    PcapRingBuffer = _import()
    storage = tmp_path / "pcap"
    ring = PcapRingBuffer(max_packets=100, storage_dir=str(storage))
    for i in range(5):
        ring.append(bytes([i]) * 32)
    seg = Path(ring.latest_segment)
    assert seg.is_file()
    data = seg.read_bytes()
    # global header magic (little-endian a1b2c3d4)
    assert struct.unpack("<I", data[:4])[0] == 0xA1B2C3D4
    # first record header: ts_sec, ts_usec, incl_len, orig_len
    incl = struct.unpack("<I", data[24 + 8 : 24 + 12])[0]
    assert incl == 32


def test_segment_rolls_and_disk_cap_prunes(tmp_path: Path) -> None:
    PcapRingBuffer = _import()
    storage = tmp_path / "pcap"
    # tiny segments + tiny disk cap force rolling and pruning
    ring = PcapRingBuffer(
        max_packets=1000,
        storage_dir=str(storage),
        segment_max_bytes=120,
        max_disk_bytes=400,
    )
    for _ in range(50):
        ring.append(b"\xaa" * 60)
    segments = list(storage.glob("seg-*.pcap"))
    assert len(segments) >= 2  # rolled into multiple segments
    total = sum(p.stat().st_size for p in segments)
    # Pruning keeps total bounded near the cap (one in-progress segment of
    # slack), far below the unpruned ~50*76 bytes that would accumulate.
    assert total <= 400 + 2 * 120
    assert total < 50 * 76 // 2


def test_window_returns_packets_in_range() -> None:
    PcapRingBuffer = _import()
    ring = PcapRingBuffer(max_packets=100)
    now = time.time()
    ring.append(b"a", captured_at=now - 100)
    ring.append(b"b", captured_at=now)
    ring.append(b"c", captured_at=now + 100)
    got = ring.window(now, before_sec=10, after_sec=10)
    assert got == [b"b"]
