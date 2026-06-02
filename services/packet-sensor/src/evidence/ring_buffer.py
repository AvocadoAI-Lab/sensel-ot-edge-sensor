"""PCAP ring buffer — in-memory retention + optional rolling on-disk pcap.

The in-memory deque gives fast windowing for evidence extraction. When a
storage directory is configured, packets are also appended to rolling libpcap
segments so evidence survives a restart; old segments are pruned by age and by
a total-disk cap. `evidence_ref` keeps its `local-ringbuffer://` form for
backward compatibility; the on-disk segment path is surfaced via
`latest_segment` and attached to events as `evidence.pcap_file`.
"""

from __future__ import annotations

import struct
import time
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

# libpcap global header: magic, ver 2.4, thiszone, sigfigs, snaplen, LINKTYPE_ETHERNET(1)
_PCAP_GLOBAL_HEADER = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)


def _utc_iso(ts: float | None = None) -> str:
    when = datetime.fromtimestamp(ts or time.time(), tz=timezone.utc)
    return when.replace(microsecond=0).isoformat()


def _segment_name(ts: float, seq: int) -> str:
    stamp = datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y%m%dT%H%M%S")
    return f"seg-{stamp}-{seq:05d}.pcap"


@dataclass
class RingEntry:
    captured_at: float
    packet_bytes: bytes


@dataclass
class PcapRingBuffer:
    max_packets: int = 5000
    storage_dir: str | None = None
    retention_sec: float = 7200.0
    max_disk_bytes: int = 2 * 1024 * 1024 * 1024
    segment_max_bytes: int = 16 * 1024 * 1024
    _entries: deque[RingEntry] = field(default_factory=deque)
    _last_ref: str = ""
    _dir: Path | None = field(default=None, init=False)
    _seg_path: Path | None = field(default=None, init=False)
    _seg_size: int = field(default=0, init=False)
    _seg_seq: int = field(default=0, init=False)

    def __post_init__(self) -> None:
        if self.storage_dir:
            self._dir = Path(self.storage_dir)
            self._dir.mkdir(parents=True, exist_ok=True)

    def append(self, packet_bytes: bytes, captured_at: float | None = None) -> str:
        ts = captured_at if captured_at is not None else time.time()
        self._entries.append(RingEntry(captured_at=ts, packet_bytes=packet_bytes))
        while len(self._entries) > self.max_packets:
            self._entries.popleft()
        if self._dir is not None:
            self._write_disk(packet_bytes, ts)
        self._last_ref = f"local-ringbuffer://{_utc_iso(ts)}"
        return self._last_ref

    def _write_disk(self, packet_bytes: bytes, ts: float) -> None:
        if self._seg_path is None or self._seg_size >= self.segment_max_bytes:
            self._roll_segment(ts)
        sec = int(ts)
        usec = int((ts - sec) * 1_000_000)
        incl = len(packet_bytes)
        record = struct.pack("<IIII", sec, usec, incl, incl) + packet_bytes
        try:
            with self._seg_path.open("ab") as handle:  # type: ignore[union-attr]
                handle.write(record)
            self._seg_size += len(record)
        except OSError:
            pass

    def _roll_segment(self, ts: float) -> None:
        assert self._dir is not None
        self._seg_seq += 1
        self._seg_path = self._dir / _segment_name(ts, self._seg_seq)
        try:
            self._seg_path.write_bytes(_PCAP_GLOBAL_HEADER)
            self._seg_size = len(_PCAP_GLOBAL_HEADER)
        except OSError:
            self._seg_size = 0
        self._prune()

    def _prune(self) -> None:
        if self._dir is None:
            return
        now = time.time()
        segments = sorted(self._dir.glob("seg-*.pcap"))
        for seg in segments:
            try:
                if seg != self._seg_path and now - seg.stat().st_mtime > self.retention_sec:
                    seg.unlink()
            except OSError:
                pass
        segments = sorted(
            (p for p in self._dir.glob("seg-*.pcap")),
            key=lambda p: p.stat().st_mtime if p.exists() else 0.0,
        )
        total = sum(p.stat().st_size for p in segments if p.exists())
        while total > self.max_disk_bytes and len(segments) > 1:
            victim = segments.pop(0)
            if victim == self._seg_path:
                break
            try:
                total -= victim.stat().st_size
                victim.unlink()
            except OSError:
                pass

    @property
    def latest_ref(self) -> str:
        return self._last_ref

    @property
    def latest_segment(self) -> str:
        return str(self._seg_path) if self._seg_path else ""

    def count(self) -> int:
        return len(self._entries)

    def window(self, center_ts: float, before_sec: float, after_sec: float) -> list[bytes]:
        start = center_ts - before_sec
        end = center_ts + after_sec
        return [
            entry.packet_bytes
            for entry in self._entries
            if start <= entry.captured_at <= end
        ]
