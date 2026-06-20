"""PCAP ring buffer — in-memory retention with local evidence references."""

from __future__ import annotations

import time
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone


def _utc_iso(ts: float | None = None) -> str:
    when = datetime.fromtimestamp(ts or time.time(), tz=timezone.utc)
    return when.replace(microsecond=0).isoformat()


@dataclass
class RingEntry:
    captured_at: float
    packet_bytes: bytes


@dataclass
class PcapRingBuffer:
    max_packets: int = 5000
    _entries: deque[RingEntry] = field(default_factory=deque)
    _last_ref: str = ""

    def append(self, packet_bytes: bytes, captured_at: float | None = None) -> str:
        ts = captured_at if captured_at is not None else time.time()
        self._entries.append(RingEntry(captured_at=ts, packet_bytes=packet_bytes))
        while len(self._entries) > self.max_packets:
            self._entries.popleft()
        self._last_ref = f"local-ringbuffer://{_utc_iso(ts)}"
        return self._last_ref

    @property
    def latest_ref(self) -> str:
        return self._last_ref

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
