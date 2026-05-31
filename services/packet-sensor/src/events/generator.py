"""Security event persistence for Packet Sensor."""

from __future__ import annotations

import json
from pathlib import Path

from src.detection.models import SecurityEvent
from src.evidence.ring_buffer import PcapRingBuffer


class EventStore:
    def __init__(self, output_dir: str) -> None:
        self._path = Path(output_dir) / "security-events.jsonl"
        self._path.parent.mkdir(parents=True, exist_ok=True)

    @property
    def path(self) -> Path:
        return self._path

    def append(
        self,
        event: SecurityEvent,
        ring_buffer: PcapRingBuffer | None = None,
    ) -> None:
        if ring_buffer is not None and not event.evidence_ref:
            ref = ring_buffer.latest_ref
            if ref:
                event.evidence_ref = ref
                event.evidence.setdefault("pcap_ref", ref)
        with self._path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(event.to_dict(), ensure_ascii=False) + "\n")

    def read_recent(self, limit: int = 20) -> list[dict]:
        if not self._path.is_file():
            return []
        lines = self._path.read_text(encoding="utf-8").splitlines()
        return [json.loads(line) for line in lines[-limit:] if line.strip()]
