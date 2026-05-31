"""Local OT asset inventory — MAC/IP/pair/port tracking for MVP rules."""

from __future__ import annotations

import time
from dataclasses import dataclass, field


@dataclass
class InventoryObservation:
    src_mac: str | None
    src_ip: str | None
    dst_ip: str | None
    dst_port: int | None
    protocol: str | None


@dataclass
class AssetInventory:
    mac_to_ip: dict[str, str] = field(default_factory=dict)
    known_macs: set[str] = field(default_factory=set)
    known_ips: set[str] = field(default_factory=set)
    known_pairs: set[str] = field(default_factory=set)
    known_dst_ports: set[str] = field(default_factory=set)
    last_seen_by_ip: dict[str, float] = field(default_factory=dict)
    window_packet_count: int = 0
    _port_scan_events: dict[str, list[tuple[float, int]]] = field(default_factory=dict)

    def observe(
        self,
        src_mac: str | None,
        src_ip: str | None,
        dst_ip: str | None,
        dst_port: int | None,
        protocol: str | None,
    ) -> InventoryObservation:
        now = time.monotonic()
        self.window_packet_count += 1

        if src_ip:
            self.last_seen_by_ip[src_ip] = now
        if dst_ip:
            self.last_seen_by_ip[dst_ip] = now

        if src_mac and src_ip:
            self.mac_to_ip[src_mac] = src_ip

        return InventoryObservation(
            src_mac=src_mac,
            src_ip=src_ip,
            dst_ip=dst_ip,
            dst_port=dst_port,
            protocol=protocol,
        )

    def record_port_scan_sample(self, src_ip: str, dst_port: int, now: float | None = None) -> None:
        ts = now if now is not None else time.monotonic()
        events = self._port_scan_events.setdefault(src_ip, [])
        events.append((ts, dst_port))

    def unique_ports_in_window(
        self, src_ip: str, window_sec: float, now: float | None = None
    ) -> set[int]:
        ts = now if now is not None else time.monotonic()
        cutoff = ts - window_sec
        events = self._port_scan_events.get(src_ip, [])
        self._port_scan_events[src_ip] = [(t, p) for t, p in events if t >= cutoff]
        return {port for t, port in self._port_scan_events[src_ip] if t >= cutoff}

    def reset_window(self) -> None:
        self.window_packet_count = 0
