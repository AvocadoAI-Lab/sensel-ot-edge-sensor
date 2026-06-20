"""Ethernet frame parsing — Sprint 1: MAC extraction and counters."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class L2Stats:
    total: int = 0
    mac_src_counts: dict[str, int] = field(default_factory=dict)
    window_total: int = 0
    window_mac_counts: dict[str, int] = field(default_factory=dict)


def parse_ethernet(packet) -> tuple[str | None, str | None]:
    """Return (src_mac, dst_mac) if Ethernet layer present."""
    if not packet.haslayer("Ether"):
        return None, None
    eth = packet["Ether"]
    return str(eth.src), str(eth.dst)


def record_l2(stats: L2Stats, src_mac: str | None) -> None:
    stats.total += 1
    stats.window_total += 1
    if src_mac:
        stats.mac_src_counts[src_mac] = stats.mac_src_counts.get(src_mac, 0) + 1
        stats.window_mac_counts[src_mac] = stats.window_mac_counts.get(src_mac, 0) + 1


def reset_l2_window(stats: L2Stats) -> None:
    stats.window_total = 0
    stats.window_mac_counts.clear()
