"""IP layer parsing — Sprint 1: address extraction."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class L3Stats:
    ipv4: int = 0
    ipv6: int = 0
    src_ip_counts: dict[str, int] = field(default_factory=dict)


def parse_ip(packet) -> tuple[str | None, str | None, str | None]:
    """Return (src_ip, dst_ip, version) for IPv4/IPv6."""
    if packet.haslayer("IP"):
        ip = packet["IP"]
        return str(ip.src), str(ip.dst), "ipv4"
    if packet.haslayer("IPv6"):
        ip6 = packet["IPv6"]
        return str(ip6.src), str(ip6.dst), "ipv6"
    return None, None, None


def record_l3(stats: L3Stats, src_ip: str | None, version: str | None) -> None:
    if version == "ipv4":
        stats.ipv4 += 1
    elif version == "ipv6":
        stats.ipv6 += 1
    if src_ip:
        stats.src_ip_counts[src_ip] = stats.src_ip_counts.get(src_ip, 0) + 1
