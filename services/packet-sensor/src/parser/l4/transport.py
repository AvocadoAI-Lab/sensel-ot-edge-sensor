"""L4: TCP/UDP five-tuple extraction."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class FlowTuple:
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str  # tcp | udp


def parse_transport(packet) -> FlowTuple | None:
    """Return L4 flow metadata when TCP or UDP is present."""
    if packet.haslayer("TCP"):
        ip_layer = packet.getlayer("IP") or packet.getlayer("IPv6")
        if ip_layer is None:
            return None
        tcp = packet["TCP"]
        return FlowTuple(
            src_ip=str(ip_layer.src),
            dst_ip=str(ip_layer.dst),
            src_port=int(tcp.sport),
            dst_port=int(tcp.dport),
            protocol="tcp",
        )
    if packet.haslayer("UDP"):
        ip_layer = packet.getlayer("IP") or packet.getlayer("IPv6")
        if ip_layer is None:
            return None
        udp = packet["UDP"]
        return FlowTuple(
            src_ip=str(ip_layer.src),
            dst_ip=str(ip_layer.dst),
            src_port=int(udp.sport),
            dst_port=int(udp.dport),
            protocol="udp",
        )
    return None
