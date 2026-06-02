"""L3: ARP parsing — MAC/IP binding extraction for ARP spoofing detection (OT-003)."""

from __future__ import annotations

from dataclasses import dataclass

ARP_REQUEST = 1
ARP_REPLY = 2


@dataclass(frozen=True)
class ArpFrame:
    op: int  # 1=request (who-has), 2=reply (is-at)
    sender_mac: str
    sender_ip: str
    target_mac: str
    target_ip: str

    @property
    def is_reply(self) -> bool:
        return self.op == ARP_REPLY


def parse_arp(packet) -> ArpFrame | None:
    """Return the ARP sender/target binding when an ARP layer is present.

    ARP spoofing announces a sender_ip already owned by another host but with
    the attacker's sender_mac; tracking the (sender_ip -> sender_mac) binding
    over time lets OT-003 detect the flip.
    """
    if not packet.haslayer("ARP"):
        return None
    arp = packet["ARP"]
    sender_ip = str(arp.psrc)
    sender_mac = str(arp.hwsrc)
    if not sender_ip or not sender_mac:
        return None
    return ArpFrame(
        op=int(arp.op),
        sender_mac=sender_mac,
        sender_ip=sender_ip,
        target_mac=str(arp.hwdst),
        target_ip=str(arp.pdst),
    )
