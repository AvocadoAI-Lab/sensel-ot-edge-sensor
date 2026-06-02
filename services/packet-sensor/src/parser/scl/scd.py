"""IEC 61850 SCL/SCD parser.

Extracts the *engineered* substation configuration (IED inventory + IP
endpoints, GOOSE control blocks) so the detection baseline can be derived from
the authoritative engineering file rather than hand-authored JSON.

Design notes:
- Passive / offline: parses a file, never touches the network.
- Matches elements by *local* name so both the 2003 and 2007 SCL namespaces work.
- The ``GSE/Address/MAC-Address`` in SCL is the GOOSE *destination multicast*
  MAC (01-0C-CD-...), NOT the publisher's source MAC. The detector matches GOOSE
  by source MAC, so the authoritative, wire-observable key from SCL is the
  **APPID** (captured here); the multicast MAC is kept only as metadata.
- Per IEC 61850-6 the APPID ``P`` value is hexadecimal; we parse base-16 first
  and fall back to base-10, then validate the GOOSE range (<= 0x3FFF).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from xml.etree import ElementTree as ET

GOOSE_APPID_MAX = 0x3FFF


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _descendants(elem, name: str) -> list:
    return [c for c in elem.iter() if _local(c.tag) == name]


def _children(elem, name: str) -> list:
    return [c for c in list(elem) if _local(c.tag) == name]


def _norm_mac(value: str) -> str:
    return value.strip().replace("-", ":").replace(".", ":").lower()


def parse_appid(value: str | None, base: int = 16) -> int | None:
    """Parse an SCL APPID. Hex per IEC 61850-6, with a base-10 fallback."""
    value = (value or "").strip()
    if not value:
        return None
    for radix in (base, 10):
        try:
            return int(value, radix)
        except ValueError:
            continue
    return None


def _p_value(address_elem, ptype: str) -> str | None:
    for p in _children(address_elem, "P"):
        if p.get("type") == ptype and p.text:
            return p.text.strip()
    return None


def _max_time_ms(gse) -> int | None:
    for mt in _children(gse, "MaxTime"):
        text = (mt.text or "").strip()
        if not text.isdigit():
            continue
        value = int(text)
        # unit is seconds; multiplier "m" = milli.
        return value if mt.get("multiplier") == "m" else value * 1000
    return None


@dataclass
class GooseControl:
    ied_name: str
    ld_inst: str
    cb_name: str
    appid: int | None
    dst_mac: str  # destination multicast MAC (metadata, not a match key)
    vlan_id: int | None
    max_time_ms: int | None
    gocb_ref: str

    @property
    def appid_in_goose_range(self) -> bool:
        return self.appid is not None and 0 <= self.appid <= GOOSE_APPID_MAX


@dataclass
class IedEndpoint:
    ied_name: str
    ip: str | None
    has_server: bool


@dataclass
class ScdModel:
    ieds: list[IedEndpoint] = field(default_factory=list)
    goose: list[GooseControl] = field(default_factory=list)

    def ied_ip(self, name: str) -> str | None:
        for ied in self.ieds:
            if ied.ied_name == name:
                return ied.ip
        return None

    def servers(self) -> list[IedEndpoint]:
        return [ied for ied in self.ieds if ied.has_server and ied.ip]


def parse_scd(path: str | Path, appid_base: int = 16) -> ScdModel:
    p = Path(path)
    if not p.is_file():
        raise FileNotFoundError(f"SCD/SCL file not found: {p}")
    try:
        root = ET.parse(p).getroot()
    except ET.ParseError as exc:
        raise ValueError(f"Invalid SCL/SCD XML: {exc}") from exc
    if _local(root.tag) != "SCL":
        raise ValueError(f"Not an SCL document (root element is {_local(root.tag)!r})")

    ip_by_ied: dict[str, str] = {}
    goose: list[GooseControl] = []

    for cap in _descendants(root, "ConnectedAP"):
        ied_name = cap.get("iedName", "")
        for addr in _children(cap, "Address"):
            ip = _p_value(addr, "IP")
            if ied_name and ip:
                ip_by_ied[ied_name] = ip
        for gse in _children(cap, "GSE"):
            cb = gse.get("cbName", "")
            ld = gse.get("ldInst", "")
            mac = appid = vlan = None
            for addr in _children(gse, "Address"):
                mac = _p_value(addr, "MAC-Address")
                appid = _p_value(addr, "APPID")
                vlan = _p_value(addr, "VLAN-ID")
            goose.append(
                GooseControl(
                    ied_name=ied_name,
                    ld_inst=ld,
                    cb_name=cb,
                    appid=parse_appid(appid, appid_base),
                    dst_mac=_norm_mac(mac) if mac else "",
                    vlan_id=int(vlan) if vlan and vlan.isdigit() else None,
                    max_time_ms=_max_time_ms(gse),
                    gocb_ref=f"{ied_name}{ld}/LLN0.{cb}" if ied_name and cb else "",
                )
            )

    ieds: list[IedEndpoint] = []
    for ied in _descendants(root, "IED"):
        name = ied.get("name", "")
        if not name:
            continue
        ieds.append(
            IedEndpoint(
                ied_name=name,
                ip=ip_by_ied.get(name),
                has_server=bool(_descendants(ied, "Server")),
            )
        )

    return ScdModel(ieds=ieds, goose=goose)
