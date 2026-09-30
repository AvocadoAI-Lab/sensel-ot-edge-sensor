"""Accumulate baseline observations from parsed packets.

``BaselineCollector.observe(packet)`` is a drop-in ``prn`` callback for
``scapy.sniff`` (live or ``offline=<pcap>``). It feeds the existing parsers and
records the *identities* needed to seed a detection baseline. It deliberately
does NOT emit security events — learning must not alert.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from src.parser.l2.ethernet import parse_ethernet
from src.parser.l3.ip import parse_ip
from src.parser.l4.transport import FlowTuple, parse_transport
from src.parser.l7.iec61850.goose import parse_goose_packet
from src.parser.l7.iec61850.mms import MMS_PORT, parse_mms_packet
from src.parser.l7.modbus.tcp import MODBUS_PORT, parse_modbus_tcp
from src.topology.protocol_hints import DNS_SERVER_MIN_CLIENTS, LDAP_SERVER_MIN_CLIENTS, hint_for_port

GOOSE_DEFAULT_SILENCE_SEC = 30


@dataclass
class _GooseObs:
    publisher_mac: str
    appid: int
    gocb_ref: str
    go_id: str = ""
    conf_rev: int = 0
    frames: int = 0
    test_frames: int = 0
    production_frames: int = 0
    stnum_min: int | None = None
    stnum_max: int | None = None
    last_seen: float = 0.0


@dataclass
class _MmsObs:
    ied_ip: str
    clients: dict[str, float] = field(default_factory=dict)
    reads: int = 0
    writes: int = 0
    last_seen: float = 0.0


@dataclass
class _ModbusObs:
    server_ip: str
    units: set[int] = field(default_factory=set)
    function_codes: set[int] = field(default_factory=set)
    clients: set[str] = field(default_factory=set)
    last_seen: float = 0.0


class BaselineCollector:
    """Reuse the live parsers to learn a candidate baseline."""

    def __init__(self, *, tenant_id: str = "", sensor_id: str = "") -> None:
        self.tenant_id = tenant_id
        self.sensor_id = sensor_id
        self.packets = 0
        self.parse_errors = 0
        self._goose: dict[str, _GooseObs] = {}
        self._mms: dict[str, _MmsObs] = {}
        self._modbus: dict[str, _ModbusObs] = {}
        self._macs: set[str] = set()
        self._ips: set[str] = set()
        self._mac_ip: dict[str, str] = {}
        self._comm_pairs: dict[tuple[str, str], float] = {}
        self._ip_hints: dict[str, set[str]] = {}
        self._ldap_clients: dict[str, dict[str, float]] = {}
        self._dns_clients: dict[str, dict[str, float]] = {}

    # -- ingestion -----------------------------------------------------------
    def observe(self, packet) -> None:
        self.note_packet()
        try:
            self._observe(packet)
        except Exception:  # parsing must never abort a learning run
            self.parse_errors += 1

    def note_packet(self) -> None:
        """Count one frame toward stats.packets (live pipeline calls this per capture)."""
        self.packets += 1

    def _observe(self, packet) -> None:
        src_mac, _ = parse_ethernet(packet)
        src_ip, dst_ip, _ = parse_ip(packet)
        self.feed_endpoints(src_mac, src_ip, dst_ip)

        goose = parse_goose_packet(packet)
        if goose is not None:
            self.feed_goose(goose)
            return

        mms = parse_mms_packet(packet)
        if mms is not None:
            self.feed_mms(mms)

        modbus = parse_modbus_tcp(packet)
        if modbus is not None:
            self.feed_modbus(modbus)

        flow = parse_transport(packet)
        if flow is not None:
            self.feed_transport(flow)

    def feed_transport(self, flow: FlowTuple) -> None:
        hint = hint_for_port(flow.dst_port)
        if not hint or not flow.src_ip or not flow.dst_ip:
            return
        now = time.monotonic()
        self._ip_hints.setdefault(flow.dst_ip, set()).add(hint)
        self._ip_hints.setdefault(flow.src_ip, set()).add(hint)
        if hint == "ldap":
            self._ldap_clients.setdefault(flow.dst_ip, {})[flow.src_ip] = now
        if hint == "dns":
            self._dns_clients.setdefault(flow.dst_ip, {})[flow.src_ip] = now

    # -- feed APIs (accept already-parsed objects; reused by the live pipeline)
    def feed_endpoints(self, src_mac: str | None, src_ip: str | None, dst_ip: str | None) -> None:
        if src_mac:
            self._macs.add(src_mac)
        if src_ip:
            self._ips.add(src_ip)
            if src_mac:
                self._mac_ip[src_mac] = src_ip
        if dst_ip:
            self._ips.add(dst_ip)
        if src_ip and dst_ip:
            self._comm_pairs[(src_ip, dst_ip)] = time.monotonic()

    def feed_goose(self, frame) -> None:
        key = f"{frame.publisher_mac}|{frame.appid}|{frame.gocb_ref}"
        obs = self._goose.get(key)
        if obs is None:
            obs = _GooseObs(
                publisher_mac=frame.publisher_mac,
                appid=int(frame.appid),
                gocb_ref=frame.gocb_ref,
                go_id=frame.go_id,
                conf_rev=int(frame.conf_rev),
            )
            self._goose[key] = obs
        obs.frames += 1
        if frame.test:
            obs.test_frames += 1
        else:
            obs.production_frames += 1
        sn = int(frame.st_num)
        obs.stnum_min = sn if obs.stnum_min is None else min(obs.stnum_min, sn)
        obs.stnum_max = sn if obs.stnum_max is None else max(obs.stnum_max, sn)
        if frame.go_id and not obs.go_id:
            obs.go_id = frame.go_id
        obs.last_seen = time.monotonic()

    def feed_mms(self, obs) -> None:
        # The IED is the endpoint on TCP/102; the peer is the client.
        if obs.dst_port == MMS_PORT:
            ied_ip, client_ip = obs.dst_ip, obs.src_ip
        elif obs.src_port == MMS_PORT:
            ied_ip, client_ip = obs.src_ip, obs.dst_ip
        else:
            return
        rec = self._mms.get(ied_ip)
        if rec is None:
            rec = _MmsObs(ied_ip=ied_ip)
            self._mms[ied_ip] = rec
        now = time.monotonic()
        if client_ip:
            rec.clients[client_ip] = now
        if obs.pdu_type == "read":
            rec.reads += 1
        elif obs.pdu_type == "write":
            rec.writes += 1
        rec.last_seen = now

    def feed_modbus(self, frame) -> None:
        if frame.dst_port == MODBUS_PORT:
            server_ip, client_ip = frame.dst_ip, frame.src_ip
        elif frame.src_port == MODBUS_PORT:
            server_ip, client_ip = frame.src_ip, frame.dst_ip
        else:
            return
        rec = self._modbus.get(server_ip)
        if rec is None:
            rec = _ModbusObs(server_ip=server_ip)
            self._modbus[server_ip] = rec
        rec.units.add(int(frame.unit_id))
        rec.function_codes.add(int(frame.function_code))
        if client_ip:
            rec.clients.add(client_ip)
        rec.last_seen = time.monotonic()

    # -- serialisation -------------------------------------------------------
    @staticmethod
    def _fresh(last_seen: float, cutoff: float | None) -> bool:
        return cutoff is None or last_seen >= cutoff

    def goose_publishers(self, cutoff: float | None = None) -> list[dict[str, Any]]:
        items = [o for o in self._goose.values() if self._fresh(o.last_seen, cutoff)]
        out: list[dict[str, Any]] = []
        for i, obs in enumerate(sorted(items, key=lambda o: (o.appid, o.publisher_mac)), 1):
            production = obs.production_frames > 0 or obs.test_frames == 0
            out.append(
                {
                    "asset_id": f"learned-goose-{i:02d}",
                    "publisher_mac": obs.publisher_mac,
                    "appid": obs.appid,
                    "gocb_ref": obs.gocb_ref,
                    "go_id": obs.go_id,
                    "conf_rev": obs.conf_rev,
                    "production": production,
                    "max_silence_sec": GOOSE_DEFAULT_SILENCE_SEC,
                    "observed_frames": obs.frames,
                }
            )
        return out

    def mms_ieds(self, cutoff: float | None = None) -> list[dict[str, Any]]:
        items = [r for r in self._mms.values() if self._fresh(r.last_seen, cutoff)]
        out: list[dict[str, Any]] = []
        for i, rec in enumerate(sorted(items, key=lambda r: r.ied_ip), 1):
            clients = sorted(ip for ip, seen in rec.clients.items() if self._fresh(seen, cutoff))
            out.append(
                {
                    "asset_id": f"learned-ied-{i:02d}",
                    "ied_ip": rec.ied_ip,
                    "allowed_mms_clients": clients,
                    "observed_reads": rec.reads,
                    "observed_writes": rec.writes,
                }
            )
        return out

    def modbus_servers(self, cutoff: float | None = None) -> list[dict[str, Any]]:
        items = [r for r in self._modbus.values() if self._fresh(r.last_seen, cutoff)]
        out: list[dict[str, Any]] = []
        for rec in sorted(items, key=lambda r: r.server_ip):
            out.append(
                {
                    "server_ip": rec.server_ip,
                    "unit_ids": sorted(rec.units),
                    "function_codes": sorted(rec.function_codes),
                    "allowed_clients": sorted(rec.clients),
                }
            )
        return out

    def _comm_pairs_fresh(self, cutoff: float | None) -> list[tuple[str, str]]:
        return sorted(p for p, seen in self._comm_pairs.items() if self._fresh(seen, cutoff))

    def summary(self, cutoff: float | None = None, *, goose=None, mms=None, modbus=None) -> dict[str, Any]:
        goose = goose if goose is not None else self.goose_publishers(cutoff)
        mms = mms if mms is not None else self.mms_ieds(cutoff)
        modbus = modbus if modbus is not None else self.modbus_servers(cutoff)
        return {
            "packets": self.packets,
            "parse_errors": self.parse_errors,
            "unique_macs": len(self._macs),
            "unique_ips": len(self._ips),
            "comm_pairs": len(self._comm_pairs_fresh(cutoff)),
            "goose_publishers": len(goose),
            "mms_ieds": len(mms),
            "modbus_servers": len(modbus),
        }

    def port_hint_index(self, cutoff: float | None = None) -> dict[str, dict[str, Any]]:
        out: dict[str, dict[str, Any]] = {}
        for ip, hints in self._ip_hints.items():
            ldap_clients = {
                cip
                for cip, seen in (self._ldap_clients.get(ip) or {}).items()
                if self._fresh(seen, cutoff)
            }
            dns_clients = {
                cip
                for cip, seen in (self._dns_clients.get(ip) or {}).items()
                if self._fresh(seen, cutoff)
            }
            out[ip] = {
                "hints": sorted(hints),
                "ldap_clients": len(ldap_clients),
                "dns_clients": len(dns_clients),
                "ldap_client_ips": sorted(ldap_clients),
                "dns_client_ips": sorted(dns_clients),
                "ldap_server": len(ldap_clients) >= LDAP_SERVER_MIN_CLIENTS,
                "dns_server": len(dns_clients) >= DNS_SERVER_MIN_CLIENTS,
            }
        return out

    def to_candidate(
        self,
        *,
        source: str = "pcap_import",
        source_ref: str = "",
        window_sec: float | None = None,
    ) -> dict[str, Any]:
        """Build a candidate baseline document.

        ``window_sec`` ages out identities not seen within the window (used for
        the *live* snapshot). The pcap learn path passes ``None`` to keep every
        observation. ``observed.iec61850`` mirrors the detector's policy schema
        so approving it is a straight merge into ``detection-policy.json``.
        """
        cutoff = (time.monotonic() - window_sec) if window_sec else None
        goose = self.goose_publishers(cutoff)
        mms = self.mms_ieds(cutoff)
        modbus = self.modbus_servers(cutoff)
        observed = {
            "iec61850": {"goose_publishers": goose, "mms_ieds": mms},
            "modbus_servers": modbus,
            "comm_pairs": [{"src": s, "dst": d} for s, d in self._comm_pairs_fresh(cutoff)],
            "mac_ip": [{"mac": m, "ip": ip} for m, ip in sorted(self._mac_ip.items())],
        }
        if self.tenant_id and self.sensor_id:
            from src.topology.purdue_classifier import build_observed_topology

            observed["topology"] = build_observed_topology(
                observed,
                tenant_id=self.tenant_id,
                sensor_id=self.sensor_id,
                port_hints=self.port_hint_index(cutoff),
            )
        return {
            "schema": "sensel.baseline/1",
            "generated_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
            "source": source,
            "source_ref": source_ref,
            "window_sec": window_sec,
            "stats": self.summary(cutoff, goose=goose, mms=mms, modbus=modbus),
            "observed": observed,
        }
