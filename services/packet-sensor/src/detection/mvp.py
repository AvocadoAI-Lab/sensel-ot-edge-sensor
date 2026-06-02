"""MVP detection rules OT-001 ~ OT-010 (Sprint 2)."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from datetime import datetime, timezone

from src.assets.inventory import AssetInventory, InventoryObservation
from src.detection.models import SecurityEvent, utc_now_iso
from src.parser.l7.modbus.tcp import ModbusFrame

RULE_META = {
    "OT-001": ("NEW_MAC_DETECTED", "medium", "New MAC address observed on mirror port"),
    "OT-002": ("NEW_IP_DETECTED", "medium", "New IP address observed on mirror port"),
    "OT-003": ("MAC_IP_MAPPING_CHANGED", "high", "MAC/IP mapping changed from baseline"),
    "OT-004": ("NEW_COMMUNICATION_PAIR", "medium", "New communication pair observed"),
    "OT-005": ("NEW_DESTINATION_PORT", "medium", "New destination port combination observed"),
    "OT-006": ("PORT_SCAN_BEHAVIOR", "high", "Port scan behavior detected"),
    "OT-007": ("MODBUS_WRITE_ANOMALY", "high", "Unexpected Modbus write from non-baselined source"),
    "OT-008": ("ABNORMAL_TRAFFIC_RATE", "medium", "Traffic rate exceeds baseline threshold"),
    "OT-009": ("RELAY_OFFLINE", "high", "Relay asset appears offline"),
    "OT-010": ("UNAUTHORIZED_RELAY_ACCESS", "high", "Unauthorized host accessing relay asset"),
}


@dataclass
class MvpDetector:
    site_id: str
    sensor_id: str
    policy: dict
    rules_enabled: set[str] = field(default_factory=set)
    inventory: AssetInventory = field(default_factory=AssetInventory)
    alerted_offline: set[str] = field(default_factory=set)
    alerted_unauthorized: set[str] = field(default_factory=set)
    alerted_port_scan: set[str] = field(default_factory=set)
    _event_seq: int = 0
    # Wall-clock (epoch) is used for all "seen / silence" timing so it shares a
    # timeline with evidence_ref / on-disk pcap timestamps. NTP steps can jump
    # this clock; acceptable for coarse 60–120s silence windows.
    _started_at: float = field(default_factory=time.time)

    def _enabled(self, rule_id: str) -> bool:
        return not self.rules_enabled or rule_id in self.rules_enabled

    def _next_event_id(self, suffix: str = "mvp") -> str:
        self._event_seq += 1
        day = datetime.now(timezone.utc).strftime("%Y%m%d")
        return f"evt-{day}-{suffix}-{self._event_seq:05d}"

    def _global_allowlist(self, key: str) -> set[str]:
        values = self.policy.get("global_allowlists", {}).get(key, [])
        return {str(v).lower() for v in values}

    def _threshold(self, key: str, default: float | int) -> float | int:
        return self.policy.get("thresholds", {}).get(key, default)

    def _assets(self) -> list[dict]:
        return self.policy.get("assets", [])

    def _asset_for_ip(self, ip: str) -> dict | None:
        for asset in self._assets():
            addresses = asset.get("addresses", [])
            if ip in addresses:
                return asset
        return None

    def _relay_addresses(self) -> list[tuple[str, dict]]:
        relays: list[tuple[str, dict]] = []
        for asset in self._assets():
            for addr in asset.get("addresses", []):
                relays.append((addr, asset))
        return relays

    def evaluate_observation(self, obs: InventoryObservation) -> list[SecurityEvent]:
        events: list[SecurityEvent] = []
        mac = obs.src_mac
        src_ip = obs.src_ip
        dst_ip = obs.dst_ip
        dst_port = obs.dst_port

        if mac and self._enabled("OT-001"):
            mac_key = mac.lower()
            if mac_key not in self.inventory.known_macs:
                self.inventory.known_macs.add(mac_key)
                if mac_key not in self._global_allowlist("mac"):
                    events.append(self._event("OT-001", mac=mac))

        if src_ip and self._enabled("OT-002"):
            if src_ip not in self.inventory.known_ips:
                self.inventory.known_ips.add(src_ip)
                if src_ip.lower() not in self._global_allowlist("ip"):
                    events.append(self._event("OT-002", src_ip=src_ip))

        if mac and src_ip and self._enabled("OT-003"):
            mac_key = mac.lower()
            previous = self.inventory.mac_to_ip.get(mac_key)
            if previous and previous != src_ip:
                events.append(
                    self._event(
                        "OT-003",
                        mac=mac,
                        src_ip=src_ip,
                        evidence={"previous_ip": previous, "observed_ip": src_ip},
                        risk_score=85,
                    )
                )
            # Update only AFTER the comparison and with a case-normalised key so
            # repeated observations of the same MAC do not mask the change.
            self.inventory.mac_to_ip[mac_key] = src_ip

        if src_ip and dst_ip and self._enabled("OT-004"):
            pair = f"{src_ip}->{dst_ip}"
            if pair not in self.inventory.known_pairs:
                self.inventory.known_pairs.add(pair)
                allow_pairs = self._global_allowlist("communication_pairs")
                if pair.lower() not in allow_pairs:
                    events.append(
                        self._event("OT-004", src_ip=src_ip, dst_ip=dst_ip, evidence={"pair": pair})
                    )

        if dst_ip and dst_port is not None and self._enabled("OT-005"):
            port_key = f"{dst_ip}:{dst_port}"
            if port_key not in self.inventory.known_dst_ports:
                self.inventory.known_dst_ports.add(port_key)
                allowed_ports = self._global_allowlist("ports")
                if str(dst_port) not in allowed_ports and port_key.lower() not in allowed_ports:
                    events.append(
                        self._event(
                            "OT-005",
                            src_ip=src_ip or "",
                            dst_ip=dst_ip,
                            dst_port=dst_port,
                            evidence={"destination": port_key},
                        )
                    )

        if src_ip and dst_port is not None and self._enabled("OT-006"):
            self.inventory.record_port_scan_sample(src_ip, dst_port)
            window = float(self._threshold("port_scan_window_sec", 60))
            unique = self.inventory.unique_ports_in_window(src_ip, window)
            threshold = int(self._threshold("port_scan_unique_ports", 10))
            if len(unique) >= threshold and src_ip not in self.alerted_port_scan:
                self.alerted_port_scan.add(src_ip)
                events.append(
                    self._event(
                        "OT-006",
                        src_ip=src_ip,
                        evidence={
                            "unique_ports": sorted(unique),
                            "window_sec": window,
                            "threshold": threshold,
                        },
                        risk_score=88,
                    )
                )

        if src_ip and dst_ip and self._enabled("OT-010"):
            asset = self._asset_for_ip(dst_ip)
            if asset:
                allowed = {p for p in asset.get("allowed_peers", [])}
                pair = f"{src_ip}->{dst_ip}"
                if src_ip not in allowed and pair not in self.alerted_unauthorized:
                    self.alerted_unauthorized.add(pair)
                    events.append(
                        self._event(
                            "OT-010",
                            src_ip=src_ip,
                            dst_ip=dst_ip,
                            dst_port=dst_port,
                            asset_id=str(asset.get("asset_id", "")),
                            evidence={"relay_ip": dst_ip},
                            risk_score=90,
                        )
                    )

        return events

    def evaluate_arp(self, sender_mac: str, sender_ip: str) -> list[SecurityEvent]:
        """OT-002 / OT-003 via ARP — the (sender_ip -> sender_mac) binding.

        ARP carries the IP that the L2/L3 observation path misses (an ARP frame
        has no IP layer), so this is where ARP-spoofing flips are caught: when an
        IP that was previously bound to one MAC is suddenly announced by another.
        """
        events: list[SecurityEvent] = []
        if not sender_mac or not sender_ip:
            return events
        mac_key = sender_mac.lower()

        if self._enabled("OT-002") and sender_ip not in self.inventory.known_ips:
            self.inventory.known_ips.add(sender_ip)
            if sender_ip.lower() not in self._global_allowlist("ip"):
                events.append(self._event("OT-002", src_ip=sender_ip))

        if self._enabled("OT-003"):
            previous = self.inventory.ip_to_mac.get(sender_ip)
            if previous and previous != mac_key:
                events.append(
                    self._event(
                        "OT-003",
                        mac=sender_mac,
                        src_ip=sender_ip,
                        evidence={
                            "ip": sender_ip,
                            "previous_mac": previous,
                            "observed_mac": mac_key,
                            "indicator": "arp_spoofing",
                        },
                        risk_score=92,
                    )
                )
            self.inventory.ip_to_mac[sender_ip] = mac_key

        return events

    def evaluate_modbus(self, frame: ModbusFrame) -> list[SecurityEvent]:
        if not self._enabled("OT-007") or not frame.is_write:
            return []

        asset = self._asset_for_ip(frame.dst_ip)
        if asset is None:
            return []

        allowed_peers = set(asset.get("allowed_peers", []))
        allowed_fcs = set(asset.get("allowed_modbus_function_codes", []))
        if frame.src_ip in allowed_peers and (
            not allowed_fcs or frame.function_code in allowed_fcs
        ):
            return []

        return [
            self._event(
                "OT-007",
                src_ip=frame.src_ip,
                dst_ip=frame.dst_ip,
                dst_port=frame.dst_port,
                asset_id=str(asset.get("asset_id", "")),
                protocol="modbus-tcp",
                evidence={
                    "function_code": frame.function_code,
                    "unit_id": frame.unit_id,
                    "baseline_write_count_per_hour": asset.get("normal_write_count_per_hour", 0),
                },
                risk_score=86,
            )
        ]

    def evaluate_window(self, window_sec: int) -> list[SecurityEvent]:
        events: list[SecurityEvent] = []
        if self._enabled("OT-008"):
            events.extend(self._check_traffic_rate(window_sec))
        if self._enabled("OT-009"):
            events.extend(self._check_relay_offline())
        self.inventory.reset_window()
        return events

    def _check_traffic_rate(self, window_sec: int) -> list[SecurityEvent]:
        events: list[SecurityEvent] = []
        multiplier = float(self._threshold("traffic_rate_multiplier", 3.0))
        observed_per_min = self.inventory.window_packet_count * (60.0 / max(window_sec, 1))

        for asset in self._assets():
            rate_cfg = asset.get("normal_packet_rate_per_min", {})
            max_rate = rate_cfg.get("max")
            if max_rate is None:
                continue
            if observed_per_min <= float(max_rate) * multiplier:
                continue
            events.append(
                self._event(
                    "OT-008",
                    asset_id=str(asset.get("asset_id", "")),
                    evidence={
                        "observed_packets_per_min": round(observed_per_min, 1),
                        "baseline_max_per_min": max_rate,
                        "multiplier": multiplier,
                        "window_sec": window_sec,
                    },
                )
            )
        return events

    def _check_relay_offline(self, silence_sec: float = 120.0) -> list[SecurityEvent]:
        events: list[SecurityEvent] = []
        now = time.time()
        uptime = now - self._started_at
        if uptime < silence_sec:
            return events

        for address, asset in self._relay_addresses():
            asset_id = str(asset.get("asset_id", address))
            if asset_id in self.alerted_offline:
                continue
            last_seen = self.inventory.last_seen_by_ip.get(address)
            if last_seen is not None and (now - last_seen) < silence_sec:
                continue
            self.alerted_offline.add(asset_id)
            events.append(
                self._event(
                    "OT-009",
                    asset_id=asset_id,
                    dst_ip=address,
                    evidence={
                        "relay_ip": address,
                        "silence_sec": silence_sec,
                        "last_seen_epoch": last_seen,
                    },
                    risk_score=88,
                )
            )
        return events

    def _event(
        self,
        rule_id: str,
        *,
        src_ip: str = "",
        dst_ip: str = "",
        dst_port: int | None = None,
        asset_id: str = "",
        protocol: str = "passive",
        mac: str = "",
        evidence: dict | None = None,
        risk_score: int | None = None,
    ) -> SecurityEvent:
        event_type, severity, description = RULE_META[rule_id]
        payload = dict(evidence or {})
        if mac:
            payload.setdefault("mac", mac)
        return SecurityEvent(
            event_id=self._next_event_id(),
            site_id=self.site_id,
            sensor_id=self.sensor_id,
            event_type=event_type,
            severity=severity,
            rule_id=rule_id,
            protocol=protocol,
            description=description,
            asset_id=asset_id,
            src_ip=src_ip,
            dst_ip=dst_ip,
            dst_port=dst_port,
            risk_score=risk_score if risk_score is not None else 70,
            evidence=payload,
            timestamp=utc_now_iso(),
        )
