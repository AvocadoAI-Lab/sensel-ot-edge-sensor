"""Mirror NIC capture — Scapy or AF_XDP backend, IEC 61850 pipeline."""

from __future__ import annotations

import logging
import os
import time
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Callable

from scapy.all import Ether, IP, IPv6, TCP, sniff
from scapy.interfaces import ifaces

from src.capture.xdp_reader import XdpCaptureSession, try_open_xdp_session
from src.config.settings import AppConfig
from src.pipeline.processor import PacketPipeline

logger = logging.getLogger(__name__)

_RECENT_PACKET_LIMIT = 40


def _packet_summary(packet) -> dict:
    try:
        raw = bytes(packet)
    except Exception:
        return {"size": 0, "proto": "unknown", "src_mac": None, "src_ip": None, "dst_ip": None}

    size = len(raw)
    src_mac = None
    src_ip = None
    dst_ip = None
    proto = "L2"

    try:
        eth = Ether(raw)
        src_mac = eth.src
        if eth.type == 0x88B8:
            return {
                "size": size,
                "proto": "GOOSE",
                "src_mac": src_mac,
                "src_ip": None,
                "dst_ip": None,
            }
    except Exception:
        eth = None

    if eth is not None:
        try:
            if IP in eth:
                ip = eth[IP]
                src_ip = ip.src
                dst_ip = ip.dst
                proto = f"IPv4/{ip.proto}"
                if TCP in eth and eth[TCP].dport == 102:
                    proto = "MMS"
            elif IPv6 in eth:
                ip6 = eth[IPv6]
                src_ip = ip6.src
                dst_ip = ip6.dst
                proto = "IPv6"
        except Exception:
            pass

    return {
        "size": size,
        "proto": proto,
        "src_mac": src_mac,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
    }


@dataclass
class CaptureStats:
    started_at: float = field(default_factory=time.monotonic)
    last_packet_at: float | None = None


class CaptureSession:
    def __init__(self, config: AppConfig) -> None:
        self._config = config
        self.stats = CaptureStats()
        self._recent_packets: deque[dict] = deque(maxlen=_RECENT_PACKET_LIMIT)
        self._backend_active = "scapy"
        self._xdp: XdpCaptureSession | None = None
        self.pipeline = PacketPipeline(
            sensor_id=config.sensor.id,
            site_id=config.sensor.site_id,
            policy_path=config.detection.policy_file,
            assets_dir=config.features.assets_dir,
            rules_enabled=config.detection.rules_enabled,
            mqtt_host=config.features.mqtt.host,
            mqtt_port=config.features.mqtt.port,
            topic_prefix=config.features.mqtt.topic_prefix,
            edgex_device_name=config.features.mqtt.edgex_device_name,
            edgex_data_topic=config.features.mqtt.edgex_data_topic,
            feature_window_sec=config.features.window_sec,
            ioc_enabled=config.ioc.enabled,
            ioc_cache_path=config.ioc.cache_path,
            ioc_stamp_path=config.ioc.stamp_path,
            ioc_cooldown_sec=config.ioc.cooldown_sec,
            ioc_reload_check_sec=config.ioc.reload_check_sec,
            detection_policy_path=config.detection.policy_path,
            detection_policy_stamp_path=config.detection.policy_stamp_path,
            detection_policy_reload_sec=config.detection.reload_check_sec,
            coverage_enabled=os.environ.get("COVERAGE_COUNTER_ENABLED", "true").strip().lower()
            not in ("0", "false", "no", "off"),
        )

    @property
    def capture_backend(self) -> str:
        return self._backend_active

    def _validate_interface(self) -> None:
        available = {iface.name for iface in ifaces.values()}
        iface = self._config.capture.interface
        if iface not in available:
            logger.warning(
                "Interface %s not found (available: %s)",
                iface,
                ", ".join(sorted(available)) or "none",
            )

    def _handle_packet(self, packet) -> None:
        self.stats.last_packet_at = time.monotonic()
        summary = _packet_summary(packet)
        summary["at"] = datetime.now(timezone.utc).strftime("%H:%M:%S")
        self._recent_packets.appendleft(summary)
        self.pipeline.process(packet)

    def _run_scapy(self, should_stop: Callable[[], bool]) -> None:
        capture = self._config.capture
        self._backend_active = "scapy"
        logger.info(
            "Capture backend=scapy iface=%s promisc=%s bpf=%r",
            capture.interface,
            capture.promiscuous,
            capture.bpf_filter or "",
        )

        def stop_filter(_packet) -> bool:
            return should_stop()

        sniff(
            iface=capture.interface,
            filter=capture.bpf_filter or None,
            prn=self._handle_packet,
            store=False,
            promisc=capture.promiscuous,
            stop_filter=stop_filter,
        )

    def _run_af_xdp(self, should_stop: Callable[[], bool]) -> None:
        capture = self._config.capture
        session = try_open_xdp_session(capture)
        if session is None:
            logger.warning(
                "CAPTURE_BACKEND=af_xdp unavailable; falling back to scapy"
            )
            self._run_scapy(should_stop)
            return

        self._xdp = session
        self._backend_active = session.backend_label
        try:
            session.run(self._handle_packet, should_stop)
        finally:
            session.close()
            self._xdp = None

    def run(self, should_stop: Callable[[], bool]) -> None:
        capture = self._config.capture
        self._validate_interface()
        logger.info(
            "Starting capture on %s backend=%s (promisc=%s bpf=%r ioc=%s)",
            capture.interface,
            capture.backend,
            capture.promiscuous,
            capture.bpf_filter or "",
            self._config.ioc.enabled,
        )

        if capture.backend == "af_xdp":
            self._run_af_xdp(should_stop)
        else:
            self._run_scapy(should_stop)

    def snapshot(self) -> dict:
        elapsed = max(time.monotonic() - self.stats.started_at, 1.0)
        state = self.pipeline.state
        total = state.l2.total
        ioc_entries = 0
        if self.pipeline._ioc is not None:
            ioc_entries = self.pipeline._ioc.cache.entry_count

        last_at = self.stats.last_packet_at
        idle_sec = round(time.monotonic() - last_at, 1) if last_at is not None else None
        top_macs = sorted(
            state.l2.window_mac_counts.items(),
            key=lambda item: -item[1],
        )[:8]
        top_ips = sorted(
            state.l3.src_ip_counts.items(),
            key=lambda item: -item[1],
        )[:8]

        capture = self._config.capture
        snap = {
            "capture_backend": self._backend_active,
            "capture_interface": capture.interface,
            "capture_bpf": capture.bpf_filter or "",
            "total_packets": total,
            "packet_rate": round(total / elapsed, 2),
            "window_packets": state.l2.window_total,
            "ipv4_packets": state.l3.ipv4,
            "ipv6_packets": state.l3.ipv6,
            "unique_macs": len(state.l2.mac_src_counts),
            "unique_ips": len(state.l3.src_ip_counts),
            "goose_messages": state.goose.message_count,
            "mms_writes": state.mms.write_count,
            "mms_reads": state.mms.read_count,
            "mms_sessions": len(state.mms.session_keys),
            "ioc_entries": ioc_entries,
            "elapsed_sec": round(elapsed, 1),
            "idle_sec": idle_sec,
            "top_macs": [{"mac": mac, "count": count} for mac, count in top_macs],
            "top_ips": [{"ip": ip, "count": count} for ip, count in top_ips],
            "recent_packets": list(self._recent_packets),
        }
        if self._xdp is not None:
            snap.update(self._xdp.snapshot())
        return snap

    def close(self) -> None:
        if self._xdp is not None:
            self._xdp.close()
            self._xdp = None
        self.pipeline.flush_features()
        self.pipeline.close()
