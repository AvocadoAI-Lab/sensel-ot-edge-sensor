"""Mirror NIC capture — promiscuous mode, BPF, IEC 61850 pipeline."""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Callable

from scapy.all import sniff
from scapy.interfaces import ifaces

from src.config.settings import AppConfig
from src.pipeline.processor import PacketPipeline

logger = logging.getLogger(__name__)


@dataclass
class CaptureStats:
    started_at: float = field(default_factory=time.monotonic)
    last_packet_at: float | None = None


class CaptureSession:
    def __init__(self, config: AppConfig) -> None:
        self._config = config
        self.stats = CaptureStats()
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
            ring_buffer_max_packets=config.pcap.ring_buffer_max_packets,
            ring_buffer_dir=config.pcap.ring_buffer_path,
            pcap_retention_sec=config.pcap.retention_minutes * 60,
            pcap_max_disk_bytes=config.pcap.max_disk_mb * 1024 * 1024,
            state_db=config.detection.state_db,
            mode=config.detection.mode,
        )

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
        self.pipeline.process(packet)

    def run(self, should_stop: Callable[[], bool]) -> None:
        capture = self._config.capture
        self._validate_interface()
        logger.info(
            "Starting capture on %s (promisc=%s bpf=%r)",
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

    def snapshot(self) -> dict:
        elapsed = max(time.monotonic() - self.stats.started_at, 1.0)
        state = self.pipeline.state
        total = state.l2.total
        return {
            "total_packets": total,
            "packet_rate": round(total / elapsed, 2),
            "ipv4_packets": state.l3.ipv4,
            "ipv6_packets": state.l3.ipv6,
            "unique_macs": len(state.l2.mac_src_counts),
            "unique_ips": len(state.l3.src_ip_counts),
            "goose_messages": state.goose.message_count,
            "mms_writes": state.mms.write_count,
            "mms_sessions": len(state.mms.session_keys),
            "elapsed_sec": round(elapsed, 1),
        }

    def close(self) -> None:
        self.pipeline.flush_features()
        self.pipeline.close()
