"""Packet processing pipeline — L2/L3/L4 + MVP + IEC 61850."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field

from src.detection.iec61850 import Iec61850Detector
from src.detection.mvp import MvpDetector
from src.events.generator import EventStore
from src.evidence.ring_buffer import PcapRingBuffer
from src.features.publisher import FeaturePublisher
from src.parser.l2.ethernet import L2Stats, parse_ethernet, record_l2, reset_l2_window
from src.parser.l3.ip import L3Stats, parse_ip, record_l3
from src.parser.l4.transport import parse_transport
from src.parser.l7.iec61850.goose import GooseStats, parse_goose_packet, record_goose
from src.parser.l7.iec61850.mms import MmsStats, parse_mms_packet, record_mms
from src.parser.l7.modbus.tcp import parse_modbus_tcp
from src.policy.loader import load_policy

logger = logging.getLogger(__name__)


@dataclass
class PipelineState:
    l2: L2Stats = field(default_factory=L2Stats)
    l3: L3Stats = field(default_factory=L3Stats)
    goose: GooseStats = field(default_factory=GooseStats)
    mms: MmsStats = field(default_factory=MmsStats)


class PacketPipeline:
    def __init__(
        self,
        sensor_id: str,
        site_id: str,
        policy_path: str,
        assets_dir: str,
        rules_enabled: list[str] | None = None,
        mqtt_host: str = "",
        mqtt_port: int = 1883,
        topic_prefix: str = "sensel/ot",
        edgex_device_name: str = "packet-sensor-features",
        edgex_data_topic: str = "",
        feature_window_sec: int = 60,
        ring_buffer_max_packets: int = 5000,
    ) -> None:
        self.state = PipelineState()
        self._feature_window_sec = feature_window_sec
        policy = load_policy(policy_path)
        enabled = set(rules_enabled or [])
        self._mvp = MvpDetector(
            site_id=site_id,
            sensor_id=sensor_id,
            policy=policy,
            rules_enabled=enabled,
        )
        self._detector = Iec61850Detector(
            site_id=site_id,
            sensor_id=sensor_id,
            policy=policy,
        )
        self._ring = PcapRingBuffer(max_packets=ring_buffer_max_packets)
        self._events = EventStore(assets_dir)
        self._features = FeaturePublisher(
            sensor_id=sensor_id,
            site_id=site_id,
            output_dir=assets_dir,
            mqtt_host=mqtt_host,
            mqtt_port=mqtt_port,
            topic_prefix=topic_prefix,
            edgex_device_name=edgex_device_name,
            edgex_data_topic=edgex_data_topic,
        )

    def _emit(self, events) -> None:
        for event in events:
            self._events.append(event, ring_buffer=self._ring)
            logger.warning(
                "Security event %s (%s): %s",
                event.rule_id,
                event.event_type,
                event.description,
            )

    def process(self, packet) -> None:
        try:
            packet_bytes = bytes(packet)
        except Exception:
            packet_bytes = b""
        if packet_bytes:
            self._ring.append(packet_bytes)

        src_mac, _ = parse_ethernet(packet)
        record_l2(self.state.l2, src_mac)
        src_ip, dst_ip, version = parse_ip(packet)
        record_l3(self.state.l3, src_ip, version)

        flow = parse_transport(packet)
        obs = self._mvp.inventory.observe(
            src_mac=src_mac,
            src_ip=src_ip,
            dst_ip=dst_ip,
            dst_port=flow.dst_port if flow else None,
            protocol=flow.protocol if flow else None,
        )
        self._emit(self._mvp.evaluate_observation(obs))

        modbus = parse_modbus_tcp(packet)
        if modbus:
            self._emit(self._mvp.evaluate_modbus(modbus))

        goose = parse_goose_packet(packet)
        if goose:
            record_goose(self.state.goose, goose)
            self._emit(self._detector.evaluate_goose(goose))

        mms = parse_mms_packet(packet)
        if mms:
            record_mms(self.state.mms, mms)
            self._emit(self._detector.evaluate_mms(mms))

    def flush_features(self) -> None:
        self._emit(self._mvp.evaluate_window(self._feature_window_sec))
        self._features.publish_window(
            self.state.l2,
            self._feature_window_sec,
            self.state.goose,
            self.state.mms,
        )
        reset_l2_window(self.state.l2)

    def close(self) -> None:
        self._features.close()

    @property
    def event_store(self) -> EventStore:
        return self._events

    @property
    def ring_buffer(self) -> PcapRingBuffer:
        return self._ring
