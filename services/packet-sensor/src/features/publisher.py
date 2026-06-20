"""Feature summary publishing — EdgeX device-mqtt bridge + SenseL topics."""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from src.features.mqtt_client import MqttPublisher
from src.parser.l2.ethernet import L2Stats
from src.parser.l7.iec61850.goose import GooseStats
from src.parser.l7.iec61850.mms import MmsStats

logger = logging.getLogger(__name__)


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


class FeaturePublisher:
    """Publishes windowed summaries to disk, SenseL MQTT topics, and EdgeX DataTopic."""

    def __init__(
        self,
        sensor_id: str,
        site_id: str,
        output_dir: str,
        mqtt_host: str = "",
        mqtt_port: int = 1883,
        topic_prefix: str = "sensel/ot",
        edgex_device_name: str = "packet-sensor-features",
        edgex_data_topic: str = "",
    ) -> None:
        self._sensor_id = sensor_id
        self._site_id = site_id
        self._output_dir = Path(output_dir)
        self._output_dir.mkdir(parents=True, exist_ok=True)
        self._topic_prefix = topic_prefix.rstrip("/")
        self._edgex_device_name = edgex_device_name
        self._edgex_data_topic = edgex_data_topic or (
            f"incoming/data/{edgex_device_name}/FeatureSummary"
        )
        self._mqtt = MqttPublisher(
            host=mqtt_host,
            port=mqtt_port,
            client_id=f"packet-sensor-{sensor_id}",
        )

    def publish_window(
        self,
        l2: L2Stats,
        window_sec: int,
        goose: GooseStats | None = None,
        mms: MmsStats | None = None,
    ) -> dict[str, Any]:
        packet_rate = round(l2.window_total / max(window_sec, 1), 2)
        unique_macs = len(l2.window_mac_counts)

        summary: dict[str, Any] = {
            "sensor_id": self._sensor_id,
            "site_id": self._site_id,
            "window": f"{window_sec}s",
            "protocol": "aggregate",
            "packet_count": l2.window_total,
            "packet_rate": packet_rate,
            "unique_mac_count": unique_macs,
            "timestamp": _utc_now_iso(),
        }
        if goose and goose.message_count:
            summary["goose_message_count"] = goose.message_count
            summary["goose_unique_publishers"] = len(goose.publishers)
        if mms and (mms.read_count or mms.write_count or mms.session_keys):
            summary["mms_write_count"] = mms.write_count
            summary["mms_read_count"] = mms.read_count

        self._write("feature-summary.json", summary)
        self._publish_sensel(f"features/summary", summary)
        self._publish_edgex_feature_summary(packet_rate, unique_macs)

        if goose and goose.message_count:
            self.publish_goose(goose, window=f"{window_sec}s")
        if mms and (mms.read_count or mms.write_count or mms.session_keys):
            self.publish_mms(mms, window=f"{window_sec}s")

        return summary

    def publish_goose(self, stats: GooseStats, window: str = "60s") -> dict:
        summary = {
            "sensor_id": self._sensor_id,
            "site_id": self._site_id,
            "window": window,
            "protocol": "iec61850-goose",
            "goose_message_count": stats.message_count,
            "goose_stnum_changes": stats.stnum_changes,
            "goose_test_flag_count": stats.test_flag_count,
            "goose_unique_publishers": len(stats.publishers),
            "timestamp": _utc_now_iso(),
        }
        if stats.publishers:
            first = next(iter(stats.publishers.values()))
            summary["goose_appid"] = first.appid
            summary["goose_gocb_ref"] = first.gocb_ref
            summary["goose_publisher_mac"] = first.publisher_mac
        self._write("iec61850-goose-summary.json", summary)
        self._publish_sensel("features/iec61850/goose", summary)
        return summary

    def publish_mms(self, stats: MmsStats, window: str = "60s") -> dict:
        summary = {
            "sensor_id": self._sensor_id,
            "site_id": self._site_id,
            "window": window,
            "protocol": "iec61850-mms",
            "mms_session_count": len(stats.session_keys),
            "mms_read_count": stats.read_count,
            "mms_write_count": stats.write_count,
            "mms_report_count": stats.report_count,
            "timestamp": _utc_now_iso(),
        }
        if stats.observations:
            obs = stats.observations[-1]
            summary["ied_address"] = obs.dst_ip if obs.dst_port == 102 else obs.src_ip
            summary["src_ip"] = obs.src_ip
            summary["dst_ip"] = obs.dst_ip
            summary["port"] = 102
        self._write("iec61850-mms-summary.json", summary)
        self._publish_sensel("features/iec61850/mms", summary)
        return summary

    def _publish_edgex_feature_summary(
        self,
        packet_rate: float,
        unique_macs: int,
    ) -> None:
        """EdgeX device-mqtt multi-level async topic (S1-03)."""
        payload = {
            "PacketRate": packet_rate,
            "UniqueMacCount": unique_macs,
        }
        if self._mqtt.publish_json(self._edgex_data_topic, payload):
            logger.info(
                "EdgeX feature summary → %s (PacketRate=%s UniqueMacCount=%s)",
                self._edgex_data_topic,
                packet_rate,
                unique_macs,
            )

    def _publish_sensel(self, suffix: str, payload: dict) -> None:
        topic = f"{self._topic_prefix}/{self._sensor_id}/{suffix}"
        self._mqtt.publish_json(topic, payload)

    def _write(self, filename: str, payload: dict) -> None:
        path = self._output_dir / filename
        path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    def close(self) -> None:
        self._mqtt.close()
