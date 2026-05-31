"""Northbound MQTT client — security events to Control Plane EMQX."""

from __future__ import annotations

import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Any

from src.config.settings import NorthboundMqttConfig, SensorIdentity
from src.northbound.topics import events_topic, state_topic

logger = logging.getLogger(__name__)


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


class NorthboundMqttClient:
    def __init__(self, mqtt_config: NorthboundMqttConfig, sensor: SensorIdentity) -> None:
        self._cfg = mqtt_config
        self._sensor = sensor
        self._client = None

    @property
    def enabled(self) -> bool:
        return self._cfg.enabled and bool(self._cfg.host)

    def update_tenant_id(self, tenant_id: str) -> None:
        tid = (tenant_id or "").strip()
        if tid:
            self._cfg.tenant_id = tid
            logger.info("Northbound MQTT tenant_id updated to %s", tid)

    def _ensure_client(self):
        if not self.enabled:
            return None
        if self._client is not None:
            return self._client
        try:
            import paho.mqtt.client as mqtt

            client_id = f"ot-edge-{self._sensor.id}-{uuid.uuid4().hex[:8]}"
            self._client = mqtt.Client(
                mqtt.CallbackAPIVersion.VERSION2,
                client_id=client_id,
            )
            if self._cfg.username:
                self._client.username_pw_set(self._cfg.username, self._cfg.password or None)
            self._client.connect(self._cfg.host, self._cfg.port, keepalive=60)
            self._client.loop_start()
            logger.info(
                "Northbound MQTT connected to %s:%s",
                self._cfg.host,
                self._cfg.port,
            )
        except Exception:
            logger.exception("Northbound MQTT connect failed")
            self._client = None
        return self._client

    def _envelope(self, message_type: str, payload: dict[str, Any], observed_at: str = "") -> dict:
        return {
            "schema_version": "1.0",
            "message_type": message_type,
            "tenant_id": self._cfg.tenant_id,
            "site_id": self._sensor.site_id,
            "sensor_id": self._sensor.id,
            "observed_at": observed_at or _utc_now_iso(),
            "mqtt_trace_id": str(uuid.uuid4()),
            "producer": {
                "type": "sensel-ot-edge-sensor",
                "version": self._sensor.software_version,
            },
            "payload": payload,
        }

    def publish_json(self, topic: str, body: dict[str, Any], qos: int | None = None) -> bool:
        client = self._ensure_client()
        if client is None:
            return False
        qos = self._cfg.qos_events if qos is None else qos
        try:
            info = client.publish(topic, json.dumps(body, ensure_ascii=False), qos=qos)
            info.wait_for_publish(timeout=10.0)
            if info.rc != 0 or (qos > 0 and not info.is_published()):
                logger.warning("MQTT publish not confirmed topic=%s rc=%s", topic, info.rc)
                return False
            return True
        except Exception:
            logger.exception("MQTT publish failed topic=%s", topic)
            return False

    def publish_security_event(self, event: dict[str, Any]) -> bool:
        if self._cfg.require_tenant and (self._cfg.tenant_id or "").strip() in ("", "default"):
            logger.warning(
                "Skipping MQTT security event publish — tenant not bound (rule=%s)",
                event.get("rule_id"),
            )
            return False
        topic = events_topic(self._cfg.tenant_id, self._sensor.site_id, self._sensor.id)
        body = self._envelope(
            "security_event",
            event,
            observed_at=str(event.get("timestamp") or _utc_now_iso()),
        )
        ok = self.publish_json(topic, body)
        if ok:
            logger.info(
                "MQTT security event published — %s (%s)",
                event.get("rule_id"),
                event.get("event_type"),
            )
        return ok

    def publish_state(self, state: dict[str, Any]) -> bool:
        topic = state_topic(self._cfg.tenant_id, self._sensor.site_id, self._sensor.id)
        body = self._envelope("state", state)
        return self.publish_json(topic, body, qos=1)

    def close(self) -> None:
        if self._client is not None:
            try:
                self._client.loop_stop()
                self._client.disconnect()
            except Exception:
                logger.exception("Northbound MQTT disconnect failed")
            self._client = None
