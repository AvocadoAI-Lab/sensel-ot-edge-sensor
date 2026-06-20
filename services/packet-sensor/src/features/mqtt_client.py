"""Shared MQTT client for feature summary publishing."""

from __future__ import annotations

import json
import logging
from typing import Any

logger = logging.getLogger(__name__)


class MqttPublisher:
    def __init__(
        self,
        host: str,
        port: int,
        client_id: str,
    ) -> None:
        self._host = host
        self._port = port
        self._client_id = client_id
        self._client = None

    @property
    def enabled(self) -> bool:
        return bool(self._host)

    def _ensure_client(self):
        if not self.enabled:
            return None
        if self._client is None:
            try:
                import paho.mqtt.client as mqtt

                self._client = mqtt.Client(
                    mqtt.CallbackAPIVersion.VERSION2,
                    client_id=self._client_id,
                )
                self._client.connect(self._host, self._port, keepalive=30)
                self._client.loop_start()
            except Exception:
                logger.exception("MQTT connect failed")
                self._client = None
        return self._client

    def publish_json(self, topic: str, payload: dict[str, Any]) -> bool:
        client = self._ensure_client()
        if client is None:
            return False
        try:
            client.publish(topic, json.dumps(payload), qos=0)
            return True
        except Exception:
            logger.exception("MQTT publish failed for %s", topic)
            return False

    def close(self) -> None:
        if self._client is not None:
            try:
                self._client.loop_stop()
                self._client.disconnect()
            except Exception:
                logger.exception("MQTT disconnect failed")
            self._client = None
