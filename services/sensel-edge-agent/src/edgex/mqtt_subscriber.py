"""MQTT v5 subscriber for retained Tier 3 desired device state commands."""

from __future__ import annotations

import logging
import threading
import uuid
from typing import Callable

from sensel.device.v1 import device_management_pb2

from src.config.settings import AppConfig
from src.edgex.state import InvalidDesiredDeviceCommand, decode_desired_command
from src.northbound.topics import desired_device_state_topic

logger = logging.getLogger(__name__)

_CONTENT_TYPE = (
    "application/x-protobuf; message=sensel.device.v1.DesiredDeviceStateCommand"
)


class DesiredDeviceStateSubscriber:
    def __init__(
        self,
        config: AppConfig,
        handler: Callable[[device_management_pb2.DesiredDeviceStateCommand], bool],
    ) -> None:
        self.config = config
        self.handler = handler
        self._client = None
        self._topic = ""
        self._connected = False
        self._lock = threading.Lock()
        self.accepted = 0
        self.rejected = 0

    @property
    def enabled(self) -> bool:
        configured = bool(
            self.config.edgex_device_management.enabled
            and self.config.edgex_device_management.desired_mqtt_enabled
            and self.config.northbound_mqtt.enabled
            and self.config.northbound_mqtt.host
        )
        if not configured:
            return False
        return not (
            self.config.northbound_mqtt.require_tenant
            and self._tenant_id() in {"", "default"}
        )

    @property
    def connected(self) -> bool:
        return self._connected

    def _tenant_id(self) -> str:
        return self.config.northbound_mqtt.tenant_id.strip()

    def _desired_topic(self) -> str:
        return desired_device_state_topic(
            self._tenant_id(),
            self.config.sensor.site_id,
            self.config.sensor.id,
        )

    def _on_connect(self, client, userdata, flags, reason_code, properties=None) -> None:
        if getattr(reason_code, "is_failure", False) or (
            isinstance(reason_code, int) and reason_code != 0
        ):
            self._connected = False
            logger.warning("EdgeX desired MQTT connect refused rc=%s", reason_code)
            return
        self._connected = True
        topic = self._desired_topic()
        client.subscribe(topic, qos=1)
        self._topic = topic
        logger.info("EdgeX desired MQTT subscribed topic=%s", topic)

    def _on_disconnect(
        self, client, userdata, disconnect_flags, reason_code, properties=None
    ) -> None:
        self._connected = False
        logger.warning("EdgeX desired MQTT disconnected rc=%s", reason_code)

    def _on_message(self, client, userdata, message) -> None:
        properties = getattr(message, "properties", None)
        content_type = str(getattr(properties, "ContentType", "") or "")
        payload_format = getattr(properties, "PayloadFormatIndicator", None)
        if content_type != _CONTENT_TYPE or payload_format not in (None, 0):
            self.rejected += 1
            logger.warning(
                "Rejected EdgeX desired command content-type=%s pfi=%s",
                content_type,
                payload_format,
            )
            return
        try:
            command = decode_desired_command(
                bytes(message.payload),
                tenant_id=self._tenant_id(),
                site_id=self.config.sensor.site_id,
                sensor_id=self.config.sensor.id,
            )
            if self.handler(command):
                self.accepted += 1
        except InvalidDesiredDeviceCommand as exc:
            self.rejected += 1
            logger.warning("Rejected EdgeX desired command: %s", exc)
        except Exception:
            logger.exception("Failed to persist EdgeX desired command")

    def start(self) -> bool:
        if not self.enabled:
            return False
        with self._lock:
            if self._client is not None:
                return self._connected
            try:
                import paho.mqtt.client as mqtt

                nb = self.config.northbound_mqtt
                client = mqtt.Client(
                    mqtt.CallbackAPIVersion.VERSION2,
                    client_id=(
                        f"ot-edge-edgex-{self.config.sensor.id}-"
                        f"{uuid.uuid4().hex[:8]}"
                    ),
                    protocol=mqtt.MQTTv5,
                )
                if nb.username:
                    client.username_pw_set(nb.username, nb.password or None)
                if nb.tls:
                    if not nb.tls_cert_path or not nb.tls_key_path:
                        raise ValueError("EdgeX desired MQTT mTLS needs cert and key")
                    client.tls_set(
                        ca_certs=nb.tls_ca_path or None,
                        certfile=nb.tls_cert_path,
                        keyfile=nb.tls_key_path,
                    )
                    client.tls_insecure_set(nb.tls_insecure)
                client.on_connect = self._on_connect
                client.on_disconnect = self._on_disconnect
                client.on_message = self._on_message
                client.reconnect_delay_set(min_delay=2, max_delay=60)
                client.connect_async(nb.host, nb.port, keepalive=60)
                client.loop_start()
                self._client = client
                return True
            except Exception:
                logger.exception("EdgeX desired MQTT subscriber start failed")
                self._client = None
                return False

    def refresh_subscription(self) -> None:
        if self._client is None:
            self.start()
        if self._client is None or not self._connected:
            return
        topic = self._desired_topic()
        if topic == self._topic:
            return
        if self._topic:
            self._client.unsubscribe(self._topic)
        self._client.subscribe(topic, qos=1)
        self._topic = topic

    def stop(self) -> None:
        with self._lock:
            client = self._client
            self._client = None
            if client is None:
                return
            try:
                if self._topic:
                    client.unsubscribe(self._topic)
                client.loop_stop()
                client.disconnect()
            except Exception:
                logger.exception("EdgeX desired MQTT subscriber stop failed")
            self._connected = False
            self._topic = ""
