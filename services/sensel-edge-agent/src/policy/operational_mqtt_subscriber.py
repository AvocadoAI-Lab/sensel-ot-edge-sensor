"""Subscribe to Portal operational mode MQTT commands."""

from __future__ import annotations

import json
import logging
import threading
import uuid

from src.config.settings import AppConfig
from src.policy.operational_mode_sync import OperationalModeSync

logger = logging.getLogger(__name__)


class OperationalModeMqttSubscriber:
    """Background subscriber for sensel/{tenant_id}/cmd/{sensor_id}/operational."""

    def __init__(self, config: AppConfig, sync: OperationalModeSync) -> None:
        self._config = config
        self._sync = sync
        self._client = None
        self._topic = ""
        self._lock = threading.Lock()
        self._connected = False
        self._messages = 0

    def _broker_config(self) -> tuple[str, int, str, str]:
        ps = self._config.policy_sync
        nb = self._config.northbound_mqtt
        host = (ps.mqtt_host or nb.host or "").strip()
        if ps.mqtt_host:
            port = ps.mqtt_port
        elif nb.host:
            port = nb.port
        else:
            port = ps.mqtt_port
        username = ps.mqtt_username or nb.username
        password = ps.mqtt_password or nb.password
        return host, port, username, password

    @property
    def enabled(self) -> bool:
        ps = self._config.policy_sync
        host, _, _, _ = self._broker_config()
        return bool(
            self._sync.enabled
            and ps.operational_mode_mqtt_enabled
            and host
        )

    @property
    def connected(self) -> bool:
        return self._connected

    def _topic_for(self, tenant_id: str) -> str:
        return self._config.policy_sync.operational_mode_mqtt_topic_template.format(
            tenant_id=tenant_id,
            sensor_id=self._config.sensor.id,
        )

    def _resolve_tenant_id(self) -> str | None:
        override = (self._config.policy_sync.feed_tenant_id or "").strip()
        if override:
            return override
        tenant = (self._config.northbound_mqtt.tenant_id or "").strip()
        if tenant and tenant != "default":
            return tenant
        if self._config.northbound_mqtt.require_tenant:
            return None
        return tenant or None

    def _on_connect(self, client, userdata, flags, reason_code, properties=None) -> None:
        if reason_code != 0:
            logger.warning("Operational mode MQTT connect failed rc=%s", reason_code)
            self._connected = False
            return
        self._connected = True
        tenant_id = self._resolve_tenant_id()
        if not tenant_id:
            logger.warning("Operational mode MQTT connected but tenant unresolved")
            return
        topic = self._topic_for(tenant_id)
        qos = self._config.policy_sync.mqtt_qos
        client.subscribe(topic, qos=qos)
        self._topic = topic
        logger.info("Operational mode MQTT subscribed topic=%s qos=%s", topic, qos)

    def _on_disconnect(self, client, userdata, disconnect_flags, reason_code, properties=None) -> None:
        self._connected = False
        logger.warning("Operational mode MQTT disconnected rc=%s", reason_code)

    def _on_message(self, client, userdata, message) -> None:
        topic = getattr(message, "topic", "") or ""
        try:
            artifact = json.loads(message.payload.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            logger.warning("Operational mode MQTT invalid payload on %s: %s", topic, exc)
            return
        if not isinstance(artifact, dict):
            logger.warning("Operational mode MQTT payload is not an object on %s", topic)
            return

        tenant_id = str(artifact.get("tenant_id") or "").strip()
        if not tenant_id:
            parts = topic.split("/")
            if len(parts) >= 2 and parts[0] == "sensel":
                tenant_id = parts[1]
        if not tenant_id:
            tenant_id = self._resolve_tenant_id() or ""

        payload_sensor = str(artifact.get("sensor_id") or "").strip()
        if payload_sensor and payload_sensor != self._config.sensor.id:
            logger.warning(
                "Operational mode MQTT ignored sensor mismatch payload=%s local=%s",
                payload_sensor,
                self._config.sensor.id,
            )
            return

        result = self._sync.apply_artifact(artifact, tenant_id=tenant_id, source="mqtt")
        if result.ok and result.changed:
            self._messages += 1
            logger.info(
                "Operational mode MQTT applied tenant=%s mode=%s session=%s topic=%s",
                result.tenant_id,
                result.mode,
                result.session_id or "-",
                topic,
            )
        elif not result.ok:
            logger.warning("Operational mode MQTT apply failed: %s", result.error)

    def start(self) -> bool:
        if not self.enabled:
            return False
        with self._lock:
            if self._client is not None:
                return self._connected

            tenant_id = self._resolve_tenant_id()
            if not tenant_id:
                logger.warning("Operational mode MQTT subscribe skipped: tenant unresolved")
                return False

            try:
                import paho.mqtt.client as mqtt
            except ImportError:
                logger.error("paho-mqtt required for operational mode MQTT subscriber")
                return False

            host, port, username, password = self._broker_config()
            client_id = f"ot-edge-opmode-{self._config.sensor.id}-{uuid.uuid4().hex[:8]}"
            client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id=client_id)
            if username:
                client.username_pw_set(username, password or None)
            client.on_connect = self._on_connect
            client.on_disconnect = self._on_disconnect
            client.on_message = self._on_message

            try:
                client.reconnect_delay_set(min_delay=2, max_delay=60)
                client.connect(host, port, keepalive=60)
            except Exception:
                logger.exception(
                    "Operational mode MQTT connect failed host=%s port=%s",
                    host,
                    port,
                )
                return False

            client.loop_start()
            self._client = client
            logger.info(
                "Operational mode MQTT client started host=%s port=%s tenant=%s",
                host,
                port,
                tenant_id,
            )
            return True

    def ensure_connected(self) -> bool:
        if not self.enabled:
            return False
        if self._client is not None and self._connected:
            return True
        return self.start()

    def stop(self) -> None:
        with self._lock:
            if self._client is None:
                return
            try:
                if self._topic:
                    self._client.unsubscribe(self._topic)
                self._client.loop_stop()
                self._client.disconnect()
            except Exception:
                logger.exception("Operational mode MQTT stop failed")
            self._client = None
            self._connected = False
            self._topic = ""
