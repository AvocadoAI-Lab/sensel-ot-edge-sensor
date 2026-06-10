"""Subscribe to Portal OT detection policy MQTT topic (Track B / policy path B)."""

from __future__ import annotations

import json
import logging
import threading
import uuid

from src.config.settings import AppConfig
from src.policy.detection_policy_sync import DetectionPolicySync

logger = logging.getLogger(__name__)


class DetectionPolicyMqttSubscriber:
    """Background subscriber for sensel/{tenant_id}/policy/ot-detection."""

    def __init__(self, config: AppConfig, sync: DetectionPolicySync) -> None:
        self._config = config
        self._sync = sync
        self._client = None
        self._topic = ""
        self._lock = threading.Lock()
        self._connected = False
        self._messages = 0

    @property
    def enabled(self) -> bool:
        ps = self._config.policy_sync
        return bool(
            self._sync.enabled
            and ps.mqtt_enabled
            and ps.mqtt_host
            and ps.detection_policy_mqtt_enabled
        )

    @property
    def connected(self) -> bool:
        return self._connected

    def _topic_for_tenant(self, tenant_id: str) -> str:
        return self._config.policy_sync.detection_policy_mqtt_topic_template.format(
            tenant_id=tenant_id
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
            logger.warning("Detection policy MQTT connect failed rc=%s", reason_code)
            self._connected = False
            return
        self._connected = True
        tenant_id = self._resolve_tenant_id()
        if not tenant_id:
            logger.warning("Detection policy MQTT connected but tenant unresolved")
            return
        topic = self._topic_for_tenant(tenant_id)
        qos = self._config.policy_sync.mqtt_qos
        client.subscribe(topic, qos=qos)
        self._topic = topic
        logger.info("Detection policy MQTT subscribed topic=%s qos=%s", topic, qos)

    def _on_disconnect(self, client, userdata, disconnect_flags, reason_code, properties=None) -> None:
        self._connected = False
        logger.warning("Detection policy MQTT disconnected rc=%s", reason_code)

    def _on_message(self, client, userdata, message) -> None:
        topic = getattr(message, "topic", "") or ""
        try:
            artifact = json.loads(message.payload.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            logger.warning("Detection policy MQTT invalid payload on %s: %s", topic, exc)
            return
        if not isinstance(artifact, dict):
            logger.warning("Detection policy MQTT payload is not an object on %s", topic)
            return

        tenant_id = str(artifact.get("tenant_id") or "").strip()
        if not tenant_id:
            parts = topic.split("/")
            if len(parts) >= 2 and parts[0] == "sensel":
                tenant_id = parts[1]
        if not tenant_id:
            tenant_id = self._resolve_tenant_id() or ""

        result = self._sync.apply_artifact(artifact, tenant_id=tenant_id, source="mqtt")
        if result.ok and result.changed:
            self._messages += 1
            logger.info(
                "Detection policy MQTT applied tenant=%s site=%s version=%s topic=%s",
                result.tenant_id,
                result.site_id or "-",
                result.version,
                topic,
            )
        elif not result.ok:
            logger.warning("Detection policy MQTT apply failed: %s", result.error)

    def start(self) -> bool:
        if not self.enabled:
            return False
        with self._lock:
            if self._client is not None:
                return self._connected

            tenant_id = self._resolve_tenant_id()
            if not tenant_id:
                logger.warning("Detection policy MQTT subscribe skipped: tenant unresolved")
                return False

            try:
                import paho.mqtt.client as mqtt
            except ImportError:
                logger.error("paho-mqtt required for detection policy MQTT subscriber")
                return False

            ps = self._config.policy_sync
            client_id = f"ot-edge-detpol-{self._config.sensor.id}-{uuid.uuid4().hex[:8]}"
            client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id=client_id)
            if ps.mqtt_username:
                client.username_pw_set(ps.mqtt_username, ps.mqtt_password or None)
            client.on_connect = self._on_connect
            client.on_disconnect = self._on_disconnect
            client.on_message = self._on_message

            try:
                client.reconnect_delay_set(min_delay=2, max_delay=60)
                client.connect(ps.mqtt_host, ps.mqtt_port, keepalive=60)
            except Exception:
                logger.exception(
                    "Detection policy MQTT connect failed host=%s port=%s",
                    ps.mqtt_host,
                    ps.mqtt_port,
                )
                return False

            client.loop_start()
            self._client = client
            logger.info(
                "Detection policy MQTT client started host=%s port=%s tenant=%s",
                ps.mqtt_host,
                ps.mqtt_port,
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
                logger.exception("Detection policy MQTT stop failed")
            self._client = None
            self._connected = False
            self._topic = ""
