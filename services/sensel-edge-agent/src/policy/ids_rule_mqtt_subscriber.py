"""Subscribe to OT IDS-rule policy manifests and trigger an HTTP pull (D2).

The Control Plane publishes only a lightweight manifest (version + sha256 + url)
to ``sensel/{tenant}/policy/ids-rules-{engine}``. On receipt we resolve the
engine from the topic suffix and ask :class:`IdsRuleSync` to pull + apply the
signed bundle over HTTP. Mirrors ``DetectionPolicyMqttSubscriber``.
"""

from __future__ import annotations

import json
import logging
import threading
import uuid

from src.config.settings import AppConfig
from src.policy.ids_rule_sync import SUPPORTED_ENGINES, IdsRuleSync

logger = logging.getLogger(__name__)


class IdsRuleMqttSubscriber:
    """Background subscriber for sensel/{tenant_id}/policy/ids-rules-{engine}."""

    def __init__(self, config: AppConfig, sync: IdsRuleSync) -> None:
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
            and ps.ids_rule_mqtt_enabled
        )

    @property
    def connected(self) -> bool:
        return self._connected

    def _topic_for_tenant(self, tenant_id: str) -> str:
        return self._config.policy_sync.ids_rule_mqtt_topic_template.format(tenant_id=tenant_id)

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

    @staticmethod
    def _engine_from_topic(topic: str) -> str | None:
        leaf = topic.rsplit("/", 1)[-1]  # e.g. ids-rules-suricata
        if leaf.startswith("ids-rules-"):
            engine = leaf[len("ids-rules-"):].strip().lower()
            if engine in SUPPORTED_ENGINES:
                return engine
        return None

    def _on_connect(self, client, userdata, flags, reason_code, properties=None) -> None:
        if reason_code != 0:
            logger.warning("IDS rule MQTT connect failed rc=%s", reason_code)
            self._connected = False
            return
        self._connected = True
        tenant_id = self._resolve_tenant_id()
        if not tenant_id:
            logger.warning("IDS rule MQTT connected but tenant unresolved")
            return
        topic = self._topic_for_tenant(tenant_id)
        qos = self._config.policy_sync.mqtt_qos
        client.subscribe(topic, qos=qos)
        self._topic = topic
        logger.info("IDS rule MQTT subscribed topic=%s qos=%s", topic, qos)

    def _on_disconnect(self, client, userdata, disconnect_flags, reason_code, properties=None) -> None:
        self._connected = False
        logger.warning("IDS rule MQTT disconnected rc=%s", reason_code)

    def _on_message(self, client, userdata, message) -> None:
        topic = getattr(message, "topic", "") or ""
        engine = self._engine_from_topic(topic)
        if not engine:
            logger.debug("IDS rule MQTT ignoring topic without engine suffix: %s", topic)
            return
        # Manifest body is advisory only; the signed artifact is fetched over HTTP.
        try:
            json.loads(message.payload.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            logger.debug("IDS rule MQTT manifest not JSON on %s (continuing pull)", topic)

        result = self._sync.pull_http_feed(engine)
        if result.ok and result.changed:
            self._messages += 1
            logger.info(
                "IDS rule MQTT applied engine=%s tenant=%s version=%s rules=%s",
                result.engine, result.tenant_id, result.version, result.rule_count,
            )
        elif not result.ok:
            logger.warning(
                "IDS rule MQTT pull failed engine=%s rolled_back=%s: %s",
                result.engine, result.rolled_back, result.error,
            )

    def start(self) -> bool:
        if not self.enabled:
            return False
        with self._lock:
            if self._client is not None:
                return self._connected

            tenant_id = self._resolve_tenant_id()
            if not tenant_id:
                logger.warning("IDS rule MQTT subscribe skipped: tenant unresolved")
                return False

            try:
                import paho.mqtt.client as mqtt
            except ImportError:
                logger.error("paho-mqtt required for IDS rule MQTT subscriber")
                return False

            ps = self._config.policy_sync
            client_id = f"ot-edge-idsrule-{self._config.sensor.id}-{uuid.uuid4().hex[:8]}"
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
                    "IDS rule MQTT connect failed host=%s port=%s", ps.mqtt_host, ps.mqtt_port
                )
                return False

            client.loop_start()
            self._client = client
            logger.info(
                "IDS rule MQTT client started host=%s port=%s tenant=%s",
                ps.mqtt_host, ps.mqtt_port, tenant_id,
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
                logger.exception("IDS rule MQTT stop failed")
            self._client = None
            self._connected = False
            self._topic = ""
