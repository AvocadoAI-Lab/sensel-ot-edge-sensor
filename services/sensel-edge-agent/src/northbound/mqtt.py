<<<<<<< Updated upstream
"""Northbound MQTT client — security events to Control Plane EMQX."""

from __future__ import annotations

import json
import logging
import threading
import uuid
from datetime import datetime, timezone
from typing import Any, Optional

from src.config.settings import NorthboundMqttConfig, SensorIdentity
from src.northbound.topics import coverage_topic, events_topic, observe_tick_topic, state_topic, topology_snapshot_topic
from src.runtime.agent_snapshot import write_agent_runtime

logger = logging.getLogger(__name__)

_RECONNECT_MIN_SEC = 2.0
_RECONNECT_MAX_SEC = 60.0


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


class NorthboundMqttClient:
    def __init__(self, mqtt_config: NorthboundMqttConfig, sensor: SensorIdentity) -> None:
        self._cfg = mqtt_config
        self._sensor = sensor
        self._client = None
        self._lock = threading.Lock()
        self._connected = False

    @property
    def enabled(self) -> bool:
        return self._cfg.enabled and bool(self._cfg.host)

    @property
    def connected(self) -> bool:
        return self._connected

    def update_tenant_id(self, tenant_id: str) -> None:
        tid = (tenant_id or "").strip()
        if tid:
            self._cfg.tenant_id = tid
            logger.info("Northbound MQTT tenant_id updated to %s", tid)

    def update_credentials(self, username: str, password: str) -> bool:
        """Apply Control-Plane-issued credentials, reconnecting if they changed.

        Tearing down the client forces ``_ensure_client`` to rebuild it with the
        new ``username_pw_set`` on the next publish (paho cannot swap creds on a
        live connection). Returns True when a change was applied.
        """
        user = (username or "").strip()
        if not user:
            return False
        if user == self._cfg.username and (password or "") == (self._cfg.password or ""):
            return False
        self._cfg.username = user
        self._cfg.password = password or ""
        logger.info("Northbound MQTT credentials updated (user=%s); reconnecting", user)
        with self._lock:
            self._disconnect_locked()
        return True

    def update_endpoint_if_unset(self, host: str, port: Optional[int] = None) -> bool:
        """Bootstrap host/port from the Control Plane only when not configured."""
        host = (host or "").strip()
        if not host or self._cfg.host:
            return False
        self._cfg.host = host
        if port:
            self._cfg.port = int(port)
        logger.info("Northbound MQTT endpoint bootstrapped to %s:%s", self._cfg.host, self._cfg.port)
        with self._lock:
            self._disconnect_locked()
        return True

    def _on_connect(
        self,
        client: Any,
        userdata: Any,
        flags: Any,
        reason_code: Any,
        properties: Any = None,
    ) -> None:
        if getattr(reason_code, "is_failure", False) or (
            isinstance(reason_code, int) and reason_code != 0
        ):
            self._connected = False
            logger.warning("Northbound MQTT connect refused rc=%s", reason_code)
            return
        self._connected = True
        logger.info(
            "Northbound MQTT connected to %s:%s",
            self._cfg.host,
            self._cfg.port,
        )
        write_agent_runtime(
            mqtt_connected=True,
            tenant_id=self._cfg.tenant_id,
            last_error="",  # clear stale error once the bus is back up
        )

    def _on_disconnect(
        self,
        client: Any,
        userdata: Any,
        disconnect_flags: Any,
        reason_code: Any,
        properties: Any = None,
    ) -> None:
        self._connected = False
        logger.warning("Northbound MQTT disconnected rc=%s", reason_code)
        write_agent_runtime(mqtt_connected=False)
        # Keep the client object alive: paho's network loop auto-reconnects in
        # the background (see reconnect_delay_set). We deliberately do NOT tear
        # it down and re-connect synchronously from the main loop, which is what
        # previously hung the agent for minutes when the host IP/route changed
        # and the stale socket black-holed.

    def _disconnect_locked(self) -> None:
        client = self._client
        self._client = None
        self._connected = False
        if client is None:
            return
        try:
            client.loop_stop()
            client.disconnect()
        except Exception:
            logger.exception("Northbound MQTT disconnect failed")

    def _ensure_client(self) -> Any | None:
        if not self.enabled:
            return None
        with self._lock:
            if self._client is not None:
                return self._client
            try:
                import paho.mqtt.client as mqtt

                client_id = f"ot-edge-{self._sensor.id}-{uuid.uuid4().hex[:8]}"
                client = mqtt.Client(
                    mqtt.CallbackAPIVersion.VERSION2,
                    client_id=client_id,
                )
                client.on_connect = self._on_connect
                client.on_disconnect = self._on_disconnect
                if self._cfg.username:
                    client.username_pw_set(self._cfg.username, self._cfg.password or None)
                client.reconnect_delay_set(
                    min_delay=int(_RECONNECT_MIN_SEC),
                    max_delay=int(_RECONNECT_MAX_SEC),
                )
                # connect_async + loop_start keeps the initial connect AND every
                # reconnect on paho's background thread, so a dead route can
                # never stall the agent main loop.
                client.connect_async(self._cfg.host, self._cfg.port, keepalive=60)
                client.loop_start()
                self._client = client
                logger.info(
                    "Northbound MQTT client started host=%s port=%s",
                    self._cfg.host,
                    self._cfg.port,
                )
            except Exception:
                logger.exception("Northbound MQTT client start failed")
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
        if not self._connected:
            # Background thread is still (re)connecting; skip this publish
            # without blocking. Callers fall back to HTTP / buffering.
            return False
        qos = self._cfg.qos_events if qos is None else qos
        try:
            info = client.publish(topic, json.dumps(body, ensure_ascii=False), qos=qos)
            info.wait_for_publish(timeout=10.0)
            if info.rc != 0 or (qos > 0 and not info.is_published()):
                logger.warning("MQTT publish not confirmed topic=%s rc=%s", topic, info.rc)
                return False
            write_agent_runtime(
                mqtt_connected=True,
                tenant_id=self._cfg.tenant_id,
                last_mqtt_publish_at=_utc_now_iso(),
            )
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

    def publish_coverage(self, coverage: dict[str, Any]) -> bool:
        """Publish the edge BAS coverage tally northbound (pre-aggregation)."""
        if self._cfg.require_tenant and (self._cfg.tenant_id or "").strip() in ("", "default"):
            return False
        topic = coverage_topic(self._cfg.tenant_id, self._sensor.site_id, self._sensor.id)
        body = self._envelope(
            "coverage",
            coverage,
            observed_at=str(coverage.get("generated_at") or _utc_now_iso()),
        )
        return self.publish_json(topic, body, qos=1)

    def publish_observe_tick(self, tick: dict[str, Any]) -> bool:
        if self._cfg.require_tenant and (self._cfg.tenant_id or "").strip() in ("", "default"):
            return False
        tenant_id = str(tick.get("tenant_id") or self._cfg.tenant_id).strip()
        topic = observe_tick_topic(tenant_id, self._sensor.site_id, self._sensor.id)
        body = self._envelope(
            "baseline_observe_tick",
            tick,
            observed_at=str(tick.get("observed_at") or _utc_now_iso()),
        )
        return self.publish_json(topic, body, qos=1)

    def publish_topology_snapshot(self, payload: dict[str, Any]) -> bool:
        if self._cfg.require_tenant and (self._cfg.tenant_id or "").strip() in ("", "default"):
            return False
        tenant_id = str(payload.get("tenant_id") or self._cfg.tenant_id).strip()
        topic = topology_snapshot_topic(tenant_id, self._sensor.site_id, self._sensor.id)
        body = self._envelope(
            "ot_topology_snapshot",
            payload,
            observed_at=str(payload.get("observed_at") or _utc_now_iso()),
        )
        return self.publish_json(topic, body, qos=1)

    def close(self) -> None:
        with self._lock:
            self._disconnect_locked()
=======
"""Northbound MQTT client — security events to Control Plane EMQX."""

from __future__ import annotations

import json
import logging
import threading
import uuid
from datetime import datetime, timezone
from typing import Any, Optional

from src.config.settings import NorthboundMqttConfig, SensorIdentity
from src.northbound.topics import coverage_topic, events_topic, observe_tick_topic, state_topic, topology_snapshot_topic
from src.runtime.agent_snapshot import write_agent_runtime

logger = logging.getLogger(__name__)

_RECONNECT_MIN_SEC = 2.0
_RECONNECT_MAX_SEC = 60.0


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


class NorthboundMqttClient:
    def __init__(self, mqtt_config: NorthboundMqttConfig, sensor: SensorIdentity) -> None:
        self._cfg = mqtt_config
        self._sensor = sensor
        self._client = None
        self._lock = threading.Lock()
        self._connected = False

    @property
    def enabled(self) -> bool:
        return self._cfg.enabled and bool(self._cfg.host)

    @property
    def connected(self) -> bool:
        return self._connected

    def update_tenant_id(self, tenant_id: str) -> None:
        tid = (tenant_id or "").strip()
        if tid:
            self._cfg.tenant_id = tid
            logger.info("Northbound MQTT tenant_id updated to %s", tid)

    def update_credentials(self, username: str, password: str) -> bool:
        """Apply Control-Plane-issued credentials, reconnecting if they changed.

        Tearing down the client forces ``_ensure_client`` to rebuild it with the
        new ``username_pw_set`` on the next publish (paho cannot swap creds on a
        live connection). Returns True when a change was applied.
        """
        user = (username or "").strip()
        if not user:
            return False
        if user == self._cfg.username and (password or "") == (self._cfg.password or ""):
            return False
        self._cfg.username = user
        self._cfg.password = password or ""
        logger.info("Northbound MQTT credentials updated (user=%s); reconnecting", user)
        with self._lock:
            self._disconnect_locked()
        return True

    def update_endpoint_if_unset(self, host: str, port: Optional[int] = None) -> bool:
        """Bootstrap host/port from the Control Plane only when not configured."""
        host = (host or "").strip()
        if not host or self._cfg.host:
            return False
        self._cfg.host = host
        if port:
            self._cfg.port = int(port)
        logger.info("Northbound MQTT endpoint bootstrapped to %s:%s", self._cfg.host, self._cfg.port)
        with self._lock:
            self._disconnect_locked()
        return True

    def _on_connect(
        self,
        client: Any,
        userdata: Any,
        flags: Any,
        reason_code: Any,
        properties: Any = None,
    ) -> None:
        if getattr(reason_code, "is_failure", False) or (
            isinstance(reason_code, int) and reason_code != 0
        ):
            self._connected = False
            logger.warning("Northbound MQTT connect refused rc=%s", reason_code)
            return
        self._connected = True
        logger.info(
            "Northbound MQTT connected to %s:%s",
            self._cfg.host,
            self._cfg.port,
        )
        write_agent_runtime(
            mqtt_connected=True,
            tenant_id=self._cfg.tenant_id,
            last_error="",  # clear stale error once the bus is back up
        )

    def _on_disconnect(
        self,
        client: Any,
        userdata: Any,
        disconnect_flags: Any,
        reason_code: Any,
        properties: Any = None,
    ) -> None:
        self._connected = False
        logger.warning("Northbound MQTT disconnected rc=%s", reason_code)
        write_agent_runtime(mqtt_connected=False)
        # Keep the client object alive: paho's network loop auto-reconnects in
        # the background (see reconnect_delay_set). We deliberately do NOT tear
        # it down and re-connect synchronously from the main loop, which is what
        # previously hung the agent for minutes when the host IP/route changed
        # and the stale socket black-holed.

    def _disconnect_locked(self) -> None:
        client = self._client
        self._client = None
        self._connected = False
        if client is None:
            return
        try:
            client.loop_stop()
            client.disconnect()
        except Exception:
            logger.exception("Northbound MQTT disconnect failed")

    def _ensure_client(self) -> Any | None:
        if not self.enabled:
            return None
        with self._lock:
            if self._client is not None:
                return self._client
            try:
                import paho.mqtt.client as mqtt

                client_id = f"ot-edge-{self._sensor.id}-{uuid.uuid4().hex[:8]}"
                client = mqtt.Client(
                    mqtt.CallbackAPIVersion.VERSION2,
                    client_id=client_id,
                )
                client.on_connect = self._on_connect
                client.on_disconnect = self._on_disconnect
                if self._cfg.username:
                    client.username_pw_set(self._cfg.username, self._cfg.password or None)
                client.reconnect_delay_set(
                    min_delay=int(_RECONNECT_MIN_SEC),
                    max_delay=int(_RECONNECT_MAX_SEC),
                )
                # connect_async + loop_start keeps the initial connect AND every
                # reconnect on paho's background thread, so a dead route can
                # never stall the agent main loop.
                client.connect_async(self._cfg.host, self._cfg.port, keepalive=60)
                client.loop_start()
                self._client = client
                logger.info(
                    "Northbound MQTT client started host=%s port=%s",
                    self._cfg.host,
                    self._cfg.port,
                )
            except Exception:
                logger.exception("Northbound MQTT client start failed")
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
        if not self._connected:
            # Background thread is still (re)connecting; skip this publish
            # without blocking. Callers fall back to HTTP / buffering.
            return False
        qos = self._cfg.qos_events if qos is None else qos
        try:
            info = client.publish(topic, json.dumps(body, ensure_ascii=False), qos=qos)
            info.wait_for_publish(timeout=10.0)
            if info.rc != 0 or (qos > 0 and not info.is_published()):
                logger.warning("MQTT publish not confirmed topic=%s rc=%s", topic, info.rc)
                return False
            write_agent_runtime(
                mqtt_connected=True,
                tenant_id=self._cfg.tenant_id,
                last_mqtt_publish_at=_utc_now_iso(),
            )
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

    def publish_coverage(self, coverage: dict[str, Any]) -> bool:
        """Publish the edge BAS coverage tally northbound (pre-aggregation)."""
        if self._cfg.require_tenant and (self._cfg.tenant_id or "").strip() in ("", "default"):
            return False
        topic = coverage_topic(self._cfg.tenant_id, self._sensor.site_id, self._sensor.id)
        body = self._envelope(
            "coverage",
            coverage,
            observed_at=str(coverage.get("generated_at") or _utc_now_iso()),
        )
        return self.publish_json(topic, body, qos=1)

    def publish_observe_tick(self, tick: dict[str, Any]) -> bool:
        if self._cfg.require_tenant and (self._cfg.tenant_id or "").strip() in ("", "default"):
            return False
        tenant_id = str(tick.get("tenant_id") or self._cfg.tenant_id).strip()
        topic = observe_tick_topic(tenant_id, self._sensor.site_id, self._sensor.id)
        body = self._envelope(
            "baseline_observe_tick",
            tick,
            observed_at=str(tick.get("observed_at") or _utc_now_iso()),
        )
        return self.publish_json(topic, body, qos=1)

    def publish_topology_snapshot(self, payload: dict[str, Any]) -> bool:
        if self._cfg.require_tenant and (self._cfg.tenant_id or "").strip() in ("", "default"):
            return False
        tenant_id = str(payload.get("tenant_id") or self._cfg.tenant_id).strip()
        topic = topology_snapshot_topic(tenant_id, self._sensor.site_id, self._sensor.id)
        body = self._envelope(
            "ot_topology_snapshot",
            payload,
            observed_at=str(payload.get("observed_at") or _utc_now_iso()),
        )
        return self.publish_json(topic, body, qos=1)

    def close(self) -> None:
        with self._lock:
            self._disconnect_locked()
>>>>>>> Stashed changes
