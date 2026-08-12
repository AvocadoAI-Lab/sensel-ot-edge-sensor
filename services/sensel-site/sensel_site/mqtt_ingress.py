"""MQTT v5 Site ingress with durable QoS 1 acknowledgement semantics."""

from __future__ import annotations

import hashlib
import logging
import ssl
from dataclasses import dataclass
from typing import Any

from sensel_site.config import SiteConfig
from sensel_site.contracts import InvalidSitePublish, decode_episode_publish
from sensel_site.feature_contracts import FeatureContractRegistry
from sensel_site.store import SiteStore

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class IngressResult:
    status: str
    episode_id: str = ""


class SiteEpisodeIngress:
    def __init__(
        self,
        config: SiteConfig,
        store: SiteStore,
        registry: FeatureContractRegistry | None = None,
    ) -> None:
        self.config = config
        self.store = store
        self.registry = registry or FeatureContractRegistry(
            config.feature_contract_dir
        )

    def handle(
        self,
        *,
        topic: str,
        payload: bytes,
        content_type: str,
        payload_format_indicator: int,
        retained: bool = False,
        qos: int = 1,
    ) -> IngressResult:
        try:
            if retained:
                raise InvalidSitePublish("retained Trust Episodes are not accepted")
            receipt = decode_episode_publish(
                topic=topic,
                payload=payload,
                content_type=content_type,
                payload_format_indicator=payload_format_indicator,
                expected_tenant_id=self.config.tenant_id,
                expected_site_id=self.config.site_id,
                max_payload_bytes=self.config.max_episode_bytes,
                qos=qos,
            )
            self.registry.validate_episode(
                contract_id=receipt.feature_contract_id,
                feature_count=len(receipt.feature_values),
                sequence_length=receipt.sequence_length,
            )
            inserted = self.store.insert_episode(
                receipt,
                retention_days=self.config.episode_retention_days,
            )
            return IngressResult(
                "stored" if inserted else "duplicate",
                receipt.episode_id,
            )
        except ValueError as exc:
            digest = "sha256:" + hashlib.sha256(payload).hexdigest()
            self.store.record_dead_letter(
                topic=topic,
                payload_sha256=digest,
                content_type=content_type,
                error=str(exc),
            )
            return IngressResult("dead_letter")


class SiteMqttSubscriber:
    def __init__(self, config: SiteConfig, ingress: SiteEpisodeIngress) -> None:
        self.config = config
        self.ingress = ingress
        self._client: Any = None
        self.connected = False

    def start(self) -> None:
        if not self.config.mqtt_enabled:
            logger.info("Site MQTT ingress disabled")
            return
        import paho.mqtt.client as mqtt

        client = mqtt.Client(
            mqtt.CallbackAPIVersion.VERSION2,
            client_id=f"sensel-site-{self.config.node_id}",
            protocol=mqtt.MQTTv5,
            manual_ack=True,
        )
        if self.config.mqtt_username:
            client.username_pw_set(
                self.config.mqtt_username,
                self.config.mqtt_password,
            )
        if self.config.mqtt_tls:
            client.tls_set(
                ca_certs=self.config.mqtt_ca_path or None,
                certfile=self.config.mqtt_cert_path or None,
                keyfile=self.config.mqtt_key_path or None,
                tls_version=ssl.PROTOCOL_TLS_CLIENT,
            )
            client.tls_insecure_set(self.config.mqtt_tls_insecure)
        client.on_connect = self._on_connect
        client.on_disconnect = self._on_disconnect
        client.on_message = self._on_message
        properties = mqtt.Properties(mqtt.PacketTypes.CONNECT)
        properties.SessionExpiryInterval = self.config.mqtt_session_expiry_sec
        client.connect(
            self.config.mqtt_host,
            self.config.mqtt_port,
            keepalive=60,
            clean_start=False,
            properties=properties,
        )
        client.loop_start()
        self._client = client

    def _on_connect(self, client, userdata, flags, reason_code, properties) -> None:
        del userdata, flags, properties
        if int(reason_code) != 0:
            logger.error("Site MQTT connection rejected: %s", reason_code)
            return
        self.connected = True
        result, _ = client.subscribe(self.config.mqtt_topic, qos=1)
        if result != 0:
            self.connected = False
            logger.error("Site MQTT subscribe failed: result=%s", result)
            return
        logger.info("Site MQTT subscribed topic=%s", self.config.mqtt_topic)

    def _on_disconnect(
        self,
        client,
        userdata,
        disconnect_flags,
        reason_code,
        properties,
    ) -> None:
        del client, userdata, disconnect_flags, properties
        self.connected = False
        logger.warning("Site MQTT disconnected: %s", reason_code)

    def _on_message(self, client, userdata, message) -> None:
        del userdata
        properties = message.properties
        content_type = str(getattr(properties, "ContentType", "") or "")
        pfi = int(getattr(properties, "PayloadFormatIndicator", -1))
        try:
            result = self.ingress.handle(
                topic=message.topic,
                payload=bytes(message.payload),
                content_type=content_type,
                payload_format_indicator=pfi,
                retained=bool(message.retain),
                qos=int(message.qos),
            )
            # ACK only after the episode or poison receipt is durable.
            client.ack(message.mid, message.qos)
            logger.info(
                "Site episode ingress status=%s episode_id=%s",
                result.status,
                result.episode_id,
            )
        except Exception:  # noqa: BLE001 - no ACK causes broker redelivery
            logger.exception("Site episode persistence failed; MQTT publish not ACKed")

    def stop(self) -> None:
        if self._client is not None:
            self._client.loop_stop()
            self._client.disconnect()
            self._client = None
        self.connected = False
