"""SenseL sensor registration with periodic retry."""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional

from src.api.client import SenseLClient
from src.config.settings import AppConfig
from src.northbound.mqtt import NorthboundMqttClient
from src.policy.mqtt_subscriber import PolicyMqttSubscriber
from src.runtime.agent_snapshot import write_agent_runtime
from src.runtime.mqtt_credentials import persist_credentials

logger = logging.getLogger(__name__)


@dataclass
class RegistrationState:
    """Tracks portal registration attempts."""

    complete: bool = False
    tenant_id: str = ""
    last_attempt_at: float = 0.0
    last_error: Optional[str] = None

    def due(self, retry_sec: int) -> bool:
        if self.complete:
            return False
        if self.last_attempt_at <= 0:
            return True
        return (time.monotonic() - self.last_attempt_at) >= max(1, retry_sec)


def attempt_registration(
    *,
    client: SenseLClient,
    config: AppConfig,
    mqtt: NorthboundMqttClient,
    policy_mqtt: PolicyMqttSubscriber | None,
    state: RegistrationState,
    force: bool = False,
) -> bool:
    """
    Register with SenseL Portal when not yet complete.
    Updates northbound MQTT tenant and policy MQTT subscription on success.
    """
    retry_sec = config.sensel.register_retry_sec
    if not force and not state.due(retry_sec):
        return state.complete

    state.last_attempt_at = time.monotonic()
    try:
        reg = client.register()
    except Exception as exc:
        state.last_error = str(exc)
        write_agent_runtime(
            registered=False,
            last_error=str(exc),
            mqtt_connected=mqtt.connected if mqtt.enabled else None,
        )
        logger.exception(
            "Registration failed; will retry in %ss",
            retry_sec,
        )
        return False

    tenant_id = str(reg.get("tenant_id") or reg.get("mqtt_tenant_id") or "").strip()
    state.tenant_id = tenant_id
    state.last_error = None
    state.complete = True

    if tenant_id and mqtt.enabled:
        mqtt.update_tenant_id(tenant_id)

    _apply_mqtt_credentials(config=config, mqtt=mqtt, reg=reg)

    if policy_mqtt:
        if policy_mqtt.enabled and not policy_mqtt.connected:
            policy_mqtt.start()
        policy_mqtt.refresh_subscription()

    if mqtt.enabled:
        mqtt.publish_state(
            {
                "status": "online",
                "sensor_type": config.sensor.type,
                "capabilities": config.sensor.capabilities,
            }
        )

    write_agent_runtime(
        registered=True,
        tenant_id=tenant_id,
        last_register_at=datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
        last_error="",  # "" clears the stored error; None would be skipped on merge
        mqtt_connected=mqtt.connected if mqtt.enabled else None,
    )
    logger.info("Registration succeeded (tenant=%s)", tenant_id or "(none)")
    return True


def _apply_mqtt_credentials(
    *,
    config: AppConfig,
    mqtt: NorthboundMqttClient,
    reg: dict,
) -> None:
    """Auto-land Control-Plane-issued MQTT credentials from the register response.

    Mutates the live config (read lazily by the policy subscribers on ``start``)
    and the running northbound client, then persists the secret for the next
    boot. No-ops when the Control Plane did not return credentials (provisioning
    disabled / older Control Plane).
    """
    username = str(reg.get("mqtt_username") or "").strip()
    password = str(reg.get("mqtt_password") or "")
    if not username:
        return

    host = str(reg.get("mqtt_host") or "").strip()
    try:
        port = int(reg.get("mqtt_port")) if reg.get("mqtt_port") else None
    except (TypeError, ValueError):
        port = None

    config.northbound_mqtt.username = username
    config.northbound_mqtt.password = password
    config.policy_sync.mqtt_username = username
    config.policy_sync.mqtt_password = password

    if mqtt.enabled:
        mqtt.update_credentials(username, password)
        if host:
            mqtt.update_endpoint_if_unset(host, port)

    persisted = persist_credentials(
        username=username,
        password=password,
        host=host or None,
        port=port,
        tenant_id=str(reg.get("tenant_id") or reg.get("mqtt_tenant_id") or "").strip() or None,
        acl_version=reg.get("mqtt_acl_version"),
    )
    logger.info(
        "Applied Control-Plane MQTT credentials (user=%s persisted=%s)",
        username,
        persisted,
    )
