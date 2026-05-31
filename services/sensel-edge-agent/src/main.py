"""
SenseL Edge Agent entry point.
Sprint 1: registration + health heartbeat.
Sprint 2: security event upload from shared JSONL tail.
Northbound: MQTT to Control Plane EMQX (primary), HTTP fallback.
"""

from __future__ import annotations

import logging
import signal
import sys
import time

from src.api.client import SenseLClient
from src.config.settings import load_config
from src.health.collector import collect_health
from src.northbound.mqtt import NorthboundMqttClient
from src.upload.buffer import UploadBuffer
from src.upload.events import SecurityEventTailer

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("sensel-edge-agent")

_shutdown = False


def _handle_signal(signum: int, _frame) -> None:
    global _shutdown
    logger.info("Received signal %s, shutting down", signum)
    _shutdown = True


def _flush_buffer(client: SenseLClient, buffer: UploadBuffer, mqtt: NorthboundMqttClient | None) -> None:
    for entry_id, kind, payload in buffer.pending():
        try:
            if kind == "event" and mqtt and mqtt.enabled:
                if mqtt.publish_security_event(payload):
                    buffer.remove(entry_id)
                    logger.info("Flushed buffered event via MQTT (id=%s)", entry_id)
                    continue
            if kind == "health":
                client.upload_health(payload)
            elif kind == "event":
                client.upload_security_event(payload)
            else:
                logger.warning("Unknown buffered upload kind: %s", kind)
                buffer.remove(entry_id)
                continue
            buffer.remove(entry_id)
            logger.info("Flushed buffered %s upload (id=%s)", kind, entry_id)
        except Exception:
            logger.exception("Failed to flush buffered upload id=%s", entry_id)
            break


def _upload_pending_events(
    client: SenseLClient,
    buffer: UploadBuffer,
    tailer: SecurityEventTailer,
    mqtt: NorthboundMqttClient | None,
) -> None:
    for event in tailer.pending_events():
        event_id = str(event.get("event_id") or "")
        if mqtt and mqtt.enabled:
            if mqtt.publish_security_event(event):
                if event_id:
                    buffer.remove_by_event_id(event_id)
                continue
        try:
            client.upload_security_event(event)
            logger.info(
                "Security event uploaded (HTTP) — %s (%s)",
                event.get("rule_id"),
                event.get("event_type"),
            )
            if event_id:
                buffer.remove_by_event_id(event_id)
        except Exception:
            logger.exception(
                "Security event upload failed; buffering rule=%s",
                event.get("rule_id"),
            )
            buffer.enqueue("event", event)


def main() -> int:
    global _shutdown

    signal.signal(signal.SIGTERM, _handle_signal)
    signal.signal(signal.SIGINT, _handle_signal)

    try:
        config = load_config()
    except FileNotFoundError as exc:
        logger.error("%s", exc)
        return 1

    log_level = getattr(logging, config.logging.level.upper(), logging.INFO)
    logging.getLogger().setLevel(log_level)

    logger.info(
        "SenseL Edge Agent v%s starting (sensor=%s site=%s mqtt=%s)",
        config.sensor.software_version,
        config.sensor.id,
        config.sensor.site_id,
        config.northbound_mqtt.host if config.northbound_mqtt.enabled else "disabled",
    )

    if not config.sensel.api_url or not config.sensel.api_key:
        logger.error("SENSEL_API_URL and SENSEL_API_KEY must be set")
        return 1

    client = SenseLClient(config)
    mqtt = NorthboundMqttClient(config.northbound_mqtt, config.sensor)
    buffer = UploadBuffer(
        config.sensel.buffer.db_path,
        max_events=config.sensel.buffer.max_events,
    )
    tailer = SecurityEventTailer(
        config.sensel.events.watch_path,
        config.sensel.events.offset_path,
    )

    try:
        try:
            reg = client.register()
            tenant_id = str(reg.get("tenant_id") or reg.get("mqtt_tenant_id") or "").strip()
            if tenant_id and mqtt.enabled:
                mqtt.update_tenant_id(tenant_id)
        except Exception:
            logger.exception("Initial registration failed; will retry on health cycle")

        if mqtt.enabled:
            mqtt.publish_state(
                {
                    "status": "online",
                    "sensor_type": config.sensor.type,
                    "capabilities": config.sensor.capabilities,
                }
            )

        interval = config.sensel.health_interval_sec

        while not _shutdown:
            _flush_buffer(client, buffer, mqtt if mqtt.enabled else None)
            _upload_pending_events(client, buffer, tailer, mqtt if mqtt.enabled else None)

            health = collect_health(config)
            try:
                client.upload_health(health)
                logger.info(
                    "Health OK — cpu=%.1f%% mem=%.1f%% disk=%.1f%%",
                    health["cpu_usage"],
                    health["memory_usage"],
                    health["disk_usage"],
                )
            except Exception:
                logger.exception("Health upload failed; buffering for retry")
                buffer.enqueue("health", health)

            for _ in range(interval):
                if _shutdown:
                    break
                time.sleep(1)
    finally:
        buffer.close()
        mqtt.close()
        client.close()

    logger.info("SenseL Edge Agent stopped")
    return 0


if __name__ == "__main__":
    sys.exit(main())
