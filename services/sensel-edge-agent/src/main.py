"""
SenseL Edge Agent entry point.
Sprint 1: registration + health heartbeat.
Sprint 2: security event upload from shared JSONL tail.
Northbound: MQTT to Control Plane EMQX (primary), HTTP fallback.
"""

from __future__ import annotations

import json
import logging
import signal
import sys
import time
from pathlib import Path

from src.api.client import SenseLClient
from src.config.settings import load_config
from src.health.collector import collect_health
from src.northbound.mqtt import NorthboundMqttClient
from src.policy.sync import PolicySync
from src.policy.mqtt_subscriber import PolicyMqttSubscriber
from src.policy.detection_policy_sync import DetectionPolicySync
from src.policy.detection_mqtt_subscriber import DetectionPolicyMqttSubscriber
from src.runtime.agent_snapshot import write_agent_runtime
from src.runtime.registration import RegistrationState, attempt_registration
from src.sighting.reporter import SightingReporter
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


def _maybe_publish_coverage(
    mqtt: NorthboundMqttClient, path: Path, last_mtime: float
) -> float:
    """Publish the edge coverage tally northbound when it changed since last send.

    Reads packet-sensor's ``coverage-counters.json`` (shared volume) and forwards
    it on the ``.../coverage/v1`` topic. mtime-gated so we only emit on new
    detections; on publish failure we keep the old mtime to retry next loop.
    """
    try:
        if not path.exists():
            return last_mtime
        mtime = path.stat().st_mtime
        if mtime <= last_mtime:
            return last_mtime
        data = json.loads(path.read_text(encoding="utf-8"))
        if mqtt.publish_coverage(data):
            logger.info(
                "MQTT coverage published — events=%s techniques=%s",
                (data.get("totals") or {}).get("events"),
                (data.get("totals") or {}).get("techniques_hit"),
            )
            return mtime
    except Exception:
        logger.debug("coverage publish skipped", exc_info=True)
    return last_mtime


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
        "SenseL Edge Agent v%s starting (sensor=%s site=%s mqtt=%s register_retry=%ss)",
        config.sensor.software_version,
        config.sensor.id,
        config.sensor.site_id,
        config.northbound_mqtt.host if config.northbound_mqtt.enabled else "disabled",
        config.sensel.register_retry_sec,
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
    coverage_path = Path(config.sensel.events.watch_path).parent / "coverage-counters.json"
    last_coverage_mtime = 0.0
    policy_sync = PolicySync(config) if config.policy_sync.enabled else None
    policy_mqtt = (
        PolicyMqttSubscriber(config, policy_sync)
        if policy_sync and config.policy_sync.mqtt_enabled
        else None
    )
    detection_policy_sync = DetectionPolicySync(config)
    detection_policy_mqtt = (
        DetectionPolicyMqttSubscriber(config, detection_policy_sync)
        if detection_policy_sync.enabled and config.policy_sync.mqtt_enabled
        else None
    )
    sighting_reporter = SightingReporter(config)
    registration = RegistrationState()
    last_policy_sync = 0.0

    if policy_mqtt and policy_mqtt.enabled:
        logger.info(
            "Policy MQTT subscriber enabled host=%s topic_tpl=%s",
            config.policy_sync.mqtt_host,
            config.policy_sync.mqtt_topic_template,
        )
    if detection_policy_mqtt and detection_policy_mqtt.enabled:
        logger.info(
            "Detection policy MQTT enabled host=%s topic_tpl=%s",
            config.policy_sync.mqtt_host,
            config.policy_sync.detection_policy_mqtt_topic_template,
        )

    try:
        attempt_registration(
            client=client,
            config=config,
            mqtt=mqtt,
            policy_mqtt=policy_mqtt,
            state=registration,
            force=True,
        )

        if policy_mqtt and policy_mqtt.enabled:
            policy_mqtt.start()
        if detection_policy_mqtt and detection_policy_mqtt.enabled:
            detection_policy_mqtt.start()

        if policy_sync:
            initial = policy_sync.pull_http_feed(force=True)
            if initial.ok:
                logger.info(
                    "Policy sync initial tenant=%s version=%s items=%s",
                    initial.tenant_id,
                    initial.artifact_version,
                    initial.item_count,
                )
            else:
                logger.warning("Policy sync initial failed: %s", initial.error)
            last_policy_sync = time.monotonic()

        if sighting_reporter.enabled:
            sighting_reporter.run_cycle(force_flush=True)
        elif config.sighting_report.enabled and not config.sighting_report.smb_intel_api_key:
            logger.warning("Sighting report enabled but SMB_INTEL_API_KEY is not set")

        interval = config.sensel.health_interval_sec

        while not _shutdown:
            attempt_registration(
                client=client,
                config=config,
                mqtt=mqtt,
                policy_mqtt=policy_mqtt,
                state=registration,
            )

            if policy_mqtt and policy_mqtt.enabled:
                policy_mqtt.ensure_connected()
            if detection_policy_mqtt and detection_policy_mqtt.enabled:
                detection_policy_mqtt.ensure_connected()

            _flush_buffer(client, buffer, mqtt if mqtt.enabled else None)
            _upload_pending_events(client, buffer, tailer, mqtt if mqtt.enabled else None)

            if sighting_reporter.enabled:
                sighting_reporter.run_cycle()

            if policy_sync:
                elapsed = time.monotonic() - last_policy_sync
                if elapsed >= config.policy_sync.interval_sec:
                    result = policy_sync.pull_http_feed()
                    if result.changed:
                        logger.info(
                            "Policy sync updated tenant=%s version=%s items=%s",
                            result.tenant_id,
                            result.artifact_version,
                            result.item_count,
                        )
                    elif not result.ok and result.error:
                        logger.warning("Policy sync failed: %s", result.error)
                    last_policy_sync = time.monotonic()

            health = collect_health(config)

            write_agent_runtime(
                registered=registration.complete,
                tenant_id=registration.tenant_id or config.northbound_mqtt.tenant_id,
                mqtt_connected=mqtt.connected if mqtt.enabled else None,
            )

            # Northbound MQTT heartbeat: publish_state lazily (re)connects, so a
            # periodic state message keeps the control-plane bus alive and
            # re-establishes it after a transient broker outage even when no
            # security events are flowing. Without this the bus shows
            # disconnected during quiet periods. On success publish_state writes
            # mqtt_connected=True + last_mqtt_publish_at to the runtime snapshot.
            if mqtt.enabled:
                mqtt.publish_state(
                    {
                        "status": "online",
                        "registered": registration.complete,
                        "tenant_id": registration.tenant_id or config.northbound_mqtt.tenant_id,
                        "health": health,
                    }
                )
                last_coverage_mtime = _maybe_publish_coverage(
                    mqtt, coverage_path, last_coverage_mtime
                )

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
        if detection_policy_mqtt:
            detection_policy_mqtt.stop()
        if policy_mqtt:
            policy_mqtt.stop()
        buffer.close()
        mqtt.close()
        client.close()

    logger.info("SenseL Edge Agent stopped")
    return 0


if __name__ == "__main__":
    sys.exit(main())
