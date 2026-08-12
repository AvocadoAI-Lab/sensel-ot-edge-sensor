"""Fail-open runtime coordinator for EdgeX inventory and reconciliation."""

from __future__ import annotations

import logging
import time
from pathlib import Path

from sensel.device.v1 import device_management_pb2

from src.config.settings import AppConfig
from src.edgex.client import EdgeXMetadataClient
from src.edgex.inventory import InventoryBuilder
from src.edgex.mqtt_subscriber import DesiredDeviceStateSubscriber
from src.edgex.reconciler import DeviceReconciler
from src.edgex.state import DesiredCommandStore, ObservedReportOutbox, _atomic_json
from src.northbound.mqtt import NorthboundMqttClient
from src.runtime.agent_snapshot import write_agent_runtime

logger = logging.getLogger(__name__)


class EdgeXDeviceManager:
    def __init__(self, config: AppConfig, mqtt: NorthboundMqttClient) -> None:
        self.config = config
        self.mqtt = mqtt
        settings = config.edgex_device_management
        self.metadata = EdgeXMetadataClient(
            settings.metadata_url,
            timeout_sec=settings.request_timeout_sec,
        )
        self.builder = InventoryBuilder(
            self.metadata,
            site_id=config.sensor.site_id,
            sensor_id=config.sensor.id,
            gateway_id=settings.gateway_id,
            live_observed_path=settings.live_observed_path,
            identity_inventory_path=settings.identity_inventory_path,
            desired_state_path=settings.desired_state_path,
            reconcile_state_path=settings.reconcile_state_path,
        )
        self.commands = DesiredCommandStore(settings.desired_state_path)
        self.outbox = ObservedReportOutbox(
            settings.observed_spool_db_path,
            max_reports=settings.max_pending_reports,
        )
        self.reconciler = DeviceReconciler(
            self.metadata,
            state_path=settings.reconcile_state_path,
            sampling_profiles=settings.sampling_profiles,
            producer_version=config.sensor.software_version,
        )
        self.subscriber = DesiredDeviceStateSubscriber(config, self.commands.accept)
        self.inventory_state_path = Path(settings.inventory_state_path)
        self._last_inventory_attempt = 0.0
        self._metadata_ok = False
        self._last_error = ""

    @property
    def enabled(self) -> bool:
        return self.config.edgex_device_management.enabled

    def _inventory_tick(self, tenant_id: str, now: float) -> None:
        interval = self.config.edgex_device_management.inventory_interval_sec
        if now - self._last_inventory_attempt < interval:
            return
        self._last_inventory_attempt = now
        snapshot = self.builder.build(tenant_id)
        self._metadata_ok = True
        if self.mqtt.publish_inventory_snapshot(
            snapshot.SerializeToString(), snapshot_id=snapshot.snapshot_id
        ):
            _atomic_json(
                self.inventory_state_path,
                {
                    "published_revision": snapshot.inventory_revision,
                    "snapshot_id": snapshot.snapshot_id,
                    "published_at": snapshot.meta.observed_at.ToJsonString(),
                    "device_count": len(snapshot.devices),
                },
            )

    def _reconcile_tick(self) -> None:
        if not self._metadata_ok and not self.builder.device_records:
            return
        processed: set[str] = set()
        for command in self.commands.pending()[:100]:
            processed.add(command.asset_id)
            report = self.reconciler.reconcile(command, self.builder.device_records)
            self.outbox.enqueue(report)
            if report.status in (
                device_management_pb2.RECONCILIATION_STATUS_APPLIED,
                device_management_pb2.RECONCILIATION_STATUS_NO_CHANGE,
            ):
                status = "applied"
            elif report.status == device_management_pb2.RECONCILIATION_STATUS_REJECTED:
                status = "rejected"
            else:
                self.commands.mark_retry(
                    command.asset_id, command.command_id, report.error
                )
                continue
            self.commands.mark_done(
                command.asset_id,
                command_id=command.command_id,
                status=status,
                error=report.error,
            )
        if not self._metadata_ok:
            return
        for command in self.commands.applied()[:100]:
            if command.asset_id in processed:
                continue
            record = self.builder.device_records.get(command.asset_id)
            if not self.reconciler.needs_reconcile(command, record):
                continue
            report = self.reconciler.reconcile(
                command,
                self.builder.device_records,
                existing_desired=True,
            )
            self.outbox.enqueue(report)
            if report.status == device_management_pb2.RECONCILIATION_STATUS_FAILED:
                self.commands.mark_retry(
                    command.asset_id, command.command_id, report.error
                )
            elif report.status == device_management_pb2.RECONCILIATION_STATUS_REJECTED:
                self.commands.mark_done(
                    command.asset_id,
                    command_id=command.command_id,
                    status="rejected",
                    error=report.error,
                )

    def _drain_outbox(self) -> None:
        for entry in self.outbox.pending(limit=100):
            if self.mqtt.publish_observed_device_state(
                entry.payload, trace_id=entry.trace_id
            ):
                self.outbox.acknowledge(entry.id)
            else:
                self.outbox.record_failure(entry.id, "MQTT publish not confirmed")
                break

    def tick(self, tenant_id: str) -> None:
        if not self.enabled:
            return
        try:
            self._inventory_tick(tenant_id, time.monotonic())
            self._last_error = ""
        except Exception as exc:
            # EdgeX device management is explicitly fail-open: a metadata outage
            # cannot stop packet capture, passive identity or security uploads.
            self._metadata_ok = False
            self._last_error = str(exc)[:500]
            logger.warning("EdgeX device-management tick failed: %s", exc)
        try:
            self._reconcile_tick()
        except Exception as exc:
            self._last_error = str(exc)[:500]
            logger.warning("EdgeX desired-state reconciliation failed: %s", exc)
        try:
            self._drain_outbox()
        except Exception as exc:
            self._last_error = str(exc)[:500]
            logger.warning("EdgeX observed-state outbox drain failed: %s", exc)
        write_agent_runtime(
            edgex_device_management={
                "enabled": self.enabled,
                "metadata_ok": self._metadata_ok,
                "desired_mqtt_connected": self.subscriber.connected,
                "desired_commands_accepted": self.subscriber.accepted,
                "desired_commands_rejected": self.subscriber.rejected,
                "observed_outbox_depth": self.outbox.depth(),
                "last_error": self._last_error,
            }
        )

    def start(self) -> None:
        if self.enabled:
            self.subscriber.start()

    def refresh_subscription(self) -> None:
        self.subscriber.refresh_subscription()

    def close(self) -> None:
        self.subscriber.stop()
        self.outbox.close()
        self.metadata.close()
