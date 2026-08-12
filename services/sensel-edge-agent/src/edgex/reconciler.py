"""Single-writer reconciliation from Tier 3 desired state into EdgeX metadata."""

from __future__ import annotations

import json
import uuid
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

from sensel.device.v1 import device_management_pb2

from src.edgex.client import EdgeXMetadataClient
from src.edgex.state import _atomic_json


class DeviceReconciler:
    def __init__(
        self,
        metadata: EdgeXMetadataClient,
        *,
        state_path: str | Path,
        sampling_profiles: Mapping[str, str],
        producer_version: str,
    ) -> None:
        self.metadata = metadata
        self.state_path = Path(state_path)
        self.sampling_profiles = dict(sampling_profiles)
        self.producer_version = producer_version

    def _state(self) -> dict[str, Any]:
        try:
            value = json.loads(self.state_path.read_text(encoding="utf-8"))
            return value if isinstance(value, dict) else {"assets": {}}
        except (OSError, json.JSONDecodeError):
            return {"assets": {}}

    def _save_applied(self, asset_id: str, revision: str) -> None:
        body = self._state()
        assets = body.setdefault("assets", {})
        assets[asset_id] = {
            "applied_config_revision": revision,
            "applied_at": datetime.now(timezone.utc).isoformat(),
        }
        _atomic_json(self.state_path, body)

    def needs_reconcile(
        self,
        command: device_management_pb2.DesiredDeviceStateCommand,
        record: Mapping[str, Any] | None,
    ) -> bool:
        if not record:
            return False
        locked = command.desired.lifecycle_state in (
            device_management_pb2.DEVICE_LIFECYCLE_STATE_QUARANTINED,
            device_management_pb2.DEVICE_LIFECYCLE_STATE_RETIRED,
        ) or not command.desired.enabled
        if str(record.get("adminState") or "").upper() != (
            "LOCKED" if locked else "UNLOCKED"
        ):
            return True
        interval = self.sampling_profiles.get(command.desired.sampling_profile)
        if interval is None:
            return True
        auto_events = record.get("autoEvents")
        if not isinstance(auto_events, list):
            return False
        if not interval:
            return bool(auto_events)
        return any(
            isinstance(event, Mapping) and str(event.get("interval") or "") != interval
            for event in auto_events
        )

    def reconcile(
        self,
        command: device_management_pb2.DesiredDeviceStateCommand,
        device_records: Mapping[str, dict[str, Any]],
        *,
        existing_desired: bool = False,
    ) -> device_management_pb2.ObservedDeviceStateReport:
        status = device_management_pb2.RECONCILIATION_STATUS_FAILED
        error = ""
        observed = device_management_pb2.ObservedDeviceState()
        profile_version = ""
        try:
            if not existing_desired and command.expires_at.ToDatetime(
                tzinfo=timezone.utc
            ) <= datetime.now(timezone.utc):
                status = device_management_pb2.RECONCILIATION_STATUS_REJECTED
                raise ValueError("desired command expired before reconciliation")
            record = device_records.get(command.asset_id)
            if not record:
                status = device_management_pb2.RECONCILIATION_STATUS_REJECTED
                raise ValueError("asset is not bound to an EdgeX device")
            profile_name = command.desired.sampling_profile
            if profile_name not in self.sampling_profiles:
                status = device_management_pb2.RECONCILIATION_STATUS_REJECTED
                raise ValueError(f"sampling profile is not allowlisted: {profile_name}")
            current = self.metadata.get_device(str(record.get("name") or ""))
            updated = deepcopy(current)
            locked = command.desired.lifecycle_state in (
                device_management_pb2.DEVICE_LIFECYCLE_STATE_QUARANTINED,
                device_management_pb2.DEVICE_LIFECYCLE_STATE_RETIRED,
            ) or not command.desired.enabled
            updated["adminState"] = "LOCKED" if locked else "UNLOCKED"
            interval = self.sampling_profiles[profile_name]
            auto_events = updated.get("autoEvents")
            if isinstance(auto_events, list):
                if not interval:
                    updated["autoEvents"] = []
                else:
                    updated["autoEvents"] = [
                        {**event, "interval": interval}
                        for event in auto_events
                        if isinstance(event, dict)
                    ]
            changed = updated != current
            state = self._state().get("assets", {}).get(command.asset_id, {})
            already_applied = (
                isinstance(state, dict)
                and state.get("applied_config_revision")
                == command.desired.config_revision
            )
            if changed:
                self.metadata.update_device(updated)
                status = device_management_pb2.RECONCILIATION_STATUS_APPLIED
            elif already_applied:
                status = device_management_pb2.RECONCILIATION_STATUS_NO_CHANGE
            else:
                status = device_management_pb2.RECONCILIATION_STATUS_APPLIED
            self._save_applied(command.asset_id, command.desired.config_revision)
            observed.connection_state = str(updated.get("operatingState") or "UNKNOWN")
            observed.applied_config_revision = command.desired.config_revision
            profile_version = str(updated.get("profileVersion") or "")
            observed.profile_version = profile_version
            observed.last_seen_at.GetCurrentTime()
        except Exception as exc:
            error = str(exc)[:2048]

        # Once enqueued, this UUID and payload are retried byte-for-byte by the
        # outbox. A later drift correction for the same command needs a new ID.
        report_id = str(uuid.uuid4())
        report = device_management_pb2.ObservedDeviceStateReport(
            report_id=report_id,
            asset_id=command.asset_id,
            command_id=command.command_id,
            observed=observed,
            status=status,
            error=error,
        )
        report.meta.event_id = report_id
        report.meta.tenant_id = command.meta.tenant_id
        report.meta.site_id = command.meta.site_id
        report.meta.sensor_id = command.meta.sensor_id
        report.meta.trace_id = command.meta.trace_id or command.command_id
        report.meta.producer.type = "sensel-edge-agent-edgex"
        report.meta.producer.version = self.producer_version
        report.meta.observed_at.GetCurrentTime()
        report.reconciled_at.GetCurrentTime()
        return report
