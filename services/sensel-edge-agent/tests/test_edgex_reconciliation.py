from copy import deepcopy
from datetime import datetime, timedelta, timezone

from sensel.device.v1 import device_management_pb2
from src.edgex.reconciler import DeviceReconciler
from src.edgex.state import (
    DesiredCommandStore,
    InvalidDesiredDeviceCommand,
    ObservedReportOutbox,
    decode_desired_command,
)


class FakeMetadata:
    def __init__(self) -> None:
        self.device = {
            "name": "plc-1",
            "adminState": "UNLOCKED",
            "operatingState": "UP",
            "autoEvents": [{"sourceName": "HoldingRegister", "interval": "10s"}],
        }
        self.updates = []
        self.error = None

    def get_device(self, name):
        if self.error:
            raise self.error
        return deepcopy(self.device)

    def update_device(self, device):
        if self.error:
            raise self.error
        self.device = deepcopy(device)
        self.updates.append(device)


def _command(*, command_id="cmd-1", revision="rev-1", profile="slow"):
    command = device_management_pb2.DesiredDeviceStateCommand(
        command_id=command_id,
        asset_id="edgex:site-a:id-1",
        desired=device_management_pb2.DesiredDeviceState(
            enabled=False,
            lifecycle_state=device_management_pb2.DEVICE_LIFECYCLE_STATE_QUARANTINED,
            sampling_profile=profile,
            config_revision=revision,
        ),
    )
    command.meta.event_id = command_id
    command.meta.tenant_id = "tenant-a"
    command.meta.site_id = "site-a"
    command.meta.sensor_id = "edge-a"
    command.meta.observed_at.GetCurrentTime()
    command.expires_at.FromDatetime(
        datetime.now(timezone.utc) + timedelta(minutes=5)
    )
    return command


def test_desired_command_validates_route_expiry_and_deduplicates(tmp_path) -> None:
    command = _command()
    decoded = decode_desired_command(
        command.SerializeToString(),
        tenant_id="tenant-a",
        site_id="site-a",
        sensor_id="edge-a",
    )
    store = DesiredCommandStore(tmp_path / "desired.json")

    assert store.accept(decoded) is True
    assert store.accept(decoded) is False
    assert [item.command_id for item in store.pending()] == ["cmd-1"]
    stale = _command(command_id="cmd-stale", revision="rev-stale")
    stale.meta.observed_at.FromDatetime(
        decoded.meta.observed_at.ToDatetime(tzinfo=timezone.utc) - timedelta(seconds=1)
    )
    assert store.accept(stale) is False

    try:
        decode_desired_command(
            command.SerializeToString(),
            tenant_id="other",
            site_id="site-a",
            sensor_id="edge-a",
        )
        raise AssertionError("expected InvalidDesiredDeviceCommand")
    except InvalidDesiredDeviceCommand as exc:
        assert "route" in str(exc)


def test_reconcile_applies_safe_fields_and_is_idempotent(tmp_path) -> None:
    metadata = FakeMetadata()
    reconciler = DeviceReconciler(
        metadata,
        state_path=tmp_path / "reconcile.json",
        sampling_profiles={"slow": "60s", "disabled": ""},
        producer_version="0.3.0",
    )
    command = _command()
    records = {command.asset_id: {"name": "plc-1"}}

    applied = reconciler.reconcile(command, records)
    unchanged = reconciler.reconcile(command, records)

    assert applied.status == device_management_pb2.RECONCILIATION_STATUS_APPLIED
    assert metadata.updates[0]["adminState"] == "LOCKED"
    assert metadata.updates[0]["autoEvents"][0]["interval"] == "60s"
    assert unchanged.status == device_management_pb2.RECONCILIATION_STATUS_NO_CHANGE
    assert len(metadata.updates) == 1
    assert reconciler.needs_reconcile(command, metadata.device) is False
    drifted = deepcopy(metadata.device)
    drifted["adminState"] = "UNLOCKED"
    assert reconciler.needs_reconcile(command, drifted) is True


def test_reconcile_rejects_unbound_asset_and_retries_metadata_failure(tmp_path) -> None:
    metadata = FakeMetadata()
    reconciler = DeviceReconciler(
        metadata,
        state_path=tmp_path / "reconcile.json",
        sampling_profiles={"slow": "60s"},
        producer_version="0.3.0",
    )
    command = _command()
    rejected = reconciler.reconcile(command, {})
    metadata.error = RuntimeError("metadata unavailable")
    failed = reconciler.reconcile(command, {command.asset_id: {"name": "plc-1"}})

    assert rejected.status == device_management_pb2.RECONCILIATION_STATUS_REJECTED
    assert "not bound" in rejected.error
    assert failed.status == device_management_pb2.RECONCILIATION_STATUS_FAILED
    assert "unavailable" in failed.error


def test_observed_report_outbox_is_durable_and_deduplicated(tmp_path) -> None:
    path = tmp_path / "observed.db"
    report = device_management_pb2.ObservedDeviceStateReport(report_id="report-1")
    report.meta.trace_id = "trace-1"
    first = ObservedReportOutbox(path)
    assert first.enqueue(report) is True
    assert first.enqueue(report) is False
    first.close()

    reopened = ObservedReportOutbox(path)
    pending = reopened.pending()
    assert len(pending) == 1
    assert pending[0].trace_id == "trace-1"
    reopened.acknowledge(pending[0].id)
    assert reopened.depth() == 0
    reopened.close()
