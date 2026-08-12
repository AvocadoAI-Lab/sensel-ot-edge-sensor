from types import SimpleNamespace
from unittest.mock import MagicMock

from test_edgex_reconciliation import _command

from src.config.settings import (
    AppConfig,
    NorthboundMqttConfig,
    SenselConfig,
    SensorIdentity,
)
from src.edgex.mqtt_subscriber import DesiredDeviceStateSubscriber


def _config() -> AppConfig:
    return AppConfig(
        sensor=SensorIdentity(id="edge-a", site_id="site-a"),
        sensel=SenselConfig(api_url="http://control", api_key="key"),
        northbound_mqtt=NorthboundMqttConfig(
            enabled=True,
            host="broker",
            tenant_id="tenant-a",
        ),
    )


def test_desired_subscriber_accepts_only_binary_protobuf_contract() -> None:
    accepted = []
    subscriber = DesiredDeviceStateSubscriber(
        _config(), lambda command: not accepted.append(command)
    )
    message = SimpleNamespace(
        topic=(
            "sensel/tenant-a/site-a/edge-a/device/desired/"
            "edgex:site-a:id-1/v1"
        ),
        payload=_command().SerializeToString(),
        properties=SimpleNamespace(
            ContentType=(
                "application/x-protobuf; "
                "message=sensel.device.v1.DesiredDeviceStateCommand"
            ),
            PayloadFormatIndicator=0,
            CorrelationData=b"cmd-1",
        ),
    )

    subscriber._on_message(None, None, message)

    assert subscriber.accepted == 1
    assert accepted[0].command_id == "cmd-1"


def test_desired_subscriber_rejects_missing_content_type() -> None:
    subscriber = DesiredDeviceStateSubscriber(_config(), lambda command: True)
    message = SimpleNamespace(
        topic=(
            "sensel/tenant-a/site-a/edge-a/device/desired/"
            "edgex:site-a:id-1/v1"
        ),
        payload=_command().SerializeToString(),
        properties=SimpleNamespace(PayloadFormatIndicator=0),
    )

    subscriber._on_message(None, None, message)

    assert subscriber.rejected == 1


def test_desired_subscriber_rejects_asset_topic_mismatch() -> None:
    subscriber = DesiredDeviceStateSubscriber(_config(), lambda command: True)
    message = SimpleNamespace(
        topic="sensel/tenant-a/site-a/edge-a/device/desired/other-asset/v1",
        payload=_command().SerializeToString(),
        properties=SimpleNamespace(
            ContentType=(
                "application/x-protobuf; "
                "message=sensel.device.v1.DesiredDeviceStateCommand"
            ),
            PayloadFormatIndicator=0,
            CorrelationData=b"cmd-1",
        ),
    )

    subscriber._on_message(None, None, message)

    assert subscriber.rejected == 1


def test_desired_subscriber_rejects_correlation_mismatch() -> None:
    subscriber = DesiredDeviceStateSubscriber(_config(), lambda command: True)
    message = SimpleNamespace(
        topic=(
            "sensel/tenant-a/site-a/edge-a/device/desired/"
            "edgex:site-a:id-1/v1"
        ),
        payload=_command().SerializeToString(),
        properties=SimpleNamespace(
            ContentType=(
                "application/x-protobuf; "
                "message=sensel.device.v1.DesiredDeviceStateCommand"
            ),
            PayloadFormatIndicator=0,
            CorrelationData=b"other-command",
        ),
    )

    subscriber._on_message(None, None, message)

    assert subscriber.rejected == 1


def test_desired_subscriber_uses_per_asset_wildcard() -> None:
    subscriber = DesiredDeviceStateSubscriber(_config(), lambda command: True)
    client = MagicMock()

    subscriber._on_connect(client, None, None, 0)

    client.subscribe.assert_called_once_with(
        "sensel/tenant-a/site-a/edge-a/device/desired/+/v1",
        qos=1,
    )
