from types import SimpleNamespace

from src.config.settings import (
    AppConfig,
    NorthboundMqttConfig,
    SensorIdentity,
    SenselConfig,
)
from src.edgex.mqtt_subscriber import DesiredDeviceStateSubscriber

from test_edgex_reconciliation import _command


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
        payload=_command().SerializeToString(),
        properties=SimpleNamespace(
            ContentType=(
                "application/x-protobuf; "
                "message=sensel.device.v1.DesiredDeviceStateCommand"
            ),
            PayloadFormatIndicator=0,
        ),
    )

    subscriber._on_message(None, None, message)

    assert subscriber.accepted == 1
    assert accepted[0].command_id == "cmd-1"


def test_desired_subscriber_rejects_missing_content_type() -> None:
    subscriber = DesiredDeviceStateSubscriber(_config(), lambda command: True)
    message = SimpleNamespace(
        payload=_command().SerializeToString(),
        properties=SimpleNamespace(PayloadFormatIndicator=0),
    )

    subscriber._on_message(None, None, message)

    assert subscriber.rejected == 1
