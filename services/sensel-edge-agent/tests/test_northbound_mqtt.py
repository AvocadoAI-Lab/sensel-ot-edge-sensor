"""Tests for northbound MQTT non-blocking connect + background auto-reconnect."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from src.config.settings import NorthboundMqttConfig, SensorIdentity
from src.northbound.mqtt import NorthboundMqttClient


def _client_cfg() -> tuple[NorthboundMqttConfig, SensorIdentity]:
    return (
        NorthboundMqttConfig(
            enabled=True,
            host="192.168.1.203",
            port=1883,
            tenant_id="company-test",
        ),
        SensorIdentity(id="ot-edge-001", site_id="site-a"),
    )


def test_ensure_client_created_once_and_reused() -> None:
    cfg, sensor = _client_cfg()
    nb = NorthboundMqttClient(cfg, sensor)

    mock_instance = MagicMock()
    with patch("paho.mqtt.client.Client", return_value=mock_instance) as client_cls, patch(
        "src.northbound.mqtt.write_agent_runtime"
    ):
        first = nb._ensure_client()
        assert first is mock_instance
        client_cls.assert_called_once()
        # Non-blocking connect path: async connect + background loop + backoff.
        mock_instance.connect_async.assert_called_once()
        mock_instance.loop_start.assert_called_once()
        mock_instance.reconnect_delay_set.assert_called_once()
        mock_instance.connect.assert_not_called()

        # Reused, never recreated — paho's loop owns reconnection.
        second = nb._ensure_client()
        assert second is mock_instance
        assert client_cls.call_count == 1


def test_publish_skipped_until_connected() -> None:
    cfg, sensor = _client_cfg()
    nb = NorthboundMqttClient(cfg, sensor)

    mock_instance = MagicMock()
    with patch("paho.mqtt.client.Client", return_value=mock_instance), patch(
        "src.northbound.mqtt.write_agent_runtime"
    ):
        # Background thread has not reported on_connect yet -> no publish, no block.
        assert nb.publish_json("ot-edge/t/events", {"x": 1}) is False
        mock_instance.publish.assert_not_called()
        # Client retained so paho can finish (re)connecting.
        assert nb._client is mock_instance


def test_publish_success_when_connected() -> None:
    cfg, sensor = _client_cfg()
    nb = NorthboundMqttClient(cfg, sensor)

    mock_instance = MagicMock()
    mock_info = MagicMock()
    mock_info.rc = 0
    mock_info.is_published.return_value = True
    mock_instance.publish.return_value = mock_info

    with patch("paho.mqtt.client.Client", return_value=mock_instance), patch(
        "src.northbound.mqtt.write_agent_runtime"
    ):
        nb._ensure_client()
        nb._on_connect(mock_instance, None, None, 0)  # paho reports success
        assert nb.connected is True
        assert nb.publish_json("ot-edge/t/events", {"x": 1}) is True
        mock_instance.publish.assert_called_once()


def test_publish_failure_keeps_client_for_auto_reconnect() -> None:
    cfg, sensor = _client_cfg()
    nb = NorthboundMqttClient(cfg, sensor)

    mock_instance = MagicMock()
    mock_info = MagicMock()
    mock_info.rc = 1
    mock_info.is_published.return_value = False
    mock_instance.publish.return_value = mock_info

    with patch("paho.mqtt.client.Client", return_value=mock_instance), patch(
        "src.northbound.mqtt.write_agent_runtime"
    ):
        nb._ensure_client()
        nb._on_connect(mock_instance, None, None, 0)
        assert nb.publish_json("ot-edge/t/events", {"x": 1}) is False
        # New behavior: do NOT tear the client down; paho's loop reconnects.
        assert nb._client is mock_instance


def test_on_disconnect_marks_down_but_keeps_client() -> None:
    cfg, sensor = _client_cfg()
    nb = NorthboundMqttClient(cfg, sensor)

    mock_instance = MagicMock()
    with patch("paho.mqtt.client.Client", return_value=mock_instance), patch(
        "src.northbound.mqtt.write_agent_runtime"
    ):
        nb._ensure_client()
        nb._on_connect(mock_instance, None, None, 0)
        assert nb.connected is True

        nb._on_disconnect(mock_instance, None, None, 0)
        assert nb.connected is False
        # Client survives the disconnect so the background loop can reconnect.
        assert nb._client is mock_instance


def test_update_credentials_tears_down_for_reconnect() -> None:
    cfg, sensor = _client_cfg()
    nb = NorthboundMqttClient(cfg, sensor)

    mock_instance = MagicMock()
    with patch("paho.mqtt.client.Client", return_value=mock_instance), patch(
        "src.northbound.mqtt.write_agent_runtime"
    ):
        nb._ensure_client()
        assert nb._client is mock_instance

        # New creds -> apply + tear down so _ensure_client rebuilds with them.
        assert nb.update_credentials("ndr-tenant-x", "s3cret") is True
        assert cfg.username == "ndr-tenant-x"
        assert cfg.password == "s3cret"
        assert nb._client is None

        # Idempotent: identical creds do not churn the connection.
        nb._ensure_client()
        assert nb.update_credentials("ndr-tenant-x", "s3cret") is False
        assert nb._client is mock_instance

        # Empty username is ignored.
        assert nb.update_credentials("", "x") is False


def test_update_endpoint_only_bootstraps_when_unset() -> None:
    cfg = NorthboundMqttConfig(enabled=True, host="", port=1883, tenant_id="t")
    sensor = SensorIdentity(id="ot-edge-001", site_id="site-a")
    nb = NorthboundMqttClient(cfg, sensor)

    assert nb.update_endpoint_if_unset("broker.example", 8883) is True
    assert cfg.host == "broker.example"
    assert cfg.port == 8883
    # Already set -> no override.
    assert nb.update_endpoint_if_unset("other.example", 1883) is False
    assert cfg.host == "broker.example"
