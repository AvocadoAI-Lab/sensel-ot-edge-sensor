"""PolicyAckReporter: MQTT-first with HTTP fallback to the internal ingest API."""

from __future__ import annotations

from pathlib import Path

from src.config.settings import (
    AppConfig,
    LoggingConfig,
    PolicySyncConfig,
    SenselConfig,
    SensorIdentity,
)
from src.policy import policy_ack as pa
from src.policy.policy_ack import PolicyAckReporter


def _config() -> AppConfig:
    return AppConfig(
        sensor=SensorIdentity(id="ot-edge-1", site_id="site-1"),
        sensel=SenselConfig(api_url="http://cp.local", api_key="ingest-secret"),
        policy_sync=PolicySyncConfig(policy_ack_http_fallback_enabled=True),
        logging=LoggingConfig(),
    )


class _FakeResp:
    status_code = 200
    text = ""


class _FakeClient:
    captured: dict = {}

    def __init__(self, *a, **k):
        pass

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def post(self, url, json, headers):
        _FakeClient.captured = {"url": url, "json": json, "headers": headers}
        return _FakeResp()


class _Mqtt:
    def __init__(self, enabled: bool, ok: bool):
        self.enabled = enabled
        self._ok = ok
        self.calls = 0

    def publish_policy_ack(self, ack):
        self.calls += 1
        return self._ok


def test_reporter_uses_mqtt_when_available(monkeypatch):
    _FakeClient.captured = {}
    monkeypatch.setattr(pa.httpx, "Client", _FakeClient)
    mqtt = _Mqtt(enabled=True, ok=True)
    PolicyAckReporter(_config(), mqtt).report({"artifact_type": "ids_rule", "status": "ack"})
    assert mqtt.calls == 1
    assert _FakeClient.captured == {}  # no HTTP fallback


def test_reporter_http_fallback_when_mqtt_down(monkeypatch):
    _FakeClient.captured = {}
    monkeypatch.setattr(pa.httpx, "Client", _FakeClient)
    mqtt = _Mqtt(enabled=True, ok=False)  # publish fails → fallback
    PolicyAckReporter(_config(), mqtt).report(
        {"artifact_type": "ids_rule", "status": "nack", "tenant_id": "t1"}
    )
    cap = _FakeClient.captured
    assert cap["url"] == "http://cp.local/api/v1/internal/ot-security/policy-ack"
    assert cap["headers"]["X-Ot-Security-Ingest-Secret"] == "ingest-secret"
    assert cap["json"]["sensor_id"] == "ot-edge-1"  # injected
    assert cap["json"]["tenant_id"] == "t1"


def test_reporter_http_fallback_when_mqtt_disabled(monkeypatch):
    _FakeClient.captured = {}
    monkeypatch.setattr(pa.httpx, "Client", _FakeClient)
    PolicyAckReporter(_config(), None).report({"artifact_type": "listfile", "status": "ack"})
    assert _FakeClient.captured["url"].endswith("/api/v1/internal/ot-security/policy-ack")
