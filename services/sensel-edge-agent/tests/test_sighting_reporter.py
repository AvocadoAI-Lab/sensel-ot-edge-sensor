"""Tests for SMB sighting reporter (Track B-S3)."""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import httpx
import pytest

from src.config.settings import (
    AppConfig,
    LoggingConfig,
    NorthboundMqttConfig,
    PolicySyncConfig,
    SensorIdentity,
    SenselConfig,
    SightingReportConfig,
)
from src.sighting.queue import QueuedSighting, SightingQueue
from src.sighting.reporter import SightingReporter, build_sighting_ingest_payload


def _config(
    tmp_path: Path,
    *,
    intel_key: str = "test-intel-key",
    snort_sighting_enabled: bool = False,
    snort_cti_sid_min: int = 0,
    snort_cti_sid_max: int = 0,
) -> AppConfig:
    events_path = tmp_path / "security-events.jsonl"
    return AppConfig(
        sensor=SensorIdentity(id="ot-edge-001", site_id="factory-lab-001"),
        sensel=SenselConfig(
            api_url="http://192.168.1.108:8081",
            api_key="ingest-key",
            verify_tls=False,
            events={
                "watch_path": str(events_path),
                "offset_path": str(tmp_path / "events.offset"),
                "snort_watch_path": str(tmp_path / "snort-events.jsonl"),
                "snort_offset_path": str(tmp_path / "snort-events.offset"),
            },
        ),
        northbound_mqtt=NorthboundMqttConfig(tenant_id="sensel-platform"),
        policy_sync=PolicySyncConfig(smb_intel_api_key=intel_key),
        sighting_report=SightingReportConfig(
            enabled=True,
            queue_path=str(tmp_path / "sighting-queue.jsonl"),
            events_offset_path=str(tmp_path / "sighting-events.offset"),
            snort_events_offset_path=str(tmp_path / "sighting-snort-events.offset"),
            smb_intel_api_key=intel_key,
            interval_sec=10,
            max_attempts=3,
            backoff_base_sec=1,
            backoff_max_sec=4,
            snort_sighting_enabled=snort_sighting_enabled,
            snort_cti_sid_min=snort_cti_sid_min,
            snort_cti_sid_max=snort_cti_sid_max,
        ),
        logging=LoggingConfig(),
    )


def _snort_cti_event(event_id: str = "evt-20260618-snort-00001", sid: int = 9000001) -> dict:
    return {
        "event_id": event_id,
        "site_id": "factory-lab-001",
        "sensor_id": "ot-edge-001",
        "event_type": "SNORT_ALERT",
        "severity": "high",
        "rule_id": f"snort-1-{sid}",
        "protocol": "tcp",
        "description": "SENSEL CTI C2 beacon",
        "timestamp": "2026-06-18T10:30:00+00:00",
        "risk_score": 85,
        "src_ip": "10.10.1.20",
        "dst_ip": "203.0.113.10",
        "dst_port": 443,
        "evidence": {
            "engine": "snort",
            "sid": sid,
            "gid": 1,
            "classtype": "trojan-activity",
        },
    }


def _ot019_event(event_id: str = "evt-20260601-ioc-00001") -> dict:
    return {
        "event_id": event_id,
        "site_id": "factory-lab-001",
        "sensor_id": "ot-edge-001",
        "event_type": "CTI_IOC_OBSERVED",
        "severity": "high",
        "rule_id": "OT-019",
        "protocol": "tcp",
        "description": "CTI blacklist IPv4 observed on mirror (passive)",
        "timestamp": "2026-06-01T22:27:37+00:00",
        "risk_score": 90,
        "evidence": {
            "ioc_type": "ipv4",
            "ioc_value": "203.0.113.55",
            "intel_item_id": "item-abc",
            "artifact_version": "20260601-001",
            "direction": "src",
            "mirror_passive": True,
        },
        "src_ip": "203.0.113.55",
        "dst_ip": "192.168.10.50",
        "dst_port": 102,
    }


def test_build_sighting_ingest_payload_maps_ot019(tmp_path: Path) -> None:
    config = _config(tmp_path)
    payload = build_sighting_ingest_payload(_ot019_event(), config)
    assert payload is not None
    assert payload["source_system"] == "ndr"
    raw = payload["raw_event"]
    assert raw["event_type"] == "cti_ioc_observed"
    assert raw["ioc_value"] == "203.0.113.55"
    assert raw["intel_item_id"] == "item-abc"
    assert payload["defaults"]["source_event_type"] == "CTI_IOC_OBSERVED"
    assert payload["defaults"]["confidence"] == 90


def test_build_sighting_ingest_payload_ignores_non_cti(tmp_path: Path) -> None:
    config = _config(tmp_path)
    event = _ot019_event()
    event["event_type"] = "MMS_WRITE_ANOMALY"
    assert build_sighting_ingest_payload(event, config) is None


def test_sighting_queue_dedupes_by_event_id(tmp_path: Path) -> None:
    queue = SightingQueue(str(tmp_path / "queue.jsonl"))
    payload = {"raw_event": {"event_id": "evt-1"}}
    queue.enqueue(QueuedSighting(event_id="evt-1", payload=payload))
    queue.enqueue(QueuedSighting(event_id="evt-1", payload=payload))
    assert len(queue.load_all()) == 1


def test_sighting_reporter_posts_new_event(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    config = _config(tmp_path)
    events_path = Path(config.sensel.events.watch_path)
    events_path.write_text(json.dumps(_ot019_event()) + "\n", encoding="utf-8")

    calls: list[dict] = []

    class FakeClient:
        def __init__(self, *args, **kwargs) -> None:
            pass

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def post(self, url, headers=None, json=None):
            calls.append({"url": url, "headers": headers, "json": json})
            request = httpx.Request("POST", url)
            return httpx.Response(
                200,
                json={
                    "sighting": {"sighting_id": "sig-001", "tenant_id": "sensel-platform"},
                    "correlation": {"matched": True},
                },
                request=request,
            )

    monkeypatch.setattr("src.sighting.reporter.httpx.Client", FakeClient)

    reporter = SightingReporter(config)
    assert reporter.process_new_events() == 1
    assert calls
    assert calls[0]["headers"]["X-API-Key"] == "test-intel-key"
    assert calls[0]["json"]["raw_event"]["ioc_value"] == "203.0.113.55"
    assert not reporter._queue.load_all()


def test_sighting_reporter_queues_failed_post(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    config = _config(tmp_path)
    events_path = Path(config.sensel.events.watch_path)
    events_path.write_text(json.dumps(_ot019_event("evt-fail")) + "\n", encoding="utf-8")

    class FakeClient:
        def __init__(self, *args, **kwargs) -> None:
            pass

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def post(self, url, headers=None, json=None):
            request = httpx.Request("POST", url)
            return httpx.Response(503, text="unavailable", request=request)

    monkeypatch.setattr("src.sighting.reporter.httpx.Client", FakeClient)

    reporter = SightingReporter(config)
    assert reporter.process_new_events() == 0
    queued = reporter._queue.load_all()
    assert len(queued) == 1
    assert queued[0].event_id == "evt-fail"
    assert queued[0].attempts == 1


def test_sighting_reporter_flush_queue_retries_due_items(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    config = _config(tmp_path)
    reporter = SightingReporter(config)
    payload = build_sighting_ingest_payload(_ot019_event("evt-retry"), config)
    assert payload is not None
    past = (datetime.now(timezone.utc) - timedelta(seconds=30)).isoformat()
    reporter._queue.rewrite(
        [
            QueuedSighting(
                event_id="evt-retry",
                payload=payload,
                attempts=1,
                next_retry_at=past,
            )
        ]
    )

    class FakeClient:
        def __init__(self, *args, **kwargs) -> None:
            pass

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def post(self, url, headers=None, json=None):
            request = httpx.Request("POST", url)
            return httpx.Response(
                200,
                json={"sighting": {"sighting_id": "sig-retry"}, "correlation": {"matched": False}},
                request=request,
            )

    monkeypatch.setattr("src.sighting.reporter.httpx.Client", FakeClient)
    assert reporter.flush_queue() == 1
    assert reporter._queue.load_all() == []


def test_snort_cti_payload_disabled_by_default(tmp_path: Path) -> None:
    config = _config(tmp_path)  # snort sighting disabled
    assert build_sighting_ingest_payload(_snort_cti_event(), config) is None


def test_snort_cti_payload_built_when_enabled_and_in_range(tmp_path: Path) -> None:
    config = _config(
        tmp_path,
        snort_sighting_enabled=True,
        snort_cti_sid_min=9000000,
        snort_cti_sid_max=9999999,
    )
    payload = build_sighting_ingest_payload(_snort_cti_event(sid=9000001), config)
    assert payload is not None
    assert payload["source_system"] == "ndr"
    raw = payload["raw_event"]
    assert raw["event_type"] == "snort_cti_observed"
    assert raw["ioc_type"] == "ipv4"
    assert raw["ioc_value"] == "203.0.113.10"  # external dst_ip
    assert raw["matched_field"] == "dst_ip"
    assert raw["snort_sid"] == 9000001
    assert payload["defaults"]["source_event_type"] == "SNORT_CTI_OBSERVED"
    assert payload["defaults"]["confidence"] == 85


def test_snort_cti_payload_none_when_sid_out_of_range(tmp_path: Path) -> None:
    config = _config(
        tmp_path,
        snort_sighting_enabled=True,
        snort_cti_sid_min=9000000,
        snort_cti_sid_max=9999999,
    )
    # Generic Snort rule (community SID) -> not a CTI sighting.
    assert build_sighting_ingest_payload(_snort_cti_event(sid=1000001), config) is None


def test_snort_cti_payload_falls_back_to_src_ip(tmp_path: Path) -> None:
    config = _config(
        tmp_path,
        snort_sighting_enabled=True,
        snort_cti_sid_min=9000000,
        snort_cti_sid_max=9999999,
    )
    event = _snort_cti_event()
    event["dst_ip"] = ""
    payload = build_sighting_ingest_payload(event, config)
    assert payload is not None
    assert payload["raw_event"]["ioc_value"] == "10.10.1.20"
    assert payload["raw_event"]["matched_field"] == "src_ip"


def test_reporter_processes_snort_cti_from_second_tailer(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config = _config(
        tmp_path,
        snort_sighting_enabled=True,
        snort_cti_sid_min=9000000,
        snort_cti_sid_max=9999999,
    )
    snort_path = Path(config.sensel.events.snort_watch_path)
    snort_path.write_text(json.dumps(_snort_cti_event()) + "\n", encoding="utf-8")

    calls: list[dict] = []

    class FakeClient:
        def __init__(self, *args, **kwargs) -> None:
            pass

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def post(self, url, headers=None, json=None):
            calls.append({"json": json})
            request = httpx.Request("POST", url)
            return httpx.Response(
                200,
                json={"sighting": {"sighting_id": "sig-snort"}, "correlation": {"matched": True}},
                request=request,
            )

    monkeypatch.setattr("src.sighting.reporter.httpx.Client", FakeClient)

    reporter = SightingReporter(config)
    assert reporter.process_new_events() == 1
    assert calls[0]["json"]["raw_event"]["ioc_value"] == "203.0.113.10"
    assert calls[0]["json"]["raw_event"]["event_type"] == "snort_cti_observed"


def test_reporter_skips_snort_tailer_when_disabled(tmp_path: Path) -> None:
    config = _config(tmp_path)  # disabled
    snort_path = Path(config.sensel.events.snort_watch_path)
    snort_path.write_text(json.dumps(_snort_cti_event()) + "\n", encoding="utf-8")
    reporter = SightingReporter(config)
    assert reporter._snort_tailer is None
    assert reporter.process_new_events() == 0
