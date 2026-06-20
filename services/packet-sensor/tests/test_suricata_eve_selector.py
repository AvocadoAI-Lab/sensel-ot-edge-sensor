"""Unit tests for the bounded Suricata EVE selector (PRD EDGE-1.2 / EDGE-1.3)."""

from __future__ import annotations

from src.detection.external_engine.eve_selector import (
    EveRecordMapper,
    EveSelector,
    EveSelectorConfig,
    map_eve_records,
)

_ALERT = {
    "timestamp": "2026-06-18T10:30:00.000000+0000",
    "flow_id": 1,
    "event_type": "alert",
    "src_ip": "192.168.80.131",
    "dest_ip": "192.168.80.130",
    "dest_port": 80,
    "proto": "TCP",
    "app_proto": "http",
    "alert": {"gid": 1, "signature_id": 2001, "signature": "ET WEB probe", "severity": 1},
}

_HTTP = {
    "timestamp": "2026-06-18T10:30:01.000000+0000",
    "flow_id": 2,
    "event_type": "http",
    "src_ip": "192.168.80.131",
    "dest_ip": "192.168.80.130",
    "dest_port": 80,
    "proto": "TCP",
    "app_proto": "http",
    "http": {"hostname": "192.168.80.130", "http_method": "GET", "url": "/relay"},
}

_FLOW = {
    "timestamp": "2026-06-18T10:30:02.000000+0000",
    "flow_id": 3,
    "event_type": "flow",
    "src_ip": "192.168.80.131",
    "dest_ip": "192.168.80.130",
    "proto": "TCP",
    "app_proto": "failed",
}

_DNS = {"event_type": "dns", "dest_ip": "8.8.8.8", "dns": {"rrname": "evil.example"}}


def test_default_is_alert_only():
    cfg = EveSelectorConfig()
    sel = EveSelector(cfg)
    assert sel.should_emit(_ALERT) is True
    assert sel.should_emit(_HTTP) is False
    assert sel.should_emit(_FLOW) is False


def test_from_env_parses_selector():
    cfg = EveSelectorConfig.from_env(
        {
            "SURICATA_EVE_EVENT_TYPES": "alert,http,flow",
            "SURICATA_EVE_SAMPLE": "flow:10",
            "SURICATA_EVE_RATE_LIMIT": "http:2,flow:5",
            "SURICATA_EVE_PROTO_ALLOWLIST": "http,modbus",
        }
    )
    assert cfg.event_types == ("alert", "http", "flow")
    assert cfg.sample_rates == {"flow": 10}
    assert cfg.rate_limit_per_min == {"http": 2, "flow": 5}
    assert cfg.proto_allowlist == ("http", "modbus")


def test_from_env_unknown_types_fall_back_to_alert():
    cfg = EveSelectorConfig.from_env({"SURICATA_EVE_EVENT_TYPES": "bogus,nonsense"})
    assert cfg.event_types == ("alert",)


def test_selector_enables_http():
    sel = EveSelector(EveSelectorConfig(event_types=("alert", "http")))
    assert sel.should_emit(_HTTP) is True
    assert sel.should_emit(_FLOW) is False


def test_proto_allowlist_filters_non_alert_only():
    sel = EveSelector(
        EveSelectorConfig(event_types=("alert", "http", "flow"), proto_allowlist=("http",))
    )
    assert sel.should_emit(_HTTP) is True  # app_proto http allowed
    assert sel.should_emit(_FLOW) is False  # app_proto "failed" not allowed
    assert sel.should_emit(_ALERT) is True  # alerts bypass proto allowlist


def test_sampling_keeps_one_in_n():
    sel = EveSelector(EveSelectorConfig(event_types=("flow",), sample_rates={"flow": 3}))
    kept = [sel.should_emit(_FLOW) for _ in range(9)]
    # 1-in-3 -> keep indices 0,3,6
    assert kept == [True, False, False, True, False, False, True, False, False]


def test_rate_limit_per_minute_window():
    now = {"t": 1000.0}
    sel = EveSelector(
        EveSelectorConfig(event_types=("http",), rate_limit_per_min={"http": 2}),
        clock=lambda: now["t"],
    )
    assert sel.should_emit(_HTTP) is True
    assert sel.should_emit(_HTTP) is True
    assert sel.should_emit(_HTTP) is False  # over cap in same window
    now["t"] += 61.0  # next window
    assert sel.should_emit(_HTTP) is True


def test_mapper_maps_non_alert_to_ndr_observed():
    mapper = EveRecordMapper(site_id="lab-ot-site", sensor_id="ndr-edge-001")
    http_event = mapper.map(_HTTP).to_dict()
    assert http_event["event_type"] == "NDR_HTTP_OBSERVED"
    assert http_event["target_ip"] == "192.168.80.130"
    assert http_event["protocol"] == "http"
    assert http_event["severity"] == "info"
    assert http_event["raw_ref"] == "suricata:eve:flow_id=2"
    assert "192.168.80.130" in http_event["description"]

    dns_event = mapper.map(_DNS).to_dict()
    assert dns_event["event_type"] == "NDR_DNS_OBSERVED"
    assert "evil.example" in dns_event["description"]


def test_mapper_delegates_alert_to_suricata_mapper():
    mapper = EveRecordMapper(site_id="lab-ot-site", sensor_id="ndr-edge-001")
    alert = mapper.map(_ALERT).to_dict()
    assert alert["event_type"] == "SURICATA_ALERT"
    assert alert["rule_id"] == "suricata-1-2001"
    assert alert["target_ip"] == "192.168.80.130"


def test_map_eve_records_applies_selector():
    sel = EveSelector(EveSelectorConfig(event_types=("alert", "http")))
    mapper = EveRecordMapper(site_id="lab-ot-site", sensor_id="ndr-edge-001")
    events = map_eve_records([_ALERT, _HTTP, _FLOW, _DNS], mapper=mapper, selector=sel)
    types = [e.event_type for e in events]
    assert types == ["SURICATA_ALERT", "NDR_HTTP_OBSERVED"]
