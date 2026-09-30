"""Unit tests for the Snort 3 alert_json -> SecurityEvent bridge."""

from __future__ import annotations

import json

from src.detection.external_engine.snort_source import (
    SnortAlertMapper,
    SnortAlertSource,
    map_severity,
    parse_snort_timestamp,
)

_MODBUS_ALERT = {
    "timestamp": "06/18-10:30:00.123456",
    "gid": 1,
    "sid": 100001,
    "rev": 1,
    "priority": 1,
    "class": "Attempted Administrator Privilege Gain",
    "action": "alert",
    "msg": "Unauthorized Modbus TCP access",
    "proto": "TCP",
    "src_addr": "10.10.1.20",
    "src_port": 55321,
    "dst_addr": "10.10.1.100",
    "dst_port": 502,
    "service": "modbus",
    "pkt_num": 48211,
    "iface": "eth1",
}


def test_map_modbus_alert_fields():
    mapper = SnortAlertMapper(site_id="factory-a", sensor_id="ndr-edge-001")
    event = mapper.map(_MODBUS_ALERT)
    payload = event.to_dict()

    assert payload["rule_id"] == "snort-1-100001"
    assert payload["severity"] == "high"
    assert payload["risk_score"] == 85
    assert payload["protocol"] == "tcp"
    assert payload["src_ip"] == "10.10.1.20"
    assert payload["dst_ip"] == "10.10.1.100"
    assert payload["dst_port"] == 502
    assert payload["event_type"] == "SNORT_ALERT"
    assert payload["description"] == "Unauthorized Modbus TCP access"
    assert payload["evidence"]["engine"] == "snort"
    assert payload["evidence"]["sid"] == 100001
    assert payload["evidence"]["raw_event"] == _MODBUS_ALERT
    assert payload["event_id"].startswith("evt-")
    assert "-snort-" in payload["event_id"]


def test_event_id_increments():
    mapper = SnortAlertMapper(site_id="s", sensor_id="n")
    first = mapper.map(_MODBUS_ALERT).event_id
    second = mapper.map(_MODBUS_ALERT).event_id
    assert first != second


def test_map_severity_mapping():
    assert map_severity(1) == "high"
    assert map_severity(2) == "medium"
    assert map_severity(3) == "low"
    assert map_severity(None) == "medium"
    assert map_severity("bogus") == "medium"
    assert map_severity(9) == "medium"


def test_parse_snort_timestamp_adds_year_and_tz():
    ts = parse_snort_timestamp("06/18-10:30:00.123456")
    # ISO8601 UTC, seconds precision, no microseconds.
    assert ts.endswith("+00:00")
    assert "T10:30:00" in ts
    assert ts[:4].isdigit()


def test_parse_snort_timestamp_passthrough_iso():
    iso = "2026-06-18T10:30:00+00:00"
    assert parse_snort_timestamp(iso) == iso


def test_parse_snort_timestamp_fallback_on_garbage():
    ts = parse_snort_timestamp("not-a-timestamp")
    assert ts.endswith("+00:00")


def test_missing_optional_fields_defaults():
    mapper = SnortAlertMapper(site_id="s", sensor_id="n")
    event = mapper.map({"sid": 5, "gid": 1})
    payload = event.to_dict()
    assert payload["protocol"] == "ip"
    assert payload["severity"] == "medium"
    assert payload["description"] == "Snort alert"
    assert "src_ip" not in payload  # empty src omitted by to_dict
    assert "dst_port" not in payload  # None omitted by to_dict


def _write_lines(path, alerts, *, trailing_newline=True):
    text = "\n".join(json.dumps(a) for a in alerts)
    if trailing_newline:
        text += "\n"
    path.write_text(text, encoding="utf-8")


def test_source_poll_writes_events(tmp_path):
    src = tmp_path / "alert_json.txt"
    out_dir = tmp_path / "assets"
    out_dir.mkdir()
    offset = tmp_path / "offset"
    _write_lines(src, [_MODBUS_ALERT, _MODBUS_ALERT])

    source = SnortAlertSource(
        alert_json_path=str(src),
        output_dir=str(out_dir),
        offset_path=str(offset),
        site_id="s",
        sensor_id="n",
    )
    written = source.poll_once()
    assert written == 2

    lines = source.output_path.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 2
    assert json.loads(lines[0])["rule_id"] == "snort-1-100001"


def test_source_offset_only_reads_new_lines(tmp_path):
    src = tmp_path / "alert_json.txt"
    out_dir = tmp_path / "assets"
    out_dir.mkdir()
    offset = tmp_path / "offset"
    _write_lines(src, [_MODBUS_ALERT])

    source = SnortAlertSource(
        alert_json_path=str(src),
        output_dir=str(out_dir),
        offset_path=str(offset),
        site_id="s",
        sensor_id="n",
    )
    assert source.poll_once() == 1
    assert source.poll_once() == 0  # nothing new

    with src.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(_MODBUS_ALERT) + "\n")
    assert source.poll_once() == 1


def test_source_preserves_partial_trailing_line(tmp_path):
    src = tmp_path / "alert_json.txt"
    out_dir = tmp_path / "assets"
    out_dir.mkdir()
    offset = tmp_path / "offset"
    # one complete line + one partial (no newline yet)
    _write_lines(src, [_MODBUS_ALERT], trailing_newline=True)
    with src.open("a", encoding="utf-8") as handle:
        handle.write('{"sid": 7, "gid": 1')  # partial
    source = SnortAlertSource(
        alert_json_path=str(src),
        output_dir=str(out_dir),
        offset_path=str(offset),
        site_id="s",
        sensor_id="n",
    )
    assert source.poll_once() == 1  # only the complete line

    # complete the partial line
    with src.open("a", encoding="utf-8") as handle:
        handle.write(', "priority": 3}\n')
    assert source.poll_once() == 1


def test_source_skips_malformed_lines(tmp_path):
    src = tmp_path / "alert_json.txt"
    out_dir = tmp_path / "assets"
    out_dir.mkdir()
    offset = tmp_path / "offset"
    src.write_text("not json\n" + json.dumps(_MODBUS_ALERT) + "\n", encoding="utf-8")
    source = SnortAlertSource(
        alert_json_path=str(src),
        output_dir=str(out_dir),
        offset_path=str(offset),
        site_id="s",
        sensor_id="n",
    )
    assert source.poll_once() == 1  # malformed skipped, valid kept


def test_source_handles_file_rotation(tmp_path):
    src = tmp_path / "alert_json.txt"
    out_dir = tmp_path / "assets"
    out_dir.mkdir()
    offset = tmp_path / "offset"
    _write_lines(src, [_MODBUS_ALERT, _MODBUS_ALERT, _MODBUS_ALERT])
    source = SnortAlertSource(
        alert_json_path=str(src),
        output_dir=str(out_dir),
        offset_path=str(offset),
        site_id="s",
        sensor_id="n",
    )
    assert source.poll_once() == 3

    # Snort rotated the file: now smaller than the saved offset.
    _write_lines(src, [_MODBUS_ALERT])
    assert source.poll_once() == 1  # offset reset, reads from start


def test_source_missing_file_is_noop(tmp_path):
    source = SnortAlertSource(
        alert_json_path=str(tmp_path / "does-not-exist.txt"),
        output_dir=str(tmp_path),
        offset_path=str(tmp_path / "offset"),
        site_id="s",
        sensor_id="n",
    )
    assert source.poll_once() == 0
