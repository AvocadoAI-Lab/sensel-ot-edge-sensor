"""IEC 61850 SCL/SCD parser unit tests."""

from __future__ import annotations

from pathlib import Path

import pytest

from service_loader import import_from_service

ROOT = Path(__file__).resolve().parents[2]
SAMPLE = ROOT / "lab" / "61850" / "sample.scd"


def _scd():
    return import_from_service("packet-sensor", "src.parser.scl.scd")


def test_parse_appid_hex_then_decimal_fallback() -> None:
    scd = _scd()
    assert scd.parse_appid("03E8") == 1000      # hex per IEC 61850-6
    assert scd.parse_appid("1000", base=16) == 0x1000
    assert scd.parse_appid("not-hex") is None
    assert scd.parse_appid("") is None


def test_parse_sample_ied_inventory() -> None:
    scd = _scd()
    model = scd.parse_scd(SAMPLE)
    by_name = {ied.ied_name: ied for ied in model.ieds}
    assert set(by_name) == {"ied-01", "hmi-01"}
    assert by_name["ied-01"].ip == "192.168.10.50"
    assert by_name["ied-01"].has_server is True
    assert by_name["hmi-01"].ip == "192.168.10.10"
    assert by_name["hmi-01"].has_server is False
    assert [s.ied_name for s in model.servers()] == ["ied-01"]


def test_parse_sample_goose_control() -> None:
    scd = _scd()
    model = scd.parse_scd(SAMPLE)
    assert len(model.goose) == 1
    g = model.goose[0]
    assert g.ied_name == "ied-01"
    assert g.appid == 1000                      # 0x03E8
    assert g.appid_in_goose_range is True
    assert g.dst_mac == "01:0c:cd:01:00:01"     # normalised, metadata only
    assert g.vlan_id == 5
    assert g.max_time_ms == 2000
    assert g.gocb_ref == "ied-01LD0/LLN0.gcbEvents"


def test_missing_file_raises() -> None:
    scd = _scd()
    with pytest.raises(FileNotFoundError):
        scd.parse_scd(ROOT / "does-not-exist.scd")


def test_non_scl_xml_raises(tmp_path: Path) -> None:
    scd = _scd()
    bad = tmp_path / "bad.xml"
    bad.write_text("<root><nope/></root>", encoding="utf-8")
    with pytest.raises(ValueError):
        scd.parse_scd(bad)
