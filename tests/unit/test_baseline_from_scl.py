"""SCD-derived baseline: structure, schema-validity, and detector behaviour."""

from __future__ import annotations

from pathlib import Path

from service_loader import import_from_service

ROOT = Path(__file__).resolve().parents[2]
SAMPLE = ROOT / "lab" / "61850" / "sample.scd"


def _mods():
    return import_from_service(
        "packet-sensor",
        "src.policy.from_scl",
        "src.policy.schema",
        "src.detection.iec61850",
        "src.parser.l7.iec61850.goose",
        "src.parser.l7.iec61850.mms",
    )


def _baseline():
    from_scl, *_ = _mods()
    return from_scl.baseline_from_scd(SAMPLE, site_id="lab")


def test_derived_baseline_structure() -> None:
    baseline = _baseline()
    assert baseline["site_id"] == "lab"
    assert {a["asset_id"] for a in baseline["assets"]} == {"ied-01", "hmi-01"}

    pubs = baseline["iec61850"]["goose_publishers"]
    assert len(pubs) == 1
    pub = pubs[0]
    assert pub["asset_id"] == "ied-01"
    assert pub["appid"] == 1000
    assert pub["publisher_mac"] == ""           # matched on APPID, not MAC
    assert pub["max_silence_sec"] == 8.0         # MaxTime 2000ms * 4 / 1000

    ieds = baseline["iec61850"]["mms_ieds"]
    assert len(ieds) == 1
    assert ieds[0]["ied_ip"] == "192.168.10.50"
    assert ieds[0]["allowed_mms_clients"] == ["192.168.10.10"]  # hmi-01 (non-server)


def test_derived_baseline_is_schema_clean() -> None:
    _, schema, *_ = _mods()
    assert schema.validate_policy(_baseline()) == []


def test_goose_appid_match_against_derived_baseline() -> None:
    _, _, iec, goose, _ = _mods()
    detector = iec.Iec61850Detector(site_id="lab", sensor_id="x", policy=_baseline())

    def frame(appid):
        return goose.GooseFrame(
            publisher_mac="aa:bb:cc:dd:ee:ff", appid=appid, gocb_ref="x/LLN0.cb",
            go_id="g", st_num=1, sq_num=1, test=False, conf_rev=1, raw_length=100,
        )

    # Engineered APPID 1000 is known -> no OT-011.
    assert not [e for e in detector.evaluate_goose(frame(1000)) if e.rule_id == "OT-011"]
    # An APPID not in the SCD -> rogue publisher.
    assert [e for e in detector.evaluate_goose(frame(0x2000)) if e.rule_id == "OT-011"]


def test_mms_authorization_against_derived_baseline() -> None:
    _, _, iec, _, mms = _mods()
    detector = iec.Iec61850Detector(site_id="lab", sensor_id="x", policy=_baseline())

    def obs(src):
        return mms.MmsObservation(
            src_ip=src, dst_ip="192.168.10.50", src_port=44000, dst_port=102,
            pdu_type="read", payload_len=10,
        )

    # Engineered client (hmi-01) is allowed.
    assert not [e for e in detector.evaluate_mms(obs("192.168.10.10")) if e.rule_id == "OT-018"]
    # An unknown host hitting the IED is unauthorized.
    rogue = {e.rule_id for e in detector.evaluate_mms(obs("192.168.10.231"))}
    assert "OT-018" in rogue and "OT-014" in rogue
