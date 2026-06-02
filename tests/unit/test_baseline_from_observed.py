"""Candidate baseline from observed/learned state: structure, schema, detector."""

from __future__ import annotations

from pathlib import Path

from service_loader import import_from_service


def _mods():
    return import_from_service(
        "packet-sensor",
        "src.policy.from_observed",
        "src.policy.schema",
        "src.detection.iec61850",
        "src.parser.l7.iec61850.goose",
        "src.parser.l7.iec61850.mms",
        "src.assets.store",
        "src.assets.inventory",
    )


def _observed():
    from_obs, *_ = _mods()
    return from_obs.derive_baseline_from_observed(
        known_ips={"192.168.10.50", "192.168.10.10"},
        goose_keys={"00:11:22:33:44:55|1000|simpleIO/LLN0.gcb"},
        mms_pairs={"192.168.10.10->192.168.10.50:102"},
        site_id="lab",
    )


def test_structure_and_keys() -> None:
    baseline = _observed()
    assert {a["asset_id"] for a in baseline["assets"]} == {"host-192.168.10.50", "host-192.168.10.10"}
    pub = baseline["iec61850"]["goose_publishers"][0]
    assert pub["publisher_mac"] == "00:11:22:33:44:55"   # observed source MAC
    assert pub["appid"] == 1000
    ied = baseline["iec61850"]["mms_ieds"][0]
    assert ied["ied_ip"] == "192.168.10.50"
    assert ied["allowed_mms_clients"] == ["192.168.10.10"]


def test_schema_clean_and_detector_behaviour() -> None:
    _, schema, iec, goose, mms, *_ = _mods()
    baseline = _observed()
    assert schema.validate_policy(baseline) == []

    detector = iec.Iec61850Detector(site_id="lab", sensor_id="x", policy=baseline)

    def gframe(appid, mac):
        return goose.GooseFrame(
            publisher_mac=mac, appid=appid, gocb_ref="x", go_id="g",
            st_num=1, sq_num=1, test=False, conf_rev=1, raw_length=100,
        )

    # Observed publisher (mac+appid) is known -> no OT-011; an unseen one alerts.
    assert not [e for e in detector.evaluate_goose(gframe(1000, "00:11:22:33:44:55")) if e.rule_id == "OT-011"]
    assert [e for e in detector.evaluate_goose(gframe(0x2222, "02:99:99:99:99:99")) if e.rule_id == "OT-011"]

    def obs(src):
        return mms.MmsObservation(src_ip=src, dst_ip="192.168.10.50", src_port=44000,
                                  dst_port=102, pdu_type="read", payload_len=10)

    assert not [e for e in detector.evaluate_mms(obs("192.168.10.10")) if e.rule_id == "OT-018"]
    assert "OT-018" in {e.rule_id for e in detector.evaluate_mms(obs("192.168.10.231"))}


def test_baseline_from_state_db_roundtrip(tmp_path: Path) -> None:
    from_obs, _schema, iec_mod, _goose, _mms, store_mod, inv_mod = _mods()

    inv = inv_mod.AssetInventory()
    inv.known_ips.update({"192.168.10.50", "192.168.10.10"})
    iec = iec_mod.Iec61850Detector(site_id="", sensor_id="", policy={})
    iec.known_goose.add("00:11:22:33:44:55|1000|gcb")
    iec.known_mms_pairs.add("192.168.10.10->192.168.10.50:102")

    db = tmp_path / "learned.db"
    s = store_mod.StateStore(str(db))
    s.save(inv, iec)
    s.close()

    baseline = from_obs.baseline_from_state_db(str(db), site_id="lab")
    assert baseline["iec61850"]["goose_publishers"][0]["appid"] == 1000
    assert baseline["iec61850"]["mms_ieds"][0]["ied_ip"] == "192.168.10.50"
