"""Advanced IEC 61850 detection: stNum wrap, OT-015 MMS rate, OT-017 silence."""

from __future__ import annotations

import time
from pathlib import Path

from service_loader import import_from_service

ROOT = Path(__file__).resolve().parents[2]


def _import():
    detection, goose, mms, loader = import_from_service(
        "packet-sensor",
        "src.detection.iec61850",
        "src.parser.l7.iec61850.goose",
        "src.parser.l7.iec61850.mms",
        "src.policy.loader",
    )
    return detection.Iec61850Detector, goose.GooseFrame, mms.MmsObservation, loader.load_policy


def _detector():
    Iec61850Detector, GooseFrame, MmsObservation, load_policy = _import()
    policy = load_policy(str(ROOT / "config/policy/baseline.example.json"))
    return Iec61850Detector(site_id="s", sensor_id="x", policy=policy), GooseFrame, MmsObservation


def _goose(GooseFrame, st, sq=1, mac="aa:bb:cc:dd:ee:ff", appid=4000, gocb="rogue/gcb"):
    return GooseFrame(
        publisher_mac=mac, appid=appid, gocb_ref=gocb, go_id="g",
        st_num=st, sq_num=sq, test=False, conf_rev=1, raw_length=120,
    )


def test_stnum_wrap_is_not_flagged() -> None:
    det, GooseFrame, _ = _detector()
    det.evaluate_goose(_goose(GooseFrame, st=(1 << 32) - 1))
    events = det.evaluate_goose(_goose(GooseFrame, st=2, sq=2))  # 2**32-1 -> 2 wraps (+3)
    assert not [e for e in events if e.rule_id == "OT-013"]


def test_stnum_rollback_is_flagged() -> None:
    det, GooseFrame, _ = _detector()
    det.evaluate_goose(_goose(GooseFrame, st=50))
    events = det.evaluate_goose(_goose(GooseFrame, st=2, sq=2))
    ot013 = [e for e in events if e.rule_id == "OT-013"]
    assert ot013 and ot013[0].evidence["anomaly"] == "rollback"


def test_stnum_forward_jump_is_flagged() -> None:
    det, GooseFrame, _ = _detector()
    det.evaluate_goose(_goose(GooseFrame, st=50))
    events = det.evaluate_goose(_goose(GooseFrame, st=500, sq=2))
    ot013 = [e for e in events if e.rule_id == "OT-013"]
    assert ot013 and ot013[0].evidence["anomaly"] == "forward_jump"


def test_ot017_goose_silence_fires_after_max_silence() -> None:
    det, GooseFrame, _ = _detector()
    # baselined publisher (matches baseline.example.json → asset ied-01, 30s)
    det.evaluate_goose(_goose(GooseFrame, st=1, mac="00:11:22:33:44:55",
                              appid=1000, gocb="simpleIOGenericIO/LLN0.gcbEvents"))
    fresh = det.evaluate_goose_silence(now=time.time())
    assert not [e for e in fresh if e.rule_id == "OT-017"]
    late = det.evaluate_goose_silence(now=time.time() + 600)
    ot017 = [e for e in late if e.rule_id == "OT-017"]
    assert ot017 and ot017[0].severity == "high"
    # recovers, then can fire again
    det.evaluate_goose(_goose(GooseFrame, st=2, sq=2, mac="00:11:22:33:44:55",
                              appid=1000, gocb="simpleIOGenericIO/LLN0.gcbEvents"))
    assert not det.evaluate_goose_silence(now=time.time())


def test_ot015_mms_session_rate() -> None:
    det, _, MmsObservation = _detector()
    fired = []
    for i in range(25):  # threshold is 20/min
        obs = MmsObservation(
            src_ip=f"10.0.0.{i}", dst_ip="192.168.10.50",
            src_port=40000 + i, dst_port=102, pdu_type="read", payload_len=10,
        )
        fired += [e.rule_id for e in det.evaluate_mms(obs)]
    assert "OT-015" in fired
