from __future__ import annotations

from src.features.publisher import FeaturePublisher
from src.parser.l2.ethernet import L2Stats
from src.parser.l7.iec61850.goose import GooseStats, reset_goose_window
from src.parser.l7.iec61850.mms import MmsStats, reset_mms_window


def test_aggregate_summary_emits_complete_feature_contract(tmp_path) -> None:
    publisher = FeaturePublisher(
        sensor_id="sensor-a",
        site_id="site-a",
        output_dir=str(tmp_path),
    )
    l2 = L2Stats(
        window_total=600,
        window_mac_counts={"00:11:22:33:44:55": 400, "00:11:22:33:44:66": 200},
    )
    goose = GooseStats(message_count=4, stnum_changes=1, test_flag_count=2)
    mms = MmsStats(read_count=3, write_count=1, report_count=2)
    mms.session_keys.add("session-a")

    summary = publisher.publish_window(l2, 60, goose=goose, mms=mms)

    assert summary["feature_contract_id"] == "ot-window-v1"
    assert summary["packet_count"] == 600
    assert summary["packet_rate"] == 10.0
    assert summary["unique_mac_count"] == 2
    assert summary["goose_message_count"] == 4
    assert summary["goose_stnum_changes"] == 1
    assert summary["goose_test_flag_count"] == 2
    assert summary["mms_session_count"] == 1
    assert summary["mms_read_count"] == 3
    assert summary["mms_write_count"] == 1
    assert summary["mms_report_count"] == 2


def test_protocol_counters_reset_between_feature_windows() -> None:
    goose = GooseStats(message_count=4, stnum_changes=1, test_flag_count=2)
    goose.publishers["publisher-a"] = object()  # type: ignore[assignment]
    goose._last_stnum["publisher-a"] = 7
    mms = MmsStats(read_count=3, write_count=1, report_count=2, other_count=1)
    mms.session_keys.add("session-a")

    reset_goose_window(goose)
    reset_mms_window(mms)

    assert goose.message_count == 0
    assert goose.publishers == {}
    assert goose._last_stnum == {"publisher-a": 7}
    assert mms.session_keys == set()
    assert mms.read_count == mms.write_count == mms.report_count == 0
