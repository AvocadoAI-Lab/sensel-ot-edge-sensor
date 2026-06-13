"""Unit tests for the OT-005 ephemeral destination-port gate.

OT-005 (NEW_DESTINATION_PORT) used to fire for every previously unseen
`dst_ip:dst_port`, including the client-side ephemeral ports that appear on the
return leg of normal outbound flows — pure noise on IT/mixed segments. The gate
suppresses ephemeral dst ports while leaving genuine scan fan-out (OT-006) intact.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.assets.inventory import InventoryObservation
from src.detection.mvp import MvpDetector


def _detector(policy: dict | None = None, rules: set[str] | None = None) -> MvpDetector:
    return MvpDetector(
        site_id="site-1",
        sensor_id="sensor-1",
        policy=policy or {},
        rules_enabled=rules if rules is not None else {"OT-005"},
    )


def _obs(dst_port: int, *, src_ip: str = "10.0.0.5", dst_ip: str = "10.0.0.9") -> InventoryObservation:
    return InventoryObservation(
        src_mac=None, src_ip=src_ip, dst_ip=dst_ip, dst_port=dst_port, protocol="tcp"
    )


def _rule_ids(events) -> list[str]:
    return [e.rule_id for e in events]


def test_ephemeral_dst_port_suppressed() -> None:
    det = _detector()
    events = det.evaluate_observation(_obs(51000))
    assert "OT-005" not in _rule_ids(events)


def test_low_service_port_still_fires() -> None:
    det = _detector()
    events = det.evaluate_observation(_obs(30005))  # < default 32768
    assert "OT-005" in _rule_ids(events)


def test_well_known_port_still_fires() -> None:
    det = _detector()
    events = det.evaluate_observation(_obs(102))  # MMS / typical OT service port
    assert "OT-005" in _rule_ids(events)


def test_gate_disabled_by_threshold_zero() -> None:
    det = _detector(policy={"thresholds": {"ot005_ephemeral_dst_min": 0}})
    events = det.evaluate_observation(_obs(51000))
    assert "OT-005" in _rule_ids(events)


def test_scan_to_ephemeral_ports_still_caught_by_ot006() -> None:
    # Even with OT-005 gated, a fan-out scan across ephemeral ports must still
    # raise OT-006 (port-scan behavior), which samples every port.
    det = _detector(rules={"OT-005", "OT-006"})
    fired = []
    for port in range(40000, 40020):  # 20 ephemeral ports, one src
        fired += det.evaluate_observation(_obs(port, src_ip="10.0.0.66"))
    rule_ids = _rule_ids(fired)
    assert "OT-006" in rule_ids
    assert "OT-005" not in rule_ids


def main() -> int:
    tests = [
        test_ephemeral_dst_port_suppressed,
        test_low_service_port_still_fires,
        test_well_known_port_still_fires,
        test_gate_disabled_by_threshold_zero,
        test_scan_to_ephemeral_ports_still_caught_by_ot006,
    ]
    failed = 0
    for t in tests:
        try:
            t()
            print(f"\u2713 {t.__name__}")
        except Exception as exc:  # noqa: BLE001
            failed += 1
            print(f"\u2717 {t.__name__}: {exc}")
            import traceback

            traceback.print_exc()
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
