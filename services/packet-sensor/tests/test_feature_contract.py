from __future__ import annotations

import math
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from src.features.contract import FeatureContractSpec, FeatureSequenceBuilder


REPO_ROOT = Path(__file__).resolve().parents[3]
CONTRACT_PATH = REPO_ROOT / "config/model/feature-contract.ot-window-v1.json"


def _values() -> dict[str, int | float]:
    return {
        "packet_count": 500,
        "packet_rate": 10.0,
        "unique_mac_count": 4,
        "goose_message_count": 1,
        "goose_stnum_changes": 0,
        "goose_test_flag_count": 0,
        "goose_unique_publishers": 1,
        "mms_session_count": 1,
        "mms_read_count": 2,
        "mms_write_count": 0,
        "mms_report_count": 0,
    }


def test_canonical_contract_preserves_feature_order_and_normalization() -> None:
    contract = FeatureContractSpec.load(CONTRACT_PATH)

    assert contract.contract_id == "ot-window-v1"
    assert contract.sequence_length == 60
    assert [feature.name for feature in contract.features][:3] == [
        "packet_count",
        "packet_rate",
        "unique_mac_count",
    ]
    normalized = contract.normalize(_values())
    assert len(normalized) == 11
    assert normalized[0] == pytest.approx(math.log1p(500))
    assert normalized[1] == pytest.approx(math.log1p(10))
    assert normalized[8] == pytest.approx(math.log1p(2))


def test_protocol_specific_features_are_zero_filled() -> None:
    contract = FeatureContractSpec.load(CONTRACT_PATH)

    normalized = contract.normalize(
        {"packet_count": 10, "packet_rate": 1.0, "unique_mac_count": 2}
    )

    assert normalized[3:] == (0.0,) * 8


def test_required_feature_is_rejected_when_missing() -> None:
    contract = FeatureContractSpec.load(CONTRACT_PATH)

    with pytest.raises(ValueError, match="missing required feature: packet_rate"):
        contract.normalize({"packet_count": 1, "unique_mac_count": 1})


def test_sequence_is_ready_at_sixty_frames_and_is_reproducible() -> None:
    contract = FeatureContractSpec.load(CONTRACT_PATH)
    first_builder = FeatureSequenceBuilder(contract)
    second_builder = FeatureSequenceBuilder(contract)
    started = datetime(2026, 8, 12, tzinfo=timezone.utc)
    first = None
    second = None
    for offset in range(60):
        frame = {
            "entity_id": "sensor-golden",
            "observed_at": started + timedelta(minutes=offset),
            "sequence_number": offset + 1,
            "values": _values(),
        }
        first = first_builder.add_frame(**frame)
        second = second_builder.add_frame(**frame)
        if offset < 59:
            assert first is None

    assert first is not None and second is not None
    assert len(first.frames) == 60
    assert first.started_at == started
    assert first.ended_at == started + timedelta(minutes=59)
    assert first.sequence_sha256 == second.sequence_sha256
    assert len(first.sequence_sha256) == 64


def test_sequence_rejects_out_of_order_frames() -> None:
    contract = FeatureContractSpec.load(CONTRACT_PATH)
    builder = FeatureSequenceBuilder(contract)
    timestamp = datetime(2026, 8, 12, tzinfo=timezone.utc)
    builder.add_frame(
        entity_id="sensor-a",
        observed_at=timestamp,
        sequence_number=1,
        values=_values(),
    )

    with pytest.raises(ValueError, match="timestamps must be strictly increasing"):
        builder.add_frame(
            entity_id="sensor-a",
            observed_at=timestamp,
            sequence_number=2,
            values=_values(),
        )


def test_sequence_resets_after_a_missing_time_window() -> None:
    contract = FeatureContractSpec.load(CONTRACT_PATH)
    builder = FeatureSequenceBuilder(contract)
    timestamp = datetime(2026, 8, 12, tzinfo=timezone.utc)
    builder.add_frame(
        entity_id="sensor-a",
        observed_at=timestamp,
        sequence_number=1,
        values=_values(),
    )

    result = builder.add_frame(
        entity_id="sensor-a",
        observed_at=timestamp + timedelta(minutes=2),
        sequence_number=2,
        values=_values(),
    )

    assert result is None
