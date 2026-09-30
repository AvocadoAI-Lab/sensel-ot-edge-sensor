from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
import pytest

from src.features.contract import FeatureFrame, FeatureSequence
from src.inference.adapters import IsolationForestAdapter
from src.inference.calibration import ScoreCalibrator
from src.inference.calibration import load_calibrator


@dataclass
class _Node:
    name: str
    shape: list[int]


@dataclass
class _Meta:
    custom_metadata_map: dict[str, str]


class _TabularSession:
    def get_inputs(self):
        return [_Node("features", [1, 3])]

    def get_outputs(self):
        return [_Node("score", [1, 1])]

    def get_modelmeta(self):
        return _Meta({"feature_contract_id": "contract-v1"})

    def run(self, _outputs, values):
        assert values["features"].shape == (1, 3)
        return [np.asarray([[0.0]], dtype=np.float32)]


def _sequence() -> FeatureSequence:
    now = datetime(2026, 8, 12, tzinfo=timezone.utc)
    frame = FeatureFrame(now, 1, (1.0, 2.0, 3.0))
    return FeatureSequence("contract-v1", "sensor-a", now, now, (frame,), "abc")


def test_calibration_supports_platt_and_isotonic() -> None:
    platt = ScoreCalibrator(version="platt-v1", kind="platt", slope=1, intercept=0)
    isotonic = ScoreCalibrator(
        version="iso-v1",
        kind="isotonic",
        points=((0.0, 0.1), (1.0, 0.9)),
    )

    assert platt.apply(0.0) == pytest.approx(0.5)
    assert isotonic.apply(0.5) == pytest.approx(0.5)


def test_calibration_rejects_feature_contract_mismatch(tmp_path: Path) -> None:
    path = tmp_path / "calibration.json"
    path.write_text(
        '{"schema_version":"sensel.calibration.v1",'
        '"feature_contract_id":"other-v1",'
        '"calibrators":{"isolation-forest":'
        '{"version":"if-cal-v1","kind":"identity"}}}',
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="does not match runtime"):
        load_calibrator(
            path,
            "isolation-forest",
            feature_contract_id="contract-v1",
        )


def test_tabular_adapter_verifies_digest_and_calibrates(tmp_path: Path) -> None:
    model = tmp_path / "if.onnx"
    model.write_bytes(b"fake-onnx-artifact")
    digest = hashlib.sha256(model.read_bytes()).hexdigest()
    adapter = IsolationForestAdapter(
        model,
        model_version="if-2026.08",
        feature_contract_id="contract-v1",
        expected_sha256=digest,
        calibrator=ScoreCalibrator(
            version="platt-v1",
            kind="platt",
            slope=1,
            intercept=0,
        ),
        session_factory=lambda _path, _providers: _TabularSession(),
    )

    result = adapter.predict(_sequence())

    assert adapter.state.status == "ready"
    assert result.available is True
    assert result.raw_score == pytest.approx(0.0)
    assert result.score == pytest.approx(0.5)
    assert result.calibration_version == "platt-v1"
    assert result.label == "anomaly"


def test_tabular_adapter_digest_mismatch_fails_open(tmp_path: Path) -> None:
    model = tmp_path / "if.onnx"
    model.write_bytes(b"fake-onnx-artifact")
    adapter = IsolationForestAdapter(
        model,
        model_version="if-2026.08",
        feature_contract_id="contract-v1",
        expected_sha256="0" * 64,
        calibrator=ScoreCalibrator(version="identity-v1"),
        session_factory=lambda _path, _providers: _TabularSession(),
    )

    assert adapter.state.status == "load_error"
    assert "sha256 mismatch" in adapter.state.error
    assert adapter.predict(_sequence()).available is False
