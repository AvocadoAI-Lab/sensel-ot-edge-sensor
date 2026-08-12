from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import numpy as np
import pytest

from src.inference.onnx_sequence import OnnxSequenceRuntime


@dataclass
class _NodeArg:
    name: str
    shape: list[int]


@dataclass
class _ModelMeta:
    custom_metadata_map: dict[str, str]


class _FakeSession:
    def get_inputs(self) -> list[_NodeArg]:
        return [_NodeArg(name="sequence_features", shape=[1, 8, 4])]

    def get_outputs(self) -> list[_NodeArg]:
        return [_NodeArg(name="risk_score", shape=[1, 1, 1])]

    def get_modelmeta(self) -> _ModelMeta:
        return _ModelMeta(
            custom_metadata_map={"feature_contract_id": "sequence-risk-smoke-v1"}
        )

    def run(self, output_names: list[str], inputs: dict) -> list[np.ndarray]:
        assert output_names == ["risk_score"]
        assert inputs["sequence_features"].shape == (1, 8, 4)
        return [np.asarray([[[0.75]]], dtype=np.float32)]


def _runtime(model_path: Path) -> OnnxSequenceRuntime:
    return OnnxSequenceRuntime(
        model_path,
        model_version="test-v1",
        feature_contract_id="sequence-risk-smoke-v1",
        session_factory=lambda _path, _providers: _FakeSession(),
    )


def test_missing_model_is_explicitly_unavailable(tmp_path: Path) -> None:
    runtime = _runtime(tmp_path / "missing.onnx")

    assert runtime.state.status == "missing"
    result = runtime.predict([[0.0] * 4] * 8)
    assert result.available is False
    assert result.status == "missing"
    assert result.score is None


def test_sequence_runtime_returns_observable_result(tmp_path: Path) -> None:
    model_path = tmp_path / "model.onnx"
    model_path.write_bytes(b"fake-session-does-not-read-model")
    runtime = _runtime(model_path)

    result = runtime.predict(np.zeros((8, 4), dtype=np.float32))

    assert runtime.state.status == "ready"
    assert result.available is True
    assert result.score == pytest.approx(0.75)
    assert result.label == "anomaly"
    assert result.feature_contract_id == "sequence-risk-smoke-v1"
    assert result.latency_ms >= 0


def test_feature_shape_mismatch_fails_open(tmp_path: Path) -> None:
    model_path = tmp_path / "model.onnx"
    model_path.write_bytes(b"fake-session-does-not-read-model")
    runtime = _runtime(model_path)

    result = runtime.predict(np.zeros((8, 3), dtype=np.float32))

    assert result.available is False
    assert result.status == "inference_error"
    assert result.score is None
    assert "dimension 2 requires 4" in result.error


def test_feature_contract_mismatch_blocks_model_activation(tmp_path: Path) -> None:
    model_path = tmp_path / "model.onnx"
    model_path.write_bytes(b"fake-session-does-not-read-model")
    runtime = OnnxSequenceRuntime(
        model_path,
        model_version="test-v1",
        feature_contract_id="different-contract-v2",
        session_factory=lambda _path, _providers: _FakeSession(),
    )

    assert runtime.state.status == "load_error"
    assert "does not match runtime" in runtime.state.error
    assert runtime.predict(np.zeros((8, 4), dtype=np.float32)).available is False


def test_runtime_rejects_invalid_threshold(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="threshold must be between 0 and 1"):
        OnnxSequenceRuntime(
            tmp_path / "model.onnx",
            model_version="test-v1",
            feature_contract_id="sequence-risk-smoke-v1",
            threshold=1.1,
        )


def test_real_smoke_model_runs_when_onnxruntime_is_installed() -> None:
    pytest.importorskip("onnxruntime")
    fixture = Path(__file__).parent / "fixtures" / "sequence-risk-smoke.onnx"
    runtime = OnnxSequenceRuntime(
        fixture,
        model_version="p0-smoke",
        feature_contract_id="sequence-risk-smoke-v1",
    )

    result = runtime.predict(np.ones((1, 8, 4), dtype=np.float32))

    assert runtime.state.status == "ready"
    assert result.available is True
    assert result.score == pytest.approx(1.0)
