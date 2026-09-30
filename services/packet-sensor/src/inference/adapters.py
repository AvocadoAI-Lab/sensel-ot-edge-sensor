"""Replaceable ONNX adapters for IF, XGBoost, and Tiny LSTM inference."""

from __future__ import annotations

import math
import time
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from src.features.contract import FeatureSequence
from src.inference.artifact import verify_artifact_sha256
from src.inference.calibration import ScoreCalibrator
from src.inference.onnx_sequence import (
    InferenceResult,
    ModelRuntimeState,
    OnnxSequenceRuntime,
    SessionFactory,
)


class UnavailableAdapter:
    input_kind = "unavailable"

    def __init__(
        self,
        *,
        engine_id: str,
        model_version: str,
        feature_contract_id: str,
        status: str,
        error: str = "",
    ) -> None:
        self._state = ModelRuntimeState(
            engine_id=engine_id,
            status=status,
            model_path="",
            model_version=model_version,
            feature_contract_id=feature_contract_id,
            error=error,
        )

    @property
    def state(self) -> ModelRuntimeState:
        return self._state

    def predict(self, _sequence: FeatureSequence) -> InferenceResult:
        return InferenceResult(
            engine_id=self._state.engine_id,
            model_version=self._state.model_version,
            feature_contract_id=self._state.feature_contract_id,
            status=self._state.status,
            score=None,
            label="unavailable",
            latency_ms=0.0,
            error=self._state.error,
        )


class OnnxTabularAdapter:
    """Run one rank-2 ONNX model over the latest normalized feature frame."""

    input_kind = "latest_frame"

    def __init__(
        self,
        model_path: str | Path,
        *,
        engine_id: str,
        model_version: str,
        feature_contract_id: str,
        expected_sha256: str,
        calibrator: ScoreCalibrator,
        threshold: float = 0.5,
        output_index: int = 0,
        anomaly_class_index: int = 1,
        class_labels: Sequence[str] = ("normal", "anomaly"),
        enabled: bool = True,
        providers: Sequence[str] = ("CPUExecutionProvider",),
        session_factory: SessionFactory | None = None,
    ) -> None:
        if not engine_id.strip() or not model_version.strip():
            raise ValueError("engine_id and model_version are required")
        if not feature_contract_id.strip():
            raise ValueError("feature_contract_id is required")
        if not 0 <= threshold <= 1:
            raise ValueError("threshold must be between 0 and 1")
        if output_index < 0 or anomaly_class_index < 0:
            raise ValueError("output and class indices must be non-negative")
        self._path = Path(model_path)
        self._engine_id = engine_id
        self._model_version = model_version
        self._feature_contract_id = feature_contract_id
        self._expected_sha256 = expected_sha256
        self._calibrator = calibrator
        self._threshold = threshold
        self._output_index = output_index
        self._anomaly_class_index = anomaly_class_index
        self._class_labels = tuple(class_labels)
        self._providers = tuple(providers)
        self._session_factory = session_factory
        self._session: Any | None = None
        self._input: Any | None = None
        self._state = ModelRuntimeState(
            engine_id=engine_id,
            status="disabled" if not enabled else "initializing",
            model_path=str(self._path),
            model_version=model_version,
            feature_contract_id=feature_contract_id,
            artifact_sha256=expected_sha256,
            calibration_version=calibrator.version,
        )
        if enabled:
            self._load()

    @property
    def state(self) -> ModelRuntimeState:
        return self._state

    def _set_state(self, status: str, error: str = "") -> None:
        self._state = ModelRuntimeState(
            engine_id=self._engine_id,
            status=status,
            model_path=str(self._path),
            model_version=self._model_version,
            feature_contract_id=self._feature_contract_id,
            artifact_sha256=self._expected_sha256,
            calibration_version=self._calibrator.version,
            error=error,
        )

    def _load(self) -> None:
        if not self._path.is_file():
            self._set_state("missing", f"model file not found: {self._path}")
            return
        try:
            verify_artifact_sha256(self._path, self._expected_sha256)
            if self._session_factory is None:
                import onnxruntime as ort

                options = ort.SessionOptions()
                options.intra_op_num_threads = 1
                options.inter_op_num_threads = 1
                options.execution_mode = ort.ExecutionMode.ORT_SEQUENTIAL
                options.graph_optimization_level = ort.GraphOptimizationLevel.ORT_ENABLE_ALL
                self._session = ort.InferenceSession(
                    str(self._path),
                    sess_options=options,
                    providers=list(self._providers),
                )
            else:
                self._session = self._session_factory(str(self._path), self._providers)
            inputs = list(self._session.get_inputs())
            outputs = list(self._session.get_outputs())
            if len(inputs) != 1:
                raise ValueError(f"expected one model input, found {len(inputs)}")
            if self._output_index >= len(outputs):
                raise ValueError(
                    f"model output_index {self._output_index} exceeds {len(outputs)} outputs"
                )
            self._input = inputs[0]
            expected_shape = list(getattr(self._input, "shape", []) or [])
            if len(expected_shape) != 2:
                raise ValueError(f"tabular model input must have rank 2: {expected_shape}")
            get_modelmeta = getattr(self._session, "get_modelmeta", None)
            if callable(get_modelmeta):
                metadata = get_modelmeta()
                custom = getattr(metadata, "custom_metadata_map", {}) or {}
                declared_contract = str(custom.get("feature_contract_id") or "")
                if declared_contract and declared_contract != self._feature_contract_id:
                    raise ValueError(
                        f"model feature_contract_id {declared_contract!r} does not match "
                        f"runtime {self._feature_contract_id!r}"
                    )
        except ModuleNotFoundError as exc:
            self._session = None
            self._set_state("dependency_missing", str(exc))
            return
        except Exception as exc:
            self._session = None
            self._set_state("load_error", str(exc))
            return
        self._set_state("ready")

    def _unavailable(self) -> InferenceResult:
        return InferenceResult(
            engine_id=self._engine_id,
            model_version=self._model_version,
            feature_contract_id=self._feature_contract_id,
            status=self._state.status,
            score=None,
            label="unavailable",
            latency_ms=0.0,
            error=self._state.error,
        )

    def _extract_score_and_label(self, output: Any) -> tuple[float, str]:
        import numpy as np

        if isinstance(output, list) and output and isinstance(output[0], Mapping):
            probabilities = output[0]
            keys = list(probabilities)
            if self._anomaly_class_index >= len(keys):
                raise ValueError("anomaly_class_index exceeds probability map")
            anomaly_key = keys[self._anomaly_class_index]
            predicted_key = max(keys, key=lambda key: float(probabilities[key]))
            return float(probabilities[anomaly_key]), str(predicted_key)

        flattened = np.asarray(output).reshape(-1)
        if flattened.size == 0:
            raise ValueError("model returned an empty score tensor")
        if flattened.size == 1:
            raw = float(flattened[0])
            return raw, ""
        if self._anomaly_class_index >= flattened.size:
            raise ValueError("anomaly_class_index exceeds probability tensor")
        predicted_index = int(np.argmax(flattened))
        label = (
            self._class_labels[predicted_index]
            if predicted_index < len(self._class_labels)
            else str(predicted_index)
        )
        return float(flattened[self._anomaly_class_index]), label

    def predict(self, sequence: FeatureSequence) -> InferenceResult:
        if self._state.status != "ready" or self._session is None:
            return self._unavailable()
        if sequence.contract_id != self._feature_contract_id:
            return InferenceResult(
                engine_id=self._engine_id,
                model_version=self._model_version,
                feature_contract_id=self._feature_contract_id,
                status="contract_mismatch",
                score=None,
                label="unavailable",
                latency_ms=0.0,
                error=f"received feature contract {sequence.contract_id}",
            )

        started_ns = time.perf_counter_ns()
        try:
            import numpy as np

            values = np.asarray([sequence.latest_values], dtype=np.float32)
            expected_shape = list(getattr(self._input, "shape", []) or [])
            if (
                len(expected_shape) == 2
                and isinstance(expected_shape[1], int)
                and expected_shape[1] > 0
                and values.shape[1] != expected_shape[1]
            ):
                raise ValueError(
                    f"model requires {expected_shape[1]} features, received {values.shape[1]}"
                )
            outputs = self._session.run(None, {self._input.name: values})
            raw_score, label = self._extract_score_and_label(outputs[self._output_index])
            if not math.isfinite(raw_score):
                raise ValueError("model returned a non-finite score")
            score = self._calibrator.apply(raw_score)
            if not label:
                label = "anomaly" if score >= self._threshold else "normal"
            return InferenceResult(
                engine_id=self._engine_id,
                model_version=self._model_version,
                feature_contract_id=self._feature_contract_id,
                status="ok",
                score=score,
                label=label,
                latency_ms=(time.perf_counter_ns() - started_ns) / 1_000_000,
                raw_score=raw_score,
                calibration_version=self._calibrator.version,
            )
        except Exception as exc:
            return InferenceResult(
                engine_id=self._engine_id,
                model_version=self._model_version,
                feature_contract_id=self._feature_contract_id,
                status="inference_error",
                score=None,
                label="unavailable",
                latency_ms=(time.perf_counter_ns() - started_ns) / 1_000_000,
                error=str(exc),
            )


class IsolationForestAdapter(OnnxTabularAdapter):
    def __init__(self, model_path: str | Path, **kwargs: Any) -> None:
        super().__init__(model_path, engine_id="isolation-forest", **kwargs)


class XGBoostAdapter(OnnxTabularAdapter):
    def __init__(self, model_path: str | Path, **kwargs: Any) -> None:
        super().__init__(model_path, engine_id="xgboost", **kwargs)


class TinyLstmAdapter:
    input_kind = "sequence"

    def __init__(
        self,
        model_path: str | Path,
        *,
        model_version: str,
        feature_contract_id: str,
        expected_sha256: str,
        calibrator: ScoreCalibrator,
        threshold: float = 0.5,
        enabled: bool = True,
        providers: Sequence[str] = ("CPUExecutionProvider",),
        session_factory: SessionFactory | None = None,
    ) -> None:
        self._feature_contract_id = feature_contract_id
        self._runtime = OnnxSequenceRuntime(
            model_path,
            engine_id="tiny-lstm",
            model_version=model_version,
            feature_contract_id=feature_contract_id,
            enabled=enabled,
            threshold=threshold,
            expected_sha256=expected_sha256,
            calibrator=calibrator,
            providers=providers,
            session_factory=session_factory,
        )

    @property
    def state(self) -> ModelRuntimeState:
        return self._runtime.state

    def predict(self, sequence: FeatureSequence) -> InferenceResult:
        if sequence.contract_id != self._feature_contract_id:
            return InferenceResult(
                engine_id="tiny-lstm",
                model_version=self.state.model_version,
                feature_contract_id=self._feature_contract_id,
                status="contract_mismatch",
                score=None,
                label="unavailable",
                latency_ms=0.0,
                error=f"received feature contract {sequence.contract_id}",
            )
        values = [list(frame.values) for frame in sequence.frames]
        return self._runtime.predict(values)
