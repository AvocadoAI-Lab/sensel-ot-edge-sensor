"""Observable ONNX sequence inference without a PyTorch runtime dependency."""

from __future__ import annotations

import math
import time
from collections.abc import Callable, Sequence
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any


SessionFactory = Callable[[str, Sequence[str]], Any]


@dataclass(frozen=True)
class ModelRuntimeState:
    engine_id: str
    status: str
    model_path: str
    model_version: str
    feature_contract_id: str
    error: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class InferenceResult:
    engine_id: str
    model_version: str
    feature_contract_id: str
    status: str
    score: float | None
    label: str
    latency_ms: float
    error: str = ""

    @property
    def available(self) -> bool:
        return self.status == "ok" and self.score is not None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class OnnxSequenceRuntime:
    """Load one sequence model and return explicit fail-open results.

    The adapter does not perform feature extraction. Callers must provide an
    array that matches the model's declared input and ``feature_contract_id``.
    """

    def __init__(
        self,
        model_path: str | Path,
        *,
        engine_id: str = "tiny-lstm",
        model_version: str,
        feature_contract_id: str,
        enabled: bool = True,
        threshold: float = 0.5,
        providers: Sequence[str] = ("CPUExecutionProvider",),
        session_factory: SessionFactory | None = None,
    ) -> None:
        if not model_version.strip():
            raise ValueError("model_version is required")
        if not feature_contract_id.strip():
            raise ValueError("feature_contract_id is required")
        if not 0 <= threshold <= 1:
            raise ValueError("threshold must be between 0 and 1")
        self._path = Path(model_path)
        self._engine_id = engine_id
        self._model_version = model_version
        self._feature_contract_id = feature_contract_id
        self._threshold = float(threshold)
        self._providers = tuple(providers)
        self._session_factory = session_factory
        self._session: Any | None = None
        self._input: Any | None = None
        self._output: Any | None = None
        self._state = ModelRuntimeState(
            engine_id=engine_id,
            status="disabled" if not enabled else "initializing",
            model_path=str(self._path),
            model_version=model_version,
            feature_contract_id=feature_contract_id,
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
            error=error,
        )

    def _load(self) -> None:
        if not self._path.is_file():
            self._set_state("missing", f"model file not found: {self._path}")
            return

        try:
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
            if not outputs:
                raise ValueError("model has no outputs")
            self._input = inputs[0]
            self._output = outputs[0]
            get_modelmeta = getattr(self._session, "get_modelmeta", None)
            if callable(get_modelmeta):
                metadata = get_modelmeta()
                custom_metadata = getattr(metadata, "custom_metadata_map", {}) or {}
                declared_contract = str(custom_metadata.get("feature_contract_id") or "")
                if declared_contract and declared_contract != self._feature_contract_id:
                    raise ValueError(
                        "model feature_contract_id "
                        f"{declared_contract!r} does not match runtime "
                        f"{self._feature_contract_id!r}"
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

    def _unavailable_result(self) -> InferenceResult:
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

    def _validate_shape(self, values: Any) -> None:
        expected_shape = list(getattr(self._input, "shape", []) or [])
        if len(values.shape) != 3:
            raise ValueError(
                f"expected [batch, sequence, features], received shape {tuple(values.shape)}"
            )
        if len(expected_shape) != 3:
            raise ValueError(f"model input must have rank 3, declared {expected_shape}")
        for index, expected in enumerate(expected_shape):
            if isinstance(expected, int) and expected > 0 and values.shape[index] != expected:
                raise ValueError(
                    f"input dimension {index} requires {expected}, received {values.shape[index]}"
                )

    def predict(self, sequence: Any) -> InferenceResult:
        if self._state.status != "ready" or self._session is None:
            return self._unavailable_result()

        started_ns = time.perf_counter_ns()
        try:
            import numpy as np

            values = np.asarray(sequence, dtype=np.float32)
            if values.ndim == 2:
                values = np.expand_dims(values, axis=0)
            self._validate_shape(values)
            outputs = self._session.run(
                [self._output.name],
                {self._input.name: values},
            )
            if not outputs:
                raise ValueError("model returned no output tensors")
            flattened = np.asarray(outputs[0]).reshape(-1)
            if flattened.size == 0:
                raise ValueError("model returned an empty score tensor")
            score = float(flattened[0])
            if not math.isfinite(score):
                raise ValueError("model returned a non-finite score")
            if not 0 <= score <= 1:
                raise ValueError("model score must be normalized between 0 and 1")
            latency_ms = (time.perf_counter_ns() - started_ns) / 1_000_000
            return InferenceResult(
                engine_id=self._engine_id,
                model_version=self._model_version,
                feature_contract_id=self._feature_contract_id,
                status="ok",
                score=score,
                label="anomaly" if score >= self._threshold else "normal",
                latency_ms=latency_ms,
            )
        except Exception as exc:
            latency_ms = (time.perf_counter_ns() - started_ns) / 1_000_000
            return InferenceResult(
                engine_id=self._engine_id,
                model_version=self._model_version,
                feature_contract_id=self._feature_contract_id,
                status="inference_error",
                score=None,
                label="unavailable",
                latency_ms=latency_ms,
                error=str(exc),
            )
