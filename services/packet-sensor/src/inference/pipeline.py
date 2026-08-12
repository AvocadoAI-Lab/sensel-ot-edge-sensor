"""Local model orchestration from FeatureSequence to deterministic fusion."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import TYPE_CHECKING, Protocol

from src.features.contract import FeatureSequence
from src.fusion.engine import DetectionSignal, FusionDecision, RiskFusionPolicy
from src.inference.onnx_sequence import InferenceResult, ModelRuntimeState

if TYPE_CHECKING:
    from src.config.settings import InferenceConfig, ModelAdapterConfig


class InferenceAdapter(Protocol):
    @property
    def state(self) -> ModelRuntimeState: ...

    def predict(self, sequence: FeatureSequence) -> InferenceResult: ...


@dataclass(frozen=True)
class LocalInferenceOutcome:
    results: tuple[InferenceResult, ...]
    signals: tuple[DetectionSignal, ...]
    fusion: FusionDecision

    @property
    def has_available_signal(self) -> bool:
        return any(signal.available for signal in self.signals)


class LocalInferencePipeline:
    def __init__(
        self,
        adapters: Sequence[InferenceAdapter],
        *,
        fusion_policy: RiskFusionPolicy | None = None,
    ) -> None:
        engine_ids = [adapter.state.engine_id for adapter in adapters]
        if len(engine_ids) != len(set(engine_ids)):
            raise ValueError("inference adapters must have unique engine IDs")
        self._adapters = tuple(adapters)
        self._fusion_policy = fusion_policy or RiskFusionPolicy()

    @property
    def states(self) -> tuple[ModelRuntimeState, ...]:
        return tuple(adapter.state for adapter in self._adapters)

    def evaluate(self, sequence: FeatureSequence) -> LocalInferenceOutcome:
        results = tuple(adapter.predict(sequence) for adapter in self._adapters)
        signals = tuple(
            DetectionSignal(
                engine_id=result.engine_id,
                model_version=result.model_version,
                score=float(result.score or 0.0),
                label=result.label,
                feature_contract_id=result.feature_contract_id,
                available=result.available,
                error=result.error,
                attributes={
                    "runtime_status": result.status,
                    "latency_ms": result.latency_ms,
                    "raw_score": result.raw_score,
                    "calibration_version": result.calibration_version,
                },
            )
            for result in results
        )
        return LocalInferenceOutcome(
            results=results,
            signals=signals,
            fusion=self._fusion_policy.fuse(signals),
        )


def build_local_inference_pipeline(
    config: "InferenceConfig",
    *,
    feature_contract_id: str,
) -> LocalInferencePipeline:
    from src.inference.adapters import (
        IsolationForestAdapter,
        TinyLstmAdapter,
        UnavailableAdapter,
        XGBoostAdapter,
    )
    from src.inference.calibration import load_calibrator

    def unavailable(
        engine_id: str,
        model: "ModelAdapterConfig",
        status: str,
        error: str = "",
    ) -> UnavailableAdapter:
        return UnavailableAdapter(
            engine_id=engine_id,
            model_version=model.model_version,
            feature_contract_id=feature_contract_id,
            status=status,
            error=error,
        )

    adapters: list[InferenceAdapter] = []
    definitions = (
        ("isolation-forest", config.isolation_forest, IsolationForestAdapter),
        ("xgboost", config.xgboost, XGBoostAdapter),
        ("tiny-lstm", config.tiny_lstm, TinyLstmAdapter),
    )
    for engine_id, model, adapter_type in definitions:
        if not model.enabled:
            adapters.append(unavailable(engine_id, model, "disabled"))
            continue
        try:
            if not model.artifact_sha256.strip():
                raise ValueError("enabled model requires artifact_sha256")
            if model.model_version.strip().lower() in {"", "unconfigured"}:
                raise ValueError("enabled model requires a concrete model_version")
            calibrator = load_calibrator(
                model.calibration_path,
                engine_id,
                feature_contract_id=feature_contract_id,
            )
            common = {
                "model_version": model.model_version,
                "feature_contract_id": feature_contract_id,
                "expected_sha256": model.artifact_sha256,
                "calibrator": calibrator,
                "threshold": model.threshold,
            }
            if engine_id == "tiny-lstm":
                adapters.append(adapter_type(model.model_path, **common))
            else:
                adapters.append(
                    adapter_type(
                        model.model_path,
                        output_index=model.output_index,
                        anomaly_class_index=model.anomaly_class_index,
                        class_labels=model.class_labels,
                        **common,
                    )
                )
        except (OSError, TypeError, ValueError) as exc:
            adapters.append(unavailable(engine_id, model, "load_error", str(exc)))

    return LocalInferencePipeline(
        adapters,
        fusion_policy=RiskFusionPolicy(
            policy_version=config.fusion_policy_version,
            alert_threshold=config.fusion_alert_threshold,
            maximum_weight=config.fusion_maximum_weight,
        ),
    )
