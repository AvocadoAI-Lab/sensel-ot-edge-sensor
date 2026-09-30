"""HTTP bridge from SenseL feature windows to Avocdo EdgeMed /api/score."""

from __future__ import annotations

import json
import math
import time
from collections.abc import Mapping
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any

import httpx

from src.features.contract import FeatureContractSpec, FeatureDefinitionSpec, FeatureSequence
from src.fusion.engine import DetectionSignal, FusionDecision
from src.inference.onnx_sequence import InferenceResult, ModelRuntimeState
from src.inference.pipeline import EdgeMedAiAnalysis, LocalInferenceOutcome


_ANOMALY_ENGINE_MAP = (
    ("isolation_forest", "isolation-forest"),
    ("lstm_autoencoder", "tiny-lstm"),
)

_ENGINE_ORDER = ("baseline", "isolation-forest", "xgboost", "tiny-lstm")

_SEVERITY_ORDER = ("info", "low", "medium", "high", "critical")


@dataclass(frozen=True)
class EdgeMedFeatureMapping:
    mapping_id: str
    source_contract_id: str
    target_schema: str
    field_mappings: Mapping[str, str]
    defaults: Mapping[str, float]

    @classmethod
    def load(cls, path: str | Path) -> "EdgeMedFeatureMapping":
        payload = json.loads(Path(path).read_text(encoding="utf-8"))
        return cls(
            mapping_id=str(payload.get("mapping_id") or "edgemed-mapping"),
            source_contract_id=str(payload.get("source_contract_id") or ""),
            target_schema=str(payload.get("target_schema") or "edgemed"),
            field_mappings=dict(payload.get("field_mappings") or {}),
            defaults={
                str(key): float(value)
                for key, value in (payload.get("defaults") or {}).items()
            },
        )

    def map_sequence(
        self,
        sequence: FeatureSequence,
        contract: FeatureContractSpec,
    ) -> dict[str, float]:
        if contract.contract_id != self.source_contract_id:
            raise ValueError(
                "feature mapping source contract does not match active contract"
            )
        source_values = {
            feature.name: _denormalize_value(feature, value)
            for feature, value in zip(contract.features, sequence.latest_values)
        }
        features = dict(self.defaults)
        for source_name, target_name in self.field_mappings.items():
            if source_name in source_values:
                features[target_name] = float(source_values[source_name])
        return features


def _denormalize_value(feature: FeatureDefinitionSpec, normalized: float) -> float:
    if feature.normalization == "none":
        return float(normalized)
    if feature.normalization == "log1p":
        return float(math.expm1(normalized))
    if feature.normalization == "z_score":
        if feature.mean is None or feature.standard_deviation is None:
            raise ValueError(f"feature {feature.name} missing z-score parameters")
        return float(normalized * feature.standard_deviation + feature.mean)
    if feature.minimum is None or feature.maximum is None:
        raise ValueError(f"feature {feature.name} missing min-max parameters")
    span = feature.maximum - feature.minimum
    return float(normalized * span + feature.minimum)


def _clamp_score(value: float | None) -> float | None:
    if value is None or not math.isfinite(value):
        return None
    return min(1.0, max(0.0, float(value)))


def _severity_from_assessment(severity: str, fused_score: float) -> str:
    normalized = severity.strip().lower()
    if normalized in _SEVERITY_ORDER:
        return normalized
    if fused_score >= 0.95:
        return "critical"
    if fused_score >= 0.75:
        return "high"
    if fused_score >= 0.5:
        return "medium"
    if fused_score >= 0.25:
        return "low"
    return "info"


def parse_edgemed_score_event(
    event: Mapping[str, Any],
    *,
    feature_contract_id: str,
    alert_threshold: float,
    policy_version: str,
    latency_ms: float,
) -> LocalInferenceOutcome:
    detection = event.get("detection") or {}
    anomalies = detection.get("anomalies") or {}
    known_attack = detection.get("known_attack")
    baseline = detection.get("baseline")
    assessment = event.get("assessment") or {}

    by_engine: dict[str, tuple[InferenceResult, DetectionSignal]] = {}

    if isinstance(baseline, Mapping):
        score = _clamp_score(baseline.get("score"))
        model_version = str(baseline.get("model_version") or baseline.get("profile_id") or "baseline-profile")
        if score is None:
            by_engine["baseline"] = (
                InferenceResult(
                    engine_id="baseline",
                    model_version=model_version,
                    feature_contract_id=feature_contract_id,
                    status="unavailable",
                    score=None,
                    label="",
                    latency_ms=latency_ms,
                    error="baseline score unavailable",
                ),
                DetectionSignal(
                    engine_id="baseline",
                    model_version=model_version,
                    feature_contract_id=feature_contract_id,
                    available=False,
                    error="baseline score unavailable",
                ),
            )
        else:
            label = "compliant" if baseline.get("compliant", True) else "violation"
            by_engine["baseline"] = (
                InferenceResult(
                    engine_id="baseline",
                    model_version=model_version,
                    feature_contract_id=feature_contract_id,
                    status="ok",
                    score=score,
                    label=label,
                    latency_ms=latency_ms,
                    raw_score=score,
                ),
                DetectionSignal(
                    engine_id="baseline",
                    model_version=model_version,
                    score=score,
                    label=label,
                    feature_contract_id=feature_contract_id,
                    available=True,
                    attributes={
                        "runtime_status": "ok",
                        "violations": baseline.get("violations") or [],
                        "source": "edgemed",
                        "edgemed_event_id": event.get("event_id"),
                    },
                ),
            )
    else:
        by_engine["baseline"] = (
            InferenceResult(
                engine_id="baseline",
                model_version="edgemed-baseline",
                feature_contract_id=feature_contract_id,
                status="unavailable",
                score=None,
                label="",
                latency_ms=latency_ms,
                error="baseline missing in EdgeMed response",
            ),
            DetectionSignal(
                engine_id="baseline",
                model_version="edgemed-baseline",
                feature_contract_id=feature_contract_id,
                available=False,
                error="baseline missing in EdgeMed response",
            ),
        )

    for source_id, engine_id in _ANOMALY_ENGINE_MAP:
        payload = anomalies.get(source_id)
        if not isinstance(payload, Mapping):
            by_engine[engine_id] = (
                InferenceResult(
                    engine_id=engine_id,
                    model_version="edgemed-bridge",
                    feature_contract_id=feature_contract_id,
                    status="unavailable",
                    score=None,
                    label="",
                    latency_ms=latency_ms,
                    error="detector missing in EdgeMed response",
                ),
                DetectionSignal(
                    engine_id=engine_id,
                    model_version="edgemed-bridge",
                    feature_contract_id=feature_contract_id,
                    available=False,
                    error="detector missing in EdgeMed response",
                ),
            )
            continue

        model_version = str(payload.get("model_version") or "edgemed-bridge")
        if payload.get("status") == "warming":
            by_engine[engine_id] = (
                InferenceResult(
                    engine_id=engine_id,
                    model_version=model_version,
                    feature_contract_id=feature_contract_id,
                    status="warming",
                    score=None,
                    label="warming",
                    latency_ms=latency_ms,
                ),
                DetectionSignal(
                    engine_id=engine_id,
                    model_version=model_version,
                    feature_contract_id=feature_contract_id,
                    available=False,
                    error="warming",
                    attributes={"runtime_status": "warming"},
                ),
            )
            continue

        score = _clamp_score(payload.get("score"))
        if score is None:
            by_engine[engine_id] = (
                InferenceResult(
                    engine_id=engine_id,
                    model_version=model_version,
                    feature_contract_id=feature_contract_id,
                    status="error",
                    score=None,
                    label="",
                    latency_ms=latency_ms,
                    error="score unavailable",
                ),
                DetectionSignal(
                    engine_id=engine_id,
                    model_version=model_version,
                    feature_contract_id=feature_contract_id,
                    available=False,
                    error="score unavailable",
                ),
            )
            continue

        label = "anomaly" if payload.get("anomalous") else "normal"
        by_engine[engine_id] = (
            InferenceResult(
                engine_id=engine_id,
                model_version=model_version,
                feature_contract_id=feature_contract_id,
                status="ok",
                score=score,
                label=label,
                latency_ms=latency_ms,
                raw_score=score,
            ),
            DetectionSignal(
                engine_id=engine_id,
                model_version=model_version,
                score=score,
                label=label,
                feature_contract_id=feature_contract_id,
                available=True,
                attributes={
                    "runtime_status": "ok",
                    "latency_ms": latency_ms,
                    "source": "edgemed",
                    "edgemed_event_id": event.get("event_id"),
                },
            ),
        )

    if isinstance(known_attack, Mapping):
        probability = _clamp_score(known_attack.get("probability"))
        model_version = str(known_attack.get("model_version") or "edgemed-xgb")
        if probability is None:
            by_engine["xgboost"] = (
                InferenceResult(
                    engine_id="xgboost",
                    model_version=model_version,
                    feature_contract_id=feature_contract_id,
                    status="unavailable",
                    score=None,
                    label="",
                    latency_ms=latency_ms,
                    error="known_attack probability unavailable",
                ),
                DetectionSignal(
                    engine_id="xgboost",
                    model_version=model_version,
                    feature_contract_id=feature_contract_id,
                    available=False,
                    error="known_attack probability unavailable",
                ),
            )
        else:
            label = str(known_attack.get("category") or known_attack.get("label") or "")
            by_engine["xgboost"] = (
                InferenceResult(
                    engine_id="xgboost",
                    model_version=model_version,
                    feature_contract_id=feature_contract_id,
                    status="ok",
                    score=probability,
                    label=label,
                    latency_ms=latency_ms,
                    raw_score=probability,
                ),
                DetectionSignal(
                    engine_id="xgboost",
                    model_version=model_version,
                    score=probability,
                    label=label,
                    feature_contract_id=feature_contract_id,
                    available=True,
                    attributes={
                        "runtime_status": "ok",
                        "latency_ms": latency_ms,
                        "source": "edgemed",
                        "edgemed_event_id": event.get("event_id"),
                    },
                ),
            )
    else:
        by_engine["xgboost"] = (
            InferenceResult(
                engine_id="xgboost",
                model_version="edgemed-xgb",
                feature_contract_id=feature_contract_id,
                status="unavailable",
                score=None,
                label="",
                latency_ms=latency_ms,
                error="known_attack missing in EdgeMed response",
            ),
            DetectionSignal(
                engine_id="xgboost",
                model_version="edgemed-xgb",
                feature_contract_id=feature_contract_id,
                available=False,
                error="known_attack missing in EdgeMed response",
            ),
        )

    results: list[InferenceResult] = []
    signals: list[DetectionSignal] = []
    for engine_id in _ENGINE_ORDER:
        result, signal = by_engine[engine_id]
        results.append(result)
        signals.append(signal)

    available_scores = [signal.score for signal in signals if signal.available]
    fused_score = max(available_scores) if available_scores else 0.0
    weighted_mean = (
        sum(available_scores) / len(available_scores) if available_scores else 0.0
    )
    verdict = str(assessment.get("verdict") or "baseline")
    decision = "alert" if verdict != "baseline" else "observe"
    if fused_score >= alert_threshold and verdict == "baseline" and available_scores:
        decision = "alert"
    severity = _severity_from_assessment(
        str(assessment.get("severity") or "info"),
        fused_score,
    )
    input_ids = tuple(
        engine_id
        for engine_id in _ENGINE_ORDER
        if any(signal.available and signal.engine_id == engine_id for signal in signals)
    )

    fusion = FusionDecision(
        policy_version=policy_version,
        score=fused_score,
        threshold=alert_threshold,
        decision=decision,
        severity=severity,
        input_ids=input_ids,
        unavailable_ids=tuple(
            signal.engine_id for signal in signals if not signal.available
        ),
        weighted_mean=weighted_mean,
        maximum_score=fused_score,
    )
    return LocalInferenceOutcome(
        results=tuple(results),
        signals=tuple(signals),
        fusion=fusion,
        ai_analysis=None,
    )


def build_ai_analysis_ref(
    event: Mapping[str, Any],
    *,
    slm_status: Mapping[str, Any] | None = None,
) -> EdgeMedAiAnalysis:
    assessment = event.get("assessment") or {}
    event_id = str(event.get("event_id") or "").strip()
    generation_status = str(assessment.get("generation_status") or "unknown").strip()
    summary = str(assessment.get("summary") or "").strip()
    if len(summary) > 400:
        summary = summary[:397] + "..."
    payload = {
        "source": "edgemed",
        "event_id": event_id,
        "generation_status": generation_status,
        "summary": summary,
        "slm_model_id": str((slm_status or {}).get("model_id") or ""),
        "slm_runtime": str((slm_status or {}).get("status") or ""),
    }
    return EdgeMedAiAnalysis(
        ref=json.dumps(payload, ensure_ascii=False, separators=(",", ":")),
        event_id=event_id,
        generation_status=generation_status,
        summary=summary,
    )


class EdgeMedScoreClient:
    def __init__(
        self,
        *,
        base_url: str,
        timeout_sec: float,
        device_type: str,
        operating_state: str,
        criticality: str,
        feature_contract_id: str,
        alert_threshold: float,
        policy_version: str,
        mapping: EdgeMedFeatureMapping,
        contract: FeatureContractSpec,
        investigate_enabled: bool = False,
        investigate_on_decisions: tuple[str, ...] = ("alert",),
        investigate_timeout_sec: float = 90.0,
        transport: httpx.Client | None = None,
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._timeout_sec = timeout_sec
        self._device_type = device_type
        self._operating_state = operating_state
        self._criticality = criticality
        self._feature_contract_id = feature_contract_id
        self._alert_threshold = alert_threshold
        self._policy_version = policy_version
        self._mapping = mapping
        self._contract = contract
        self._investigate_enabled = investigate_enabled
        self._investigate_on_decisions = {
            decision.strip().lower()
            for decision in investigate_on_decisions
            if decision.strip()
        }
        self._investigate_timeout_sec = investigate_timeout_sec
        self._transport = transport

    def _post_json(
        self,
        path: str,
        payload: Mapping[str, Any],
        *,
        timeout_sec: float,
    ) -> Mapping[str, Any]:
        url = f"{self._base_url}{path}"
        if self._transport is not None:
            response = self._transport.post(url, json=dict(payload))
        else:
            with httpx.Client(timeout=timeout_sec) as client:
                response = client.post(url, json=dict(payload))
        response.raise_for_status()
        body = response.json()
        if not isinstance(body, Mapping):
            raise ValueError(f"EdgeMed {path} response must be a JSON object")
        return body

    def _maybe_investigate(
        self,
        *,
        score_event: Mapping[str, Any],
        outcome: LocalInferenceOutcome,
        features: Mapping[str, float],
        sequence: FeatureSequence,
    ) -> LocalInferenceOutcome:
        if not self._investigate_enabled:
            return outcome
        if outcome.fusion.decision.strip().lower() not in self._investigate_on_decisions:
            return outcome
        try:
            event_id = str(score_event.get("event_id") or "").strip()
            if event_id:
                payload = {"event_id": event_id}
            else:
                payload = {
                    "device_id": sequence.entity_id,
                    "device_type": self._device_type,
                    "operating_state": self._operating_state,
                    "criticality": self._criticality,
                    "session_id": f"{sequence.entity_id}:{sequence.sequence_sha256[:12]}",
                    "features": dict(features),
                }
            body = self._post_json(
                "/api/investigate",
                payload,
                timeout_sec=self._investigate_timeout_sec,
            )
            event = body.get("event")
            if not isinstance(event, Mapping):
                raise ValueError("EdgeMed investigate response missing event")
            slm_status = body.get("slm")
            ai_analysis = build_ai_analysis_ref(
                event,
                slm_status=slm_status if isinstance(slm_status, Mapping) else None,
            )
            return replace(outcome, ai_analysis=ai_analysis)
        except (httpx.HTTPError, ValueError, TypeError):
            return outcome

    def score_sequence(
        self,
        sequence: FeatureSequence,
        *,
        baseline_profile: Mapping[str, Any] | None = None,
    ) -> LocalInferenceOutcome:
        features = self._mapping.map_sequence(sequence, self._contract)
        payload = {
            "device_id": sequence.entity_id,
            "device_type": self._device_type,
            "operating_state": self._operating_state,
            "criticality": self._criticality,
            "session_id": f"{sequence.entity_id}:{sequence.sequence_sha256[:12]}",
            "features": features,
            "fuse": True,
        }
        if baseline_profile:
            payload["baseline_profile"] = dict(baseline_profile)
        started = time.perf_counter()
        try:
            event = self._post_json(
                "/api/score",
                payload,
                timeout_sec=self._timeout_sec,
            )
        except (httpx.HTTPError, ValueError) as exc:
            latency_ms = (time.perf_counter() - started) * 1000.0
            return _unavailable_outcome(
                feature_contract_id=self._feature_contract_id,
                alert_threshold=self._alert_threshold,
                policy_version=self._policy_version,
                latency_ms=latency_ms,
                error=str(exc),
            )
        latency_ms = (time.perf_counter() - started) * 1000.0
        outcome = parse_edgemed_score_event(
            event,
            feature_contract_id=self._feature_contract_id,
            alert_threshold=self._alert_threshold,
            policy_version=self._policy_version,
            latency_ms=latency_ms,
        )
        return self._maybe_investigate(
            score_event=event,
            outcome=outcome,
            features=features,
            sequence=sequence,
        )


def _unavailable_outcome(
    *,
    feature_contract_id: str,
    alert_threshold: float,
    policy_version: str,
    latency_ms: float,
    error: str,
) -> LocalInferenceOutcome:
    engine_ids = ("baseline", "isolation-forest", "xgboost", "tiny-lstm")
    results = tuple(
        InferenceResult(
            engine_id=engine_id,
            model_version="edgemed-bridge",
            feature_contract_id=feature_contract_id,
            status="error",
            score=None,
            label="",
            latency_ms=latency_ms,
            error=error,
        )
        for engine_id in engine_ids
    )
    signals = tuple(
        DetectionSignal(
            engine_id=engine_id,
            model_version="edgemed-bridge",
            feature_contract_id=feature_contract_id,
            available=False,
            error=error,
        )
        for engine_id in engine_ids
    )
    return LocalInferenceOutcome(
        results=results,
        signals=signals,
        fusion=FusionDecision(
            policy_version=policy_version,
            score=0.0,
            threshold=alert_threshold,
            decision="unavailable",
            severity="info",
            input_ids=(),
            unavailable_ids=engine_ids,
            weighted_mean=0.0,
            maximum_score=0.0,
        ),
        ai_analysis=None,
    )


def runtime_states(feature_contract_id: str) -> tuple[ModelRuntimeState, ...]:
    return tuple(
        ModelRuntimeState(
            engine_id=engine_id,
            status="edgemed",
            model_path="http+edgemed",
            model_version="edgemed-bridge",
            feature_contract_id=feature_contract_id,
        )
        for engine_id in ("baseline", "isolation-forest", "xgboost", "tiny-lstm")
    )
