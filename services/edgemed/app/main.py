from __future__ import annotations

from pathlib import Path
from typing import Any

import pandas as pd
from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field

from .baseline_scorer import resolve_baseline_profile, score_baseline_features
from .classifier import score_known_attack
from .cohort_xgb_registry import deployment_status, score_known_attack_for_device
from .detector import load_bundle, security_event
from .events import EventStore
from .fusion import fuse_detections
from .guardrails import (
    enforce_advisory_response,
    load_security_policy,
    sanitize_untrusted_text,
    validate_score_input,
    write_audit_event,
)
from .rag import build_default_orchestrator
from .schema import assert_detector_fields_unchanged, detector_owned_snapshot
from .slm import SlmFormatter
from .tick_buffer import DeviceTickBuffer


ROOT = Path(__file__).resolve().parents[1]
MODEL_PATH = ROOT / "artifacts" / "detector.joblib"
XGB_CATEGORY_PATH = ROOT / "artifacts" / "classifiers" / "xgboost_category.joblib"
XGB_BINARY_PATH = ROOT / "artifacts" / "classifiers" / "xgboost_binary.joblib"
LSTM_PATH = ROOT / "artifacts" / "lstm_ae.joblib"
SAMPLE_PATH = ROOT / "data" / "sample_flows.csv"
EVENT_LOG = ROOT / "artifacts" / "events" / "security_events.jsonl"

app = FastAPI(title="Avocdo EdgeMed MVP", version="0.1.0")
store = EventStore(EVENT_LOG)
slm_formatter = SlmFormatter()
# Best-effort load of SmolLM2 on hosts with transformers/torch available.
# Failure keeps template_fallback (Pi-class hosts typically stay unloaded).
_SLM_LOADED = slm_formatter.try_load()
rag = build_default_orchestrator(
    related_events_provider=lambda device_id, limit=5: store.related(device_id=device_id, limit=limit)
)
SECURITY_POLICY = load_security_policy()
TICK_BUFFER = DeviceTickBuffer(maxlen=128)


class ScoreRequest(BaseModel):
    device_id: str = "unknown-device"
    device_type: str = "medical_aiot"
    operating_state: str = "unknown"
    criticality: str = "unknown"
    session_id: str | None = None
    features: dict[str, float] = Field(default_factory=dict)
    baseline_profile: dict[str, Any] | None = None
    fuse: bool = True


class InvestigateRequest(BaseModel):
    event_id: str | None = None
    device_id: str | None = None
    device_type: str = "medical_aiot"
    operating_state: str = "unknown"
    criticality: str = "unknown"
    session_id: str | None = None
    features: dict[str, float] = Field(default_factory=dict)


def if_bundle():
    if not MODEL_PATH.exists():
        raise HTTPException(503, "Isolation Forest model missing; run scripts/train.py first")
    return load_bundle(MODEL_PATH)


def maybe_classifier(path: Path):
    if not path.exists():
        return None
    try:
        from .classifier import load_classifier
        return load_classifier(path)
    except Exception:
        return None


def maybe_lstm():
    if not LSTM_PATH.exists():
        return None
    try:
        from .lstm_ae import load_lstm_bundle
        return load_lstm_bundle(LSTM_PATH)
    except Exception:
        return None


def _anomaly_from_if(model, features: dict[str, float]) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    score, anomalous, evidence = model.score(features)
    payload = {
        "score": round(score, 6),
        "threshold": round(float(model.threshold), 6),
        "anomalous": bool(anomalous),
        "model_version": model.metadata.get("artifact_version", "if-0.1.0"),
        "detector": "isolation_forest",
    }
    feature_evidence = [
        {
            "feature": item["feature"],
            "observed": item.get("observed"),
            "baseline": None,
            "source": "detector:isolation_forest",
        }
        for item in evidence
    ]
    return payload, feature_evidence


def _anomaly_from_lstm(
    *,
    device_id: str,
    session_id: str | None,
    features: dict[str, float],
) -> dict[str, Any] | None:
    bundle = maybe_lstm()
    if bundle is None:
        return None
    tick_count = TICK_BUFFER.push(device_id=device_id, session_id=session_id, features=features)
    matrix = TICK_BUFFER.sequence_matrix(
        device_id=device_id,
        session_id=session_id,
        feature_names=bundle.features,
        seq_len=bundle.seq_len,
    )
    if matrix is None:
        return {
            "score": None,
            "threshold": round(float(bundle.threshold), 6),
            "anomalous": None,
            "status": "warming",
            "ticks": tick_count,
            "seq_len": bundle.seq_len,
            "model_version": bundle.metadata.get("artifact_version", "lstm-ae-0.1.0"),
            "detector": "lstm_autoencoder",
        }
    normalized, raw, anomalous, _evidence = bundle.score_sequence(matrix)
    return {
        "score": round(float(normalized), 6),
        "raw_error": round(float(raw), 6),
        "threshold": round(float(bundle.threshold), 6),
        "anomalous": bool(anomalous),
        "status": "ok",
        "ticks": tick_count,
        "seq_len": bundle.seq_len,
        "model_version": bundle.metadata.get("artifact_version", "lstm-ae-0.1.0"),
        "detector": "lstm_autoencoder",
    }


def _known_from_xgboost(features: dict[str, float], device_type: str) -> dict[str, Any] | None:
    """Prefer protocol-cohort binary model; fall back to legacy single/global paths."""
    cohort_scored = score_known_attack_for_device(features, device_type)
    if cohort_scored is not None:
        return cohort_scored
    for path in (XGB_CATEGORY_PATH, XGB_BINARY_PATH):
        model = maybe_classifier(path)
        if model is None:
            continue
        scored = score_known_attack(model, features)
        if scored is not None:
            return scored
    return None


def _collect_anomalies(
    *,
    device_id: str,
    session_id: str | None,
    features: dict[str, float],
) -> tuple[dict[str, dict[str, Any] | None], list[dict[str, Any]]]:
    if_model = if_bundle()
    if_payload, feature_evidence = _anomaly_from_if(if_model, features)
    lstm_payload = _anomaly_from_lstm(
        device_id=device_id,
        session_id=session_id,
        features=features,
    )
    anomalies: dict[str, dict[str, Any] | None] = {
        "isolation_forest": if_payload,
        "lstm_autoencoder": lstm_payload,
    }
    return anomalies, feature_evidence


@app.get("/", response_class=HTMLResponse)
def dashboard() -> str:
    return (ROOT / "app" / "static" / "index.html").read_text()


@app.get("/health")
def health() -> dict[str, Any]:
    if_ready = MODEL_PATH.exists()
    xgb_category_ready = XGB_CATEGORY_PATH.exists()
    xgb_binary_ready = XGB_BINARY_PATH.exists()
    lstm_ready = LSTM_PATH.exists()
    degraded = []
    if not if_ready:
        degraded.append("isolation_forest")
    if not xgb_category_ready and not xgb_binary_ready:
        degraded.append("xgboost")
    if not lstm_ready:
        degraded.append("lstm_autoencoder")
    if not slm_formatter.available:
        degraded.append("slm_runtime")
    status = "degraded" if degraded else "ok"
    if not if_ready and not xgb_category_ready and not xgb_binary_ready:
        status = "unavailable"
    cohort_status = deployment_status()
    cohort_ready = all(item.get("ready") for item in cohort_status.get("cohorts", {}).values())
    if not cohort_ready and cohort_status.get("manifest_ready"):
        degraded.append("cohort_xgb_partial")
    return {
        "status": status,
        "mode": "advisory_only",
        "degraded_components": degraded,
        "policy_version": SECURITY_POLICY.get("version", "0.1"),
        "components": {
            "isolation_forest": if_ready,
            "lstm_autoencoder": lstm_ready,
            "xgboost_category": xgb_category_ready,
            "xgboost_binary": xgb_binary_ready,
            "cohort_xgb": cohort_status,
            "slm": {
                "model_id": slm_formatter.model_id,
                "runtime_loaded": slm_formatter.available,
                "backend": slm_formatter.backend,
                "fallback": "template_fallback",
            },
            "rag": {
                "orchestrator": "deterministic_state_machine",
                "max_retrieval_steps": 5,
                "tools": "read_only_allowlist",
            },
            "event_store": EVENT_LOG.exists(),
        },
    }


@app.get("/api/model")
def model_info() -> dict[str, Any]:
    model = if_bundle()
    payload: dict[str, Any] = {
        "isolation_forest": {
            "features": model.features,
            "threshold": model.threshold,
            "metadata": model.metadata,
        }
    }
    for key, path in (
        ("xgboost_category", XGB_CATEGORY_PATH),
        ("xgboost_binary", XGB_BINARY_PATH),
    ):
        clf = maybe_classifier(path)
        if clf is not None:
            payload[key] = {
                "features": clf.features,
                "classes": clf.classes,
                "task": clf.task,
                "metadata": {k: v for k, v in clf.metadata.items() if k != "label_encoder"},
            }
    payload["cohort_xgb"] = deployment_status()
    lstm = maybe_lstm()
    if lstm is not None:
        payload["lstm_autoencoder"] = {
            "features": lstm.features,
            "seq_len": lstm.seq_len,
            "tick_seconds": lstm.tick_seconds,
            "threshold": lstm.threshold,
            "metadata": lstm.metadata,
        }
    return payload


@app.post("/api/score")
def score(request: ScoreRequest) -> dict[str, Any]:
    payload = request.model_dump()
    input_errors = validate_score_input(payload)
    if input_errors:
        write_audit_event("input_rejected", {"errors": input_errors, "route": "/api/score"})
        raise HTTPException(422, {"errors": input_errors})

    # Treat free-text asset fields as untrusted data.
    request.device_id = sanitize_untrusted_text(request.device_id)
    request.device_type = sanitize_untrusted_text(request.device_type)
    request.operating_state = sanitize_untrusted_text(request.operating_state)

    model = if_bundle()
    if not request.fuse:
        event = security_event(
            model,
            request.device_id,
            request.device_type,
            request.operating_state,
            request.features,
        )
        event = enforce_advisory_response(event, SECURITY_POLICY)
        write_audit_event("score_legacy", {"event_id": event.get("event_id")})
        return store.save(event)

    anomalies, feature_evidence = _collect_anomalies(
        device_id=request.device_id,
        session_id=request.session_id,
        features=request.features,
    )
    known = _known_from_xgboost(request.features, request.device_type)
    profile = resolve_baseline_profile(
        device_type=request.device_type,
        baseline_profile=request.baseline_profile,
    )
    baseline = score_baseline_features(request.features, profile)
    try:
        event = fuse_detections(
            device_id=request.device_id,
            device_type=request.device_type,
            operating_state=request.operating_state,
            criticality=request.criticality,
            session_id=request.session_id,
            baseline=baseline,
            known_attack=known,
            anomalies=anomalies,
            feature_evidence=feature_evidence,
        )
    except ValueError as exc:
        write_audit_event("score_unavailable", {"error": str(exc)})
        raise HTTPException(503, str(exc)) from exc
    event = enforce_advisory_response(event, SECURITY_POLICY)
    write_audit_event(
        "score_fused",
        {
            "event_id": event.get("event_id"),
            "detection_status": (event.get("detection") or {}).get("status"),
            "severity": (event.get("assessment") or {}).get("severity"),
        },
    )
    return store.save(event)


@app.post("/api/investigate")
def investigate(request: InvestigateRequest) -> dict[str, Any]:
    """Fused event + SLM formatter + deterministic allowlisted RAG."""
    if request.event_id:
        event = store.get(request.event_id)
        if event is None:
            raise HTTPException(404, f"Unknown event_id: {request.event_id}")
    else:
        if not request.features:
            raise HTTPException(422, "features or event_id required")
        scored = score(ScoreRequest(
            device_id=request.device_id or "unknown-device",
            device_type=request.device_type,
            operating_state=request.operating_state,
            criticality=request.criticality,
            session_id=request.session_id,
            features=request.features,
            fuse=True,
        ))
        event = scored

    before = detector_owned_snapshot(event)
    event = slm_formatter.format_event(event)
    event = rag.apply(event)
    related = store.related(
        device_id=(event.get("asset") or {}).get("device_id"),
        limit=10,
        exclude_event_id=event.get("event_id"),
    )
    event = {
        **event,
        "enrichment": {
            **(event.get("enrichment") or {}),
            "related_event_ids": [item.get("event_id") for item in related],
        },
    }
    assert_detector_fields_unchanged(
        {"detection": before["detection"], "evidence": before["evidence"]},
        event,
    )
    event = enforce_advisory_response(event, SECURITY_POLICY)
    store.save(event)
    write_audit_event(
        "investigate",
        {
            "event_id": event.get("event_id"),
            "rag_status": (event.get("enrichment") or {}).get("status"),
            "slm_status": (event.get("assessment") or {}).get("generation_status"),
        },
    )
    return {
        "event": event,
        "related_events": related,
        "rag": {
            "status": (event.get("enrichment") or {}).get("status"),
            "retrieval_count": (event.get("enrichment") or {}).get("retrieval_count", 0),
            "sources": (event.get("enrichment") or {}).get("sources", []),
        },
        "slm": {
            "status": "available_template" if not slm_formatter.available else "runtime_loaded",
            "model_id": slm_formatter.model_id,
            "generation_status": (event.get("assessment") or {}).get("generation_status"),
        },
    }


@app.get("/api/events/{event_id}")
def get_event(event_id: str) -> dict[str, Any]:
    event = store.get(event_id)
    if event is None:
        raise HTTPException(404, f"Unknown event_id: {event_id}")
    return event


@app.get("/api/demo-events")
def demo_events(limit: int = 25) -> list[dict[str, Any]]:
    if not SAMPLE_PATH.exists():
        raise HTTPException(404, "Sample data missing; run scripts/generate_sample.py")
    model = if_bundle()
    frame = pd.read_csv(SAMPLE_PATH).tail(max(1, min(limit, 100)))
    events = []
    for index, row in frame.iterrows():
        features = {name: float(row[name]) for name in model.features if name in row}
        device_id = f"demo-{index % 2:02d}"
        anomalies, feature_evidence = _collect_anomalies(
            device_id=device_id,
            session_id=str(row.get("session_id", "demo")),
            features=features,
        )
        device_type = str(row.get("device_type", "medical_aiot"))
        profile = resolve_baseline_profile(device_type=device_type)
        baseline = score_baseline_features(features, profile)
        event = fuse_detections(
            device_id=device_id,
            device_type=device_type,
            operating_state=str(row.get("operating_state", "unknown")),
            baseline=baseline,
            known_attack=_known_from_xgboost(features, device_type),
            anomalies=anomalies,
            feature_evidence=feature_evidence,
        )
        events.append(store.save(event))
    return events
