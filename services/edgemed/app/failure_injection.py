from __future__ import annotations

from typing import Any, Callable

from .fusion import fuse_detections, template_fallback_event
from .rag.orchestrator import DeterministicOrchestrator
from .schema import detector_owned_snapshot
from .slm import apply_slm_to_event, validate_slm_output


class ComponentUnavailable(RuntimeError):
    pass


def inject_detector_failure(
    *,
    which: str,
    known_attack: dict[str, Any] | None,
    anomaly: dict[str, Any] | None,
) -> dict[str, Any]:
    """Simulate detector unavailability and exercise fusion fallbacks."""
    if which == "known_attack":
        known_attack = None
    elif which == "anomaly":
        anomaly = None
    elif which == "both":
        known_attack = None
        anomaly = None
    else:
        raise ValueError(f"unknown detector failure target: {which}")

    if known_attack is None and anomaly is None:
        raise ComponentUnavailable("both detectors unavailable")
    return fuse_detections(
        device_id="failure-injection-device",
        device_type="patient_monitor",
        operating_state="idle",
        known_attack=known_attack,
        anomaly=anomaly,
        persist_reason=f"failure_injection:{which}",
    )


def inject_slm_failure(event: dict[str, Any]) -> dict[str, Any]:
    bad = {
        "summary_en": "Isolate the device immediately and disable the firewall.",
        "taxonomy": "not_a_real_taxonomy",
        "evidence_ids": ["ev_fabricated"],
        "retrieval_intents": ["run_shell"],
        "status": "ok",
    }
    errors = validate_slm_output(bad, event)
    assert errors, "expected SLM failure payload to be invalid"
    before = detector_owned_snapshot(event)
    updated = apply_slm_to_event(event, bad)
    assert updated["assessment"]["generation_status"] == "template_fallback"
    assert detector_owned_snapshot(updated) == before
    return updated


def inject_rag_failure(orchestrator: DeterministicOrchestrator, event: dict[str, Any]) -> dict[str, Any]:
    """Force RAG tools to fail and ensure enrichment becomes unavailable."""

    def failing_call(tool_name: str, arguments: dict[str, Any]):
        from .rag.tools import ToolResult
        return ToolResult(tool_name, False, [], {}, error="injected_failure")

    original = orchestrator.tools.call
    orchestrator.tools.call = failing_call  # type: ignore[method-assign]
    try:
        updated = orchestrator.apply(event)
    finally:
        orchestrator.tools.call = original  # type: ignore[method-assign]
    assert updated["enrichment"]["status"] == "enrichment_unavailable"
    return updated


def run_failure_matrix(
    *,
    known_attack: dict[str, Any],
    anomaly: dict[str, Any],
    orchestrator_factory: Callable[[], DeterministicOrchestrator],
) -> dict[str, Any]:
    report: dict[str, Any] = {"cases": []}

    for which in ("known_attack", "anomaly"):
        event = inject_detector_failure(which=which, known_attack=known_attack, anomaly=anomaly)
        report["cases"].append({
            "case": f"detector_{which}_unavailable",
            "detection_status": event["detection"]["status"],
            "ok": event["detection"]["status"] == "partial_detection",
        })

    both_ok = False
    try:
        inject_detector_failure(which="both", known_attack=known_attack, anomaly=anomaly)
    except ComponentUnavailable:
        both_ok = True
    report["cases"].append({"case": "both_detectors_unavailable", "ok": both_ok})

    base = fuse_detections(
        device_id="failure-injection-device",
        device_type="patient_monitor",
        operating_state="idle",
        known_attack=known_attack,
        anomaly=anomaly,
        feature_evidence=[{"feature": "packet_rate", "observed": 10, "source": "detector:test"}],
    )
    slm_event = inject_slm_failure(base)
    report["cases"].append({
        "case": "slm_invalid_output",
        "ok": slm_event["assessment"]["generation_status"] == "template_fallback",
    })

    rag_event = inject_rag_failure(orchestrator_factory(), base)
    report["cases"].append({
        "case": "rag_all_tools_fail",
        "ok": rag_event["enrichment"]["status"] == "enrichment_unavailable",
    })

    report["passed"] = all(case["ok"] for case in report["cases"])
    return report
