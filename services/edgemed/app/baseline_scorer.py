"""Score flow features against a sensel.baseline.profile.v1 artifact."""

from __future__ import annotations

from typing import Any

from .baseline_templates import resolve_profile_for_device_type


def _forbidden_patterns(profile: dict[str, Any]) -> set[str]:
    observed = profile.get("observed") if isinstance(profile.get("observed"), dict) else {}
    iomt = observed.get("iomt") if isinstance(observed.get("iomt"), dict) else {}
    patterns = {str(item).strip().lower() for item in (iomt.get("forbidden_patterns") or []) if str(item).strip()}
    categories = observed.get("allowed_destination_categories")
    if isinstance(categories, list):
        _ = categories
    return patterns


def _feature_float(features: dict[str, float], *names: str, default: float = 0.0) -> float:
    for name in names:
        if name in features:
            try:
                return float(features[name])
            except (TypeError, ValueError):
                continue
    return default


def score_baseline_features(
    features: dict[str, float],
    profile: dict[str, Any],
) -> dict[str, Any]:
    """Return a fusion-ready baseline payload from numeric flow features."""
    observed = profile.get("observed") if isinstance(profile.get("observed"), dict) else {}
    thresholds = observed.get("thresholds") if isinstance(observed.get("thresholds"), dict) else {}
    forbidden = _forbidden_patterns(profile)

    rate = _feature_float(features, "rate", "packet_rate")
    syn_count = _feature_float(features, "syn_count")
    ack_count = _feature_float(features, "ack_count")
    icmp = _feature_float(features, "icmp")
    tcp = _feature_float(features, "tcp")
    total_proto = max(icmp + tcp + _feature_float(features, "udp"), 1.0)
    syn_den = max(syn_count + ack_count, 1.0)
    syn_ratio = syn_count / syn_den
    icmp_ratio = icmp / total_proto

    violations: list[str] = []
    score = 0.0

    max_syn = float(thresholds.get("max_sustained_syn_ratio") or 0.15)
    if syn_ratio > max_syn and {"syn_flood", "sustained_flood"} & forbidden:
        violation = "syn_flood" if "syn_flood" in forbidden else "sustained_flood"
        violations.append(violation)
        score = max(score, min(1.0, syn_ratio / max(max_syn, 1e-6)))

    rate_p95 = thresholds.get("rate_p95_hint")
    if rate_p95 is not None:
        try:
            rate_limit = float(rate_p95)
        except (TypeError, ValueError):
            rate_limit = 0.0
        if rate_limit > 0 and rate > rate_limit * 1.5 and "sustained_flood" in forbidden:
            violations.append("sustained_flood")
            score = max(score, min(1.0, rate / (rate_limit * 1.5)))

    if icmp_ratio > 0.5 and rate > 100 and "icmp_storm" in forbidden:
        violations.append("icmp_storm")
        score = max(score, min(1.0, icmp_ratio))

    if syn_ratio > 0.4 and rate > 500 and "port_scan" in forbidden:
        violations.append("internal_port_scan")
        score = max(score, 0.75)

    compliant = not violations
    return {
        "compliant": compliant,
        "score": round(score, 6),
        "violations": violations,
        "profile_id": str(profile.get("profile_id") or ""),
        "profile_version": str(profile.get("version") or ""),
        "model_version": str(profile.get("version") or profile.get("profile_id") or "baseline-profile"),
        "detector": "baseline_profile",
        "syn_ratio": round(syn_ratio, 6),
        "rate": round(rate, 6),
    }


def resolve_baseline_profile(
    *,
    device_type: str,
    baseline_profile: dict[str, Any] | None = None,
) -> dict[str, Any]:
    if baseline_profile and isinstance(baseline_profile.get("observed"), dict):
        return baseline_profile
    template, _resolution = resolve_profile_for_device_type(device_type)
    return template
