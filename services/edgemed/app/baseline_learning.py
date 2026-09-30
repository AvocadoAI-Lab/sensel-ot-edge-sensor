"""Convert live-learned baseline candidates into edge-ready profile artifacts.

A live candidate is produced by Edge observation (BaselineCollector /
live-observed.json). It must never contain borrowed CIC traffic magnitudes.
Approval merges the candidate with organisation-wide common rules and marks
the resulting profile as ``live_learning``.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from app.baseline_templates import (
    RESOLUTION_GENERIC,
    apply_common_rules,
    load_common_rules,
    load_fallback_template,
)

RESOLUTION_LIVE_LEARNING = "live_learning"


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _version_stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y.%m.%d.%H%M%S")


def validate_live_candidate(candidate: dict[str, Any]) -> list[str]:
    """Return human-readable problems that block approval."""
    errors: list[str] = []
    if not isinstance(candidate, dict):
        return ["candidate must be an object"]
    source = str(candidate.get("source") or "")
    if source not in {"live_observed", "live_learning", "pcap_import"}:
        errors.append(f"unsupported candidate source: {source!r}")
    observed = candidate.get("observed")
    if not isinstance(observed, dict) or not observed:
        errors.append("candidate.observed is required")
        return errors
    if "cic_profiling_stats" in observed:
        errors.append("candidate must not carry cic_profiling_stats")
    thresholds = observed.get("thresholds") if isinstance(observed.get("thresholds"), dict) else {}
    for key in ("rate_p50_hint", "rate_p95_hint", "duration_p50_hint", "duration_p95_hint"):
        if key in thresholds:
            errors.append(f"candidate must not carry borrowed threshold {key}")
    has_identity = bool(
        (observed.get("comm_pairs") or [])
        or (observed.get("mac_ip") or [])
        or ((observed.get("iec61850") or {}).get("goose_publishers") if isinstance(observed.get("iec61850"), dict) else [])
        or ((observed.get("iec61850") or {}).get("mms_ieds") if isinstance(observed.get("iec61850"), dict) else [])
        or (observed.get("modbus_servers") or [])
        or ((observed.get("iomt") or {}).get("normal_destinations") if isinstance(observed.get("iomt"), dict) else [])
    )
    if not has_identity:
        errors.append("candidate.observed has no learnable identities")
    return errors


def _destination_categories_from_observed(observed: dict[str, Any]) -> list[str]:
    """Infer destination categories from learned identities without inventing rates."""
    categories: list[str] = []
    iomt = observed.get("iomt") if isinstance(observed.get("iomt"), dict) else {}
    for item in iomt.get("allowed_destination_categories") or []:
        text = str(item).strip()
        if text and text not in categories:
            categories.append(text)
    for item in iomt.get("normal_destinations") or []:
        text = str(item).strip().lower()
        if not text:
            continue
        mapped = {
            "dns": "dns",
            "ntp": "ntp",
            "mqtt-broker": "mqtt-broker",
            "broker": "mqtt-broker",
            "companion-app": "companion-app",
            "base-station": "base-station",
            "local-gateway": "local-gateway",
            "vendor-cloud": "vendor-cloud",
            "cloud": "vendor-cloud",
        }.get(text)
        if mapped and mapped not in categories:
            categories.append(mapped)
    for pair in observed.get("comm_pairs") or []:
        if not isinstance(pair, dict):
            continue
        dst = str(pair.get("dst") or "").lower()
        if any(token in dst for token in ("mqtt", "1883", "8883")) and "mqtt-broker" not in categories:
            categories.append("mqtt-broker")
        if any(token in dst for token in ("cloud", "amazonaws", "azure", "googleapis")) and "vendor-cloud" not in categories:
            categories.append("vendor-cloud")
    return categories


def build_learned_profile(
    candidate: dict[str, Any],
    *,
    device_type: str,
    asset_id: str,
    sensor_id: str,
    site_id: str = "",
    tenant_id: str = "default",
    profile_id: str = "",
) -> dict[str, Any]:
    """Approve a live candidate into a distributeable baseline profile."""
    errors = validate_live_candidate(candidate)
    if errors:
        raise ValueError("; ".join(errors))

    common_rules = load_common_rules()
    # Start from the generic observe-only shell so we never inherit another
    # device type's traffic magnitudes, then overlay the live observations.
    shell = apply_common_rules(load_fallback_template(), common_rules)
    observed = dict(candidate.get("observed") or {})
    shell_observed = dict(shell.get("observed") or {})
    shell_iomt = dict(shell_observed.get("iomt") or {})
    cand_iomt = observed.get("iomt") if isinstance(observed.get("iomt"), dict) else {}

    learned_categories = _destination_categories_from_observed(observed)
    allowed = list(shell_iomt.get("allowed_destination_categories") or [])
    for category in learned_categories:
        if category not in allowed:
            allowed.append(category)

    iomt = {
        "normal_destinations": list(cand_iomt.get("normal_destinations") or []),
        "allowed_destination_categories": allowed,
        "forbidden_patterns": list(shell_iomt.get("forbidden_patterns") or []),
        "interaction_modes": list(cand_iomt.get("interaction_modes") or []),
    }
    if cand_iomt.get("forbidden_patterns"):
        for pattern in cand_iomt["forbidden_patterns"]:
            text = str(pattern)
            if text not in iomt["forbidden_patterns"]:
                iomt["forbidden_patterns"].append(text)

    merged_observed: dict[str, Any] = {
        "iomt": iomt,
        "thresholds": {
            "packet_rate_baseline": "learned_local",
            "assert_rate_thresholds": False,
        },
        "comm_pairs": list(observed.get("comm_pairs") or []),
        "mac_ip": list(observed.get("mac_ip") or []),
        "iec61850": observed.get("iec61850") if isinstance(observed.get("iec61850"), dict) else {},
        "modbus_servers": list(observed.get("modbus_servers") or []),
        "provenance": {
            "resolution": RESOLUTION_LIVE_LEARNING,
            "requested_device_type": device_type,
            "profile_device_type": device_type or "unknown_device",
            "stats_source": "live_learning",
            "common_rules_id": str(common_rules.get("rules_id") or ""),
            "requires_local_learning": False,
            "candidate_source": candidate.get("source"),
            "candidate_source_ref": candidate.get("source_ref"),
            "candidate_generated_at": candidate.get("generated_at"),
            "approved_at": _utc_now(),
            "prior_resolution": RESOLUTION_GENERIC,
        },
    }
    if observed.get("topology") is not None:
        merged_observed["topology"] = observed.get("topology")

    resolved_profile_id = profile_id.strip() or f"learned-{device_type.strip() or 'unknown'}-v1"
    version = _version_stamp()
    return {
        "schema": "sensel.baseline.profile.v1",
        "profile_id": resolved_profile_id,
        "version": version,
        "sensor_id": sensor_id,
        "site_id": site_id,
        "tenant_id": tenant_id,
        "asset_id": asset_id,
        "device_type": device_type,
        "stats_source": "live_learning",
        "observed": merged_observed,
        "onboarding": {
            "initial_mode": "detect",
            "detect_after_learning": True,
            "require_learned_baseline_before_detect": False,
            "learned_from_session": True,
        },
        "edgemed": shell.get("edgemed") if isinstance(shell.get("edgemed"), dict) else {},
        "candidate_stats": candidate.get("stats") if isinstance(candidate.get("stats"), dict) else {},
    }


def synthesize_lab_live_candidate(
    *,
    device_ip: str = "192.168.50.210",
    vendor_cloud_host: str = "vendor-cloud.example.com",
    mqtt_broker: str = "192.168.50.134",
    dns: str = "8.8.8.8",
    mac: str = "02:11:22:33:44:55",
) -> dict[str, Any]:
    """Build a lab live-observed candidate without reading CIC datasets.

    This mimics what BaselineCollector would emit after watching a brand-new
    device talk to organisation-common destinations.
    """
    return {
        "schema": "sensel.baseline/1",
        "generated_at": _utc_now(),
        "source": "live_observed",
        "source_ref": "lab-synthetic-live",
        "window_sec": 900,
        "stats": {
            "packets": 128,
            "parse_errors": 0,
            "unique_macs": 1,
            "unique_ips": 4,
            "comm_pairs": 3,
            "goose_publishers": 0,
            "mms_ieds": 0,
            "modbus_servers": 0,
        },
        "observed": {
            "iomt": {
                "normal_destinations": ["vendor-cloud", "mqtt-broker", "dns"],
                "interaction_modes": ["idle_keepalive", "periodic_upload"],
            },
            "comm_pairs": [
                {"src": device_ip, "dst": vendor_cloud_host},
                {"src": device_ip, "dst": mqtt_broker},
                {"src": device_ip, "dst": dns},
            ],
            "mac_ip": [{"mac": mac, "ip": device_ip}],
            "iec61850": {"goose_publishers": [], "mms_ieds": []},
            "modbus_servers": [],
        },
    }
