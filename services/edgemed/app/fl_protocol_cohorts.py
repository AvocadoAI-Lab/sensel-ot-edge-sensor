"""FL protocol cohort mapping for multi-global federated XGBoost experiments.

Sites stay as separate FL clients (e.g. six virtual devices), but aggregation
runs inside protocol cohorts so MQTT traffic is not mixed with WiFi/TCP or
pure network-layer attack families.
"""

from __future__ import annotations

from collections import defaultdict
from typing import Any, Mapping

# Primary attack / transport family used for FL model selection.
# Extend this table when onboarding new device types or protocols.
DEVICE_TYPE_TO_FL_COHORT: dict[str, str] = {
    "medical_camera": "wifi",
    "medical_pager": "wifi",
    "bp_monitor": "mqtt",
    "baby_sensor": "mqtt",
    "network_scanner": "network",
    "network_gateway": "network",
}

FL_COHORT_LABELS: dict[str, str] = {
    "wifi": "WiFi / TCP-UDP (non-MQTT IoMT)",
    "mqtt": "MQTT application-layer",
    "network": "Network-layer (recon / ARP / scan)",
}


def resolve_fl_protocol_group(site: Mapping[str, Any]) -> str:
    explicit = site.get("fl_protocol_group")
    if explicit:
        return str(explicit)
    device_type = str(site.get("device_type") or "")
    return cohort_for_device_type(device_type)


def cohort_for_device_type(device_type: str) -> str:
    """Map onboarded device_type to the XGBoost FL / deployment cohort."""
    normalized = str(device_type or "").strip()
    return DEVICE_TYPE_TO_FL_COHORT.get(normalized, "wifi")


def group_site_ids_by_cohort(
    site_ids: tuple[str, ...],
    *,
    splits_dir: Any,
) -> dict[str, tuple[str, ...]]:
    from pathlib import Path

    root = Path(splits_dir)
    buckets: dict[str, list[str]] = defaultdict(list)
    for site_id in site_ids:
        spec_path = root / f"{site_id}.json"
        if spec_path.is_file():
            import json

            spec = json.loads(spec_path.read_text(encoding="utf-8"))
        else:
            spec = {"site_id": site_id}
        cohort = resolve_fl_protocol_group(spec)
        buckets[cohort].append(site_id)
    return {cohort: tuple(sorted(ids)) for cohort, ids in sorted(buckets.items())}


def cohort_index(site_ids: tuple[str, ...], *, splits_dir: Any) -> dict[str, Any]:
    groups = group_site_ids_by_cohort(site_ids, splits_dir=splits_dir)
    return {
        "cohort_count": len(groups),
        "cohorts": {
            cohort: {
                "label": FL_COHORT_LABELS.get(cohort, cohort),
                "site_ids": list(site_ids_in_cohort),
                "site_count": len(site_ids_in_cohort),
            }
            for cohort, site_ids_in_cohort in groups.items()
        },
    }
