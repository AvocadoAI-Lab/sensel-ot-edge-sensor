"""Load device-type baseline starter templates and resolve unknown device types.

Known device types resolve to a dedicated starter template. Unknown device types
resolve to a statistics-free fallback profile seeded only with organisation-wide
common rules, so onboarding never borrows another device type's traffic
magnitudes.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
TEMPLATES_DIR = ROOT / "config" / "baseline-templates"
CATALOG_PATH = TEMPLATES_DIR / "index.json"

RESOLUTION_DEVICE_TYPE = "device_type_template"
RESOLUTION_GENERIC = "generic_fallback"


def load_catalog(path: Path | None = None) -> dict[str, Any]:
    catalog_path = path or CATALOG_PATH
    raw = json.loads(catalog_path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError("baseline template catalog must be an object")
    return raw


def list_templates(path: Path | None = None) -> list[dict[str, Any]]:
    catalog = load_catalog(path)
    items = catalog.get("templates") or []
    return [item for item in items if isinstance(item, dict)]


def template_path_for(entry: dict[str, Any], *, base_dir: Path | None = None) -> Path:
    filename = str(entry.get("file") or "").strip()
    if not filename:
        raise ValueError("template entry missing file")
    return (base_dir or TEMPLATES_DIR) / filename


def load_template(profile_id: str, *, base_dir: Path | None = None) -> dict[str, Any]:
    for entry in list_templates():
        if str(entry.get("profile_id") or "") == profile_id:
            path = template_path_for(entry, base_dir=base_dir)
            raw = json.loads(path.read_text(encoding="utf-8"))
            if not isinstance(raw, dict):
                raise ValueError(f"{path} must contain a JSON object")
            return raw
    raise KeyError(f"unknown baseline template profile_id: {profile_id}")


def load_common_rules(*, base_dir: Path | None = None) -> dict[str, Any]:
    entry = load_catalog().get("common_rules")
    if not isinstance(entry, dict):
        raise KeyError("catalog is missing common_rules")
    raw = json.loads(template_path_for(entry, base_dir=base_dir).read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError("common rules must contain a JSON object")
    return raw


def load_fallback_template(*, base_dir: Path | None = None) -> dict[str, Any]:
    entry = load_catalog().get("fallback")
    if not isinstance(entry, dict):
        raise KeyError("catalog is missing fallback")
    raw = json.loads(template_path_for(entry, base_dir=base_dir).read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError("fallback template must contain a JSON object")
    return raw


def template_for_device_type(device_type: str, *, base_dir: Path | None = None) -> dict[str, Any] | None:
    wanted = device_type.strip()
    if not wanted:
        return None
    for entry in list_templates():
        if str(entry.get("device_type") or "") == wanted:
            return load_template(str(entry.get("profile_id") or ""), base_dir=base_dir)
    return None


def _merged_forbidden_patterns(template: dict[str, Any], common_rules: dict[str, Any]) -> list[str]:
    observed = template.get("observed") if isinstance(template.get("observed"), dict) else {}
    iomt = observed.get("iomt") if isinstance(observed.get("iomt"), dict) else {}
    own = [str(item) for item in (iomt.get("forbidden_patterns") or [])]
    common = [str(item) for item in (common_rules.get("forbidden_patterns") or [])]
    merged = list(own)
    for pattern in common:
        if pattern not in merged:
            merged.append(pattern)
    return merged


def apply_common_rules(template: dict[str, Any], common_rules: dict[str, Any]) -> dict[str, Any]:
    """Return a copy whose observed block carries the organisation-wide safety net."""
    out = dict(template)
    observed = dict(out.get("observed") or {})
    iomt = dict(observed.get("iomt") or {})
    iomt["forbidden_patterns"] = _merged_forbidden_patterns(template, common_rules)
    categories = [str(item) for item in (common_rules.get("allowed_destination_categories") or [])]
    if categories:
        iomt["allowed_destination_categories"] = categories
    observed["iomt"] = iomt

    guardrails = common_rules.get("guardrails") if isinstance(common_rules.get("guardrails"), dict) else {}
    thresholds = dict(observed.get("thresholds") or {})
    if guardrails.get("assert_rate_thresholds") is False and "rate_p95_hint" not in thresholds:
        thresholds["assert_rate_thresholds"] = False
    observed["thresholds"] = thresholds
    out["observed"] = observed
    return out


def resolve_profile_for_device_type(
    device_type: str,
    *,
    base_dir: Path | None = None,
) -> tuple[dict[str, Any], str]:
    """Resolve a device type to a starter profile, never raising for unknown types.

    Returns the template with common rules applied plus the resolution kind.
    """
    common_rules = load_common_rules(base_dir=base_dir)
    template = template_for_device_type(device_type, base_dir=base_dir)
    if template is not None:
        return apply_common_rules(template, common_rules), RESOLUTION_DEVICE_TYPE
    return apply_common_rules(load_fallback_template(base_dir=base_dir), common_rules), RESOLUTION_GENERIC


def bind_asset(
    template: dict[str, Any],
    *,
    asset_id: str,
    sensor_id: str,
    site_id: str = "",
    tenant_id: str = "default",
    device_type: str = "",
    resolution: str = RESOLUTION_DEVICE_TYPE,
    common_rules_id: str = "",
) -> dict[str, Any]:
    """Return a sensel.baseline.profile.v1 artifact ready for edge-agent apply.

    Provenance is nested inside ``observed`` because the edge sync only persists
    the schema, identity and observed blocks.
    """
    profile_id = str(template.get("profile_id") or "").strip()
    if not profile_id:
        raise ValueError("template missing profile_id")
    device_template = template.get("device_template") if isinstance(template.get("device_template"), dict) else {}
    resolved_device_type = device_type.strip() or str(device_template.get("device_type") or "")

    observed = dict(template.get("observed") or {})
    observed["provenance"] = {
        "resolution": resolution,
        "requested_device_type": device_type.strip(),
        "profile_device_type": str(device_template.get("device_type") or ""),
        "stats_source": template.get("stats_source"),
        "common_rules_id": common_rules_id,
        "requires_local_learning": resolution == RESOLUTION_GENERIC,
    }

    payload: dict[str, Any] = {
        "schema": str(template.get("schema") or "sensel.baseline.profile.v1"),
        "profile_id": profile_id,
        "version": str(template.get("version") or ""),
        "sensor_id": sensor_id,
        "site_id": site_id,
        "tenant_id": tenant_id,
        "observed": observed,
        "asset_id": asset_id,
        "device_type": resolved_device_type,
        "onboarding": template.get("onboarding") if isinstance(template.get("onboarding"), dict) else {},
        "edgemed": template.get("edgemed") if isinstance(template.get("edgemed"), dict) else {},
        "stats_source": template.get("stats_source"),
    }
    return payload
