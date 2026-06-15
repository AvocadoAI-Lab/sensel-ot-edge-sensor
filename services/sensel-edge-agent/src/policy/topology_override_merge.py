"""Merge Portal manual topology overrides into baseline observe payloads."""

from __future__ import annotations

from typing import Any, Mapping


def build_manual_override_list(override_state: Mapping[str, Any]) -> list[dict[str, Any]]:
    overrides = override_state.get("overrides")
    if not isinstance(overrides, Mapping) or not overrides:
        return []
    out: list[dict[str, Any]] = []
    for entry in overrides.values():
        if not isinstance(entry, Mapping):
            continue
        patch = entry.get("patch")
        if not isinstance(patch, Mapping) or not patch:
            continue
        out.append(
            {
                "asset_id": str(entry.get("asset_id") or ""),
                "patch": dict(patch),
                "manual_override": True,
                "evidence_sources": ["manual_tag"],
                "issued_at": entry.get("issued_at"),
                "source": entry.get("source") or "mqtt",
            }
        )
    return out


def merge_manual_overrides_into_snapshot(
    snapshot: Mapping[str, Any],
    override_state: Mapping[str, Any],
) -> dict[str, Any]:
    manual = build_manual_override_list(override_state)
    if not manual:
        return dict(snapshot)
    out = dict(snapshot)
    observed = dict(out.get("observed") or {}) if isinstance(out.get("observed"), Mapping) else {}
    observed["topology_manual_overrides"] = manual
    out["observed"] = observed
    return out
