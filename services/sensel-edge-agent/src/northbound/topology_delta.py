"""Shared topology delta helpers (PRD §5.5 / §6.1)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Mapping


def read_topology_counts(live_observed_path: Path) -> dict[str, int]:
    observed = _read_json(live_observed_path)
    topo = (observed.get("observed") or {}).get("topology") if isinstance(observed.get("observed"), dict) else {}
    if not isinstance(topo, dict):
        topo = {}
    return {
        "assets": len(topo.get("assets") or []),
        "conduits": len(topo.get("conduits") or []),
        "external": len(topo.get("external_entities") or []),
    }


def compute_topology_delta(
    live_observed_path: Path,
    prev_counts: Mapping[str, Any] | None,
) -> dict[str, int] | None:
    current = read_topology_counts(live_observed_path)
    if not any(current.values()):
        return None
    prev = prev_counts if isinstance(prev_counts, Mapping) else {}
    return {
        "new_assets": max(0, current["assets"] - int(prev.get("assets") or 0)),
        "new_conduits": max(0, current["conduits"] - int(prev.get("conduits") or 0)),
        "new_external": max(0, current["external"] - int(prev.get("external") or 0)),
    }


def _read_json(path: Path) -> dict[str, Any]:
    if not path.is_file():
        return {}
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
        return raw if isinstance(raw, dict) else {}
    except (json.JSONDecodeError, OSError):
        return {}
