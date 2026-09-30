"""Apply Portal topology override artifacts (sensel.ot_topology.override.v1)."""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from src.config.settings import AppConfig
from src.policy.operational_mode_sync import write_stamp

logger = logging.getLogger(__name__)

SCHEMA_VERSION = "sensel.ot_topology.override.v1"
STORE_SCHEMA = "sensel.ot_topology.override_store.v1"


@dataclass(frozen=True)
class TopologyOverrideResult:
    ok: bool
    changed: bool
    asset_id: str = ""
    tenant_id: str = ""
    error: str | None = None


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


class TopologyOverrideSync:
    def __init__(self, config: AppConfig) -> None:
        ps = config.policy_sync
        self._enabled = bool(getattr(ps, "topology_override_enabled", True))
        self._store_path = Path(getattr(ps, "topology_override_path", "/app/data/topology-asset-overrides.json"))
        self._stamp_path = Path(
            getattr(ps, "topology_override_stamp_path", "/app/data/topology-asset-overrides.stamp")
        )
        self._sensor_id = config.sensor.id

    @property
    def enabled(self) -> bool:
        return self._enabled

    def read_state(self) -> dict[str, Any]:
        if not self._store_path.is_file():
            return {"schema": STORE_SCHEMA, "overrides": {}}
        try:
            raw = json.loads(self._store_path.read_text(encoding="utf-8"))
            if not isinstance(raw, dict):
                return {"schema": STORE_SCHEMA, "overrides": {}}
            overrides = raw.get("overrides")
            if not isinstance(overrides, dict):
                raw["overrides"] = {}
            return raw
        except (json.JSONDecodeError, OSError):
            return {"schema": STORE_SCHEMA, "overrides": {}}

    def get_override(self, asset_id: str) -> dict[str, Any]:
        state = self.read_state()
        entry = (state.get("overrides") or {}).get(asset_id)
        return entry if isinstance(entry, dict) else {}

    def apply_artifact(
        self,
        artifact: dict[str, Any],
        *,
        tenant_id: str,
        source: str = "mqtt",
    ) -> TopologyOverrideResult:
        if not self._enabled:
            return TopologyOverrideResult(ok=True, changed=False, error="topology_override_disabled")

        schema = str(artifact.get("schema") or "").strip()
        if schema and schema != SCHEMA_VERSION:
            return TopologyOverrideResult(ok=False, changed=False, error=f"unsupported schema {schema}")

        asset_id = str(artifact.get("asset_id") or "").strip()
        if not asset_id:
            return TopologyOverrideResult(ok=False, changed=False, error="asset_id required")

        payload_sensor = str(artifact.get("sensor_id") or "").strip()
        if payload_sensor and payload_sensor != self._sensor_id:
            return TopologyOverrideResult(
                ok=False,
                changed=False,
                error=f"sensor mismatch payload={payload_sensor} local={self._sensor_id}",
            )

        patch = artifact.get("patch")
        if not isinstance(patch, dict) or not patch:
            return TopologyOverrideResult(ok=False, changed=False, asset_id=asset_id, error="patch required")

        state = self.read_state()
        overrides = dict(state.get("overrides") or {})
        existing = overrides.get(asset_id) if isinstance(overrides.get(asset_id), dict) else {}
        merged_patch = dict(existing.get("patch") or {})
        for key, value in patch.items():
            if value is None:
                continue
            text = str(value).strip()
            if text:
                merged_patch[key] = text

        entry = {
            "asset_id": asset_id,
            "tenant_id": tenant_id or str(artifact.get("tenant_id") or ""),
            "sensor_id": payload_sensor or self._sensor_id,
            "patch": merged_patch,
            "manual_override": True,
            "evidence_sources": ["manual_tag"],
            "issued_at": str(artifact.get("issued_at") or _utc_now()),
            "issued_by_user_id": artifact.get("issued_by_user_id"),
            "source": source,
            "schema": SCHEMA_VERSION,
        }
        if existing == entry:
            return TopologyOverrideResult(
                ok=True,
                changed=False,
                asset_id=asset_id,
                tenant_id=entry["tenant_id"],
            )

        overrides[asset_id] = entry
        out_doc = {
            "schema": STORE_SCHEMA,
            "tenant_id": entry["tenant_id"],
            "sensor_id": self._sensor_id,
            "updated_at": _utc_now(),
            "overrides": overrides,
        }
        self._store_path.parent.mkdir(parents=True, exist_ok=True)
        self._store_path.write_text(
            json.dumps(out_doc, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        write_stamp(self._stamp_path, version=f"{asset_id}:{entry['issued_at']}")
        logger.info(
            "Topology override applied asset=%s purdue=%s asset_type=%s source=%s",
            asset_id,
            merged_patch.get("purdue_level"),
            merged_patch.get("asset_type"),
            source,
        )
        return TopologyOverrideResult(
            ok=True,
            changed=True,
            asset_id=asset_id,
            tenant_id=entry["tenant_id"],
        )
