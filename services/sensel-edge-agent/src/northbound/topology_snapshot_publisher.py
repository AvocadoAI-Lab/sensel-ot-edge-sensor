"""Publish sensel.ot_topology.snapshot.v1 northbound (PRD §6.1)."""

from __future__ import annotations

import json
import logging
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from src.config.settings import AppConfig
from src.northbound.mqtt import NorthboundMqttClient
from src.northbound.topology_delta import compute_topology_delta, read_topology_counts
from src.policy.operational_mode_sync import OperationalModeSync
from src.policy.topology_override_merge import build_manual_override_list
from src.policy.topology_override_sync import TopologyOverrideSync

logger = logging.getLogger(__name__)

SCHEMA = "sensel.ot_topology.snapshot.v1"
_PUBLISH_MODES = frozenset({"learning", "detect"})


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _read_json(path: Path) -> dict[str, Any]:
    if not path.is_file():
        return {}
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
        return raw if isinstance(raw, dict) else {}
    except (json.JSONDecodeError, OSError):
        return {}


def _apply_manual_overrides_to_topology(
    snapshot: dict[str, Any],
    overrides: list[dict[str, Any]],
) -> dict[str, Any]:
    if not overrides:
        return snapshot
    assets = [dict(a) for a in (snapshot.get("assets") or []) if isinstance(a, dict)]
    if not assets:
        return snapshot
    by_id = {str(a.get("asset_id") or ""): idx for idx, a in enumerate(assets) if a.get("asset_id")}
    allowed = frozenset(
        {"purdue_level", "asset_type", "zone", "criticality", "hostname", "vendor", "model"}
    )
    for raw in overrides:
        if not isinstance(raw, dict):
            continue
        aid = str(raw.get("asset_id") or "").strip()
        if not aid or aid not in by_id:
            continue
        patch = raw.get("patch") if isinstance(raw.get("patch"), dict) else raw
        idx = by_id[aid]
        asset = dict(assets[idx])
        for field in allowed:
            value = patch.get(field) if isinstance(patch, dict) else None
            if value is None:
                continue
            text = str(value).strip()
            if text:
                asset[field] = text
        asset["manual_override"] = True
        evidence = list(asset.get("evidence_sources") or [])
        if "manual_tag" not in evidence:
            evidence.append("manual_tag")
        asset["evidence_sources"] = evidence
        assets[idx] = asset
    out = dict(snapshot)
    out["assets"] = assets
    return out


class TopologySnapshotPublisher:
    def __init__(
        self,
        config: AppConfig,
        mqtt: NorthboundMqttClient,
        mode_sync: OperationalModeSync,
        topology_override_sync: TopologyOverrideSync | None = None,
    ) -> None:
        ps = config.policy_sync
        self._enabled = bool(getattr(ps, "topology_snapshot_enabled", True))
        self._interval = max(30, int(getattr(ps, "topology_snapshot_interval_sec", 120)))
        self._detect_interval = max(
            60,
            int(getattr(ps, "topology_snapshot_detect_interval_sec", 300)),
        )
        self._live_observed_path = Path(ps.live_observed_path)
        self._state_path = Path(getattr(ps, "topology_snapshot_state_path", "/app/data/topology-snapshot-state.json"))
        self._mqtt = mqtt
        self._mode_sync = mode_sync
        self._topology_override_sync = topology_override_sync
        self._sensor = config.sensor
        self._tenant_id = config.northbound_mqtt.tenant_id
        self._last_publish = 0.0
        self._last_detect_publish = 0.0

    @property
    def enabled(self) -> bool:
        return self._enabled and self._mqtt.enabled

    def maybe_publish(self, *, force: bool = False) -> bool:
        if not self.enabled:
            return False
        now = time.monotonic()

        artifact = self._mode_sync.read_state()
        mode = str(artifact.get("mode") or "").strip().lower()
        if mode not in _PUBLISH_MODES:
            return False

        if mode == "detect":
            if not force and (now - self._last_detect_publish) < self._detect_interval:
                return False
            return self._publish_detect_delta(artifact, now, force=force)

        if not force and (now - self._last_publish) < self._interval:
            return False
        return self._publish_learning_snapshot(artifact, now)

    def _publish_learning_snapshot(self, artifact: dict[str, Any], now: float) -> bool:
        live = _read_json(self._live_observed_path)
        observed = live.get("observed") if isinstance(live.get("observed"), dict) else {}
        topology = observed.get("topology") if isinstance(observed.get("topology"), dict) else {}
        if not topology.get("assets"):
            return False

        manual_overrides: list[dict[str, Any]] = []
        if self._topology_override_sync and self._topology_override_sync.enabled:
            manual_overrides = build_manual_override_list(self._topology_override_sync.read_state())
        if manual_overrides:
            topology = _apply_manual_overrides_to_topology(topology, manual_overrides)

        payload: dict[str, Any] = {
            "schema": SCHEMA,
            "tenant_id": str(artifact.get("tenant_id") or self._tenant_id or "").strip(),
            "site_id": self._sensor.site_id,
            "sensor_id": self._sensor.id,
            "observed_at": _utc_now(),
            "operational_mode": "learning",
            "baseline_profile_id": str(artifact.get("baseline_profile_id") or "").strip() or None,
            "snapshot": {
                **topology,
                "schema": topology.get("schema") or SCHEMA,
                "tenant_id": str(artifact.get("tenant_id") or self._tenant_id or "").strip(),
                "site_id": self._sensor.site_id,
                "sensor_id": self._sensor.id,
            },
        }
        ok = self._mqtt.publish_topology_snapshot(payload)
        if ok:
            self._last_publish = now
            counts = read_topology_counts(self._live_observed_path)
            _save_state(
                self._state_path,
                {
                    "last_publish_at": payload["observed_at"],
                    "last_full_publish_at": payload["observed_at"],
                    "asset_count": counts["assets"],
                    "conduit_count": counts["conduits"],
                    "external_count": counts["external"],
                    "operational_mode": "learning",
                    "topology_counts": counts,
                },
            )
            logger.info(
                "Topology snapshot published mode=learning assets=%s conduits=%s",
                counts["assets"],
                counts["conduits"],
            )
        return ok

    def _publish_detect_delta(self, artifact: dict[str, Any], now: float, *, force: bool = False) -> bool:
        state = _read_json(self._state_path)
        delta = compute_topology_delta(self._live_observed_path, state.get("topology_counts"))
        if delta is None:
            return False

        payload: dict[str, Any] = {
            "schema": SCHEMA,
            "tenant_id": str(artifact.get("tenant_id") or self._tenant_id or "").strip(),
            "site_id": self._sensor.site_id,
            "sensor_id": self._sensor.id,
            "observed_at": _utc_now(),
            "operational_mode": "detect",
            "baseline_profile_id": str(artifact.get("baseline_profile_id") or "").strip() or None,
            "topology_delta": delta,
        }
        ok = self._mqtt.publish_topology_snapshot(payload)
        if ok:
            self._last_detect_publish = now
            counts = read_topology_counts(self._live_observed_path)
            _save_state(
                self._state_path,
                {
                    **state,
                    "last_publish_at": payload["observed_at"],
                    "last_delta_publish_at": payload["observed_at"],
                    "asset_count": counts["assets"],
                    "conduit_count": counts["conduits"],
                    "external_count": counts["external"],
                    "operational_mode": "detect",
                    "topology_counts": counts,
                    "last_topology_delta": delta,
                },
            )
            logger.info(
                "Topology delta published mode=detect delta=%s counts=%s",
                delta,
                counts,
            )
        return ok


def _save_state(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
