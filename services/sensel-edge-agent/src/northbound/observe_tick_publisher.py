"""Publish sensel.baseline.observe_tick.v1 northbound during listen/learning."""

from __future__ import annotations

import json
import logging
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from src.config.settings import AppConfig
from src.northbound.mqtt import NorthboundMqttClient
from src.policy.operational_mode_sync import OperationalModeSync
from src.policy.topology_override_sync import TopologyOverrideSync
from src.northbound.topology_delta import compute_topology_delta, read_topology_counts
from src.policy.topology_override_merge import (
    build_manual_override_list,
    merge_manual_overrides_into_snapshot,
)

logger = logging.getLogger(__name__)

SCHEMA = "sensel.baseline.observe_tick.v1"
_MODE_TO_KIND = {"listen": "observe", "learning": "learn"}


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


class ObserveTickPublisher:
    def __init__(
        self,
        config: AppConfig,
        mqtt: NorthboundMqttClient,
        mode_sync: OperationalModeSync,
        topology_override_sync: TopologyOverrideSync | None = None,
    ) -> None:
        ps = config.policy_sync
        self._enabled = bool(ps.observe_tick_enabled)
        self._interval = max(10, int(ps.observe_tick_interval_sec))
        self._capture_live_path = Path(ps.capture_live_path)
        self._live_observed_path = Path(ps.live_observed_path)
        self._state_path = Path(ps.observe_tick_state_path)
        self._mqtt = mqtt
        self._mode_sync = mode_sync
        self._topology_override_sync = topology_override_sync
        self._sensor = config.sensor
        self._tenant_id = config.northbound_mqtt.tenant_id
        self._last_publish = 0.0
        self._boot_at = time.monotonic()

    @property
    def enabled(self) -> bool:
        return self._enabled and self._mqtt.enabled

    def maybe_publish(self, *, force: bool = False) -> bool:
        if not self.enabled:
            return False
        now = time.monotonic()
        if not force and (now - self._last_publish) < self._interval:
            return False

        artifact = self._mode_sync.read_state()
        mode = str(artifact.get("mode") or "").strip().lower()
        if mode not in _MODE_TO_KIND:
            return False

        session_id = str(artifact.get("session_id") or "").strip()
        if not session_id:
            return False

        session_kind = _MODE_TO_KIND[mode]
        live = _read_json(self._capture_live_path)
        state = _load_state(self._state_path)
        minute_index = int(state.get("minute_index") or 0) + 1
        continuity = "ok"
        if state.get("session_id") != session_id:
            continuity = "reset"
        elif state.get("agent_boot_id") != _boot_id(self._boot_at):
            continuity = "reset"

        stats = {
            "packets": int(live.get("total_packets") or 0),
            "unique_ips": int(live.get("unique_ips") or 0),
            "unique_macs": int(live.get("unique_macs") or 0),
            "goose_publishers": int(live.get("goose_messages") or 0),
            "instant_rate": float(live.get("instant_rate") or 0),
            "capture_interface": str(
                live.get("capture_interface")
                or (artifact.get("capture") or {}).get("interface")
                or ""
            ),
        }
        top_pairs = _top_comm_pairs(live)

        manual_overrides: list[dict[str, Any]] = []
        if self._topology_override_sync and self._topology_override_sync.enabled:
            manual_overrides = build_manual_override_list(self._topology_override_sync.read_state())

        tick: dict[str, Any] = {
            "schema": SCHEMA,
            "schema_version": SCHEMA,
            "tenant_id": str(artifact.get("tenant_id") or self._tenant_id or "").strip(),
            "site_id": self._sensor.site_id,
            "sensor_id": self._sensor.id,
            "session_id": session_id,
            "session_kind": session_kind,
            "minute_index": minute_index,
            "continuity": continuity,
            "observed_at": _utc_now(),
            "stats": stats,
            "top_comm_pairs": top_pairs,
        }
        if manual_overrides:
            tick["topology_manual_overrides"] = manual_overrides
        if session_kind == "learn":
            observed = _read_json(self._live_observed_path)
            if observed:
                if manual_overrides and self._topology_override_sync:
                    observed = merge_manual_overrides_into_snapshot(
                        observed,
                        self._topology_override_sync.read_state(),
                    )
                tick["snapshot"] = observed
        else:
            delta = compute_topology_delta(self._live_observed_path, state.get("topology_counts"))
            if delta is not None:
                tick["topology_delta"] = delta

        ok = self._mqtt.publish_observe_tick(tick)
        if ok:
            self._last_publish = now
            next_state = {
                "session_id": session_id,
                "minute_index": minute_index,
                "agent_boot_id": _boot_id(self._boot_at),
                "last_publish_at": tick["observed_at"],
            }
            if tick.get("topology_delta") is not None:
                next_state["topology_counts"] = read_topology_counts(self._live_observed_path)
            _save_state(self._state_path, next_state)
            logger.info(
                "Observe tick published session=%s kind=%s minute=%s continuity=%s",
                session_id,
                session_kind,
                minute_index,
                continuity,
            )
        return ok


def _boot_id(boot_at: float) -> str:
    return f"{int(boot_at)}"


def _load_state(path: Path) -> dict[str, Any]:
    return _read_json(path)


def _save_state(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def _top_comm_pairs(live: dict[str, Any], limit: int = 8) -> list[dict[str, Any]]:
    pairs: list[dict[str, Any]] = []
    for row in live.get("top_ips") or []:
        if not isinstance(row, dict):
            continue
        ip = str(row.get("ip") or "").strip()
        if not ip:
            continue
        pairs.append({"ip": ip, "count": int(row.get("count") or 0)})
        if len(pairs) >= limit:
            break
    return pairs
