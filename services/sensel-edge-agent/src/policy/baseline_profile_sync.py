"""Apply sensel.baseline.profile.v1 artifacts from Portal MQTT."""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from src.config.settings import AppConfig

logger = logging.getLogger(__name__)

SCHEMA_VERSION = "sensel.baseline.profile.v1"


@dataclass(frozen=True)
class BaselineProfileResult:
    ok: bool
    changed: bool
    profile_id: str = ""
    version: str = ""
    tenant_id: str = ""
    error: str | None = None


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def write_stamp(stamp_path: Path, *, version: str) -> None:
    stamp_path.parent.mkdir(parents=True, exist_ok=True)
    stamp_path.write_text(f"{_utc_now()}\n{version}\n", encoding="utf-8")


class BaselineProfileSync:
    def __init__(self, config: AppConfig) -> None:
        ps = config.policy_sync
        self._enabled = bool(getattr(ps, "baseline_profile_enabled", True))
        self._profile_path = Path(getattr(ps, "baseline_profile_path", "/app/data/baseline-profile.json"))
        self._stamp_path = Path(getattr(ps, "baseline_profile_stamp_path", "/app/data/baseline-profile.stamp"))
        self._sensor_id = config.sensor.id

    @property
    def enabled(self) -> bool:
        return self._enabled

    def read_state(self) -> dict[str, Any]:
        if not self._profile_path.is_file():
            return {}
        try:
            raw = json.loads(self._profile_path.read_text(encoding="utf-8"))
            return raw if isinstance(raw, dict) else {}
        except (json.JSONDecodeError, OSError):
            return {}

    def apply_artifact(
        self,
        artifact: dict[str, Any],
        *,
        tenant_id: str,
        source: str = "mqtt",
    ) -> BaselineProfileResult:
        if not self._enabled:
            return BaselineProfileResult(ok=True, changed=False, error="baseline_profile_disabled")

        if not isinstance(artifact, dict):
            return BaselineProfileResult(ok=False, changed=False, error="payload is not an object")

        profile_id = str(artifact.get("profile_id") or "").strip()
        if not profile_id:
            return BaselineProfileResult(ok=False, changed=False, error="profile_id required")

        payload_sensor = str(artifact.get("sensor_id") or "").strip()
        if payload_sensor and payload_sensor != self._sensor_id:
            return BaselineProfileResult(
                ok=False,
                changed=False,
                error=f"sensor_id mismatch: expected {self._sensor_id}",
            )

        version = str(artifact.get("version") or artifact.get("updated_at") or _utc_now())
        existing = self.read_state()
        if (
            existing
            and str(existing.get("profile_id") or "") == profile_id
            and str(existing.get("version") or "") == version
            and str(existing.get("tenant_id") or "") == tenant_id
        ):
            return BaselineProfileResult(
                ok=True,
                changed=False,
                profile_id=profile_id,
                version=version,
                tenant_id=tenant_id,
            )

        observed = artifact.get("observed")
        if observed is not None and not isinstance(observed, dict):
            return BaselineProfileResult(ok=False, changed=False, error="observed must be an object")

        payload: dict[str, Any] = {
            "schema": str(artifact.get("schema") or SCHEMA_VERSION),
            "schema_version": str(artifact.get("schema_version") or SCHEMA_VERSION),
            "tenant_id": tenant_id,
            "profile_id": profile_id,
            "sensor_id": self._sensor_id,
            "site_id": str(artifact.get("site_id") or existing.get("site_id") or "").strip(),
            "version": version,
            "observed": observed if isinstance(observed, dict) else {},
            "updated_at": _utc_now(),
            "source": source,
        }

        self._profile_path.parent.mkdir(parents=True, exist_ok=True)
        self._profile_path.write_text(
            json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        write_stamp(self._stamp_path, version=version)

        logger.info(
            "Baseline profile applied via %s tenant=%s profile=%s version=%s",
            source,
            tenant_id,
            profile_id,
            version,
        )
        return BaselineProfileResult(
            ok=True,
            changed=True,
            profile_id=profile_id,
            version=version,
            tenant_id=tenant_id,
        )
