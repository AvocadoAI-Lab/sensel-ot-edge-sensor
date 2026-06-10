"""Apply OT detection policy artifacts (rules_enabled + baseline) from MQTT/HTTP."""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from src.config.settings import AppConfig

logger = logging.getLogger(__name__)

SCHEMA_VERSION = "ot_detection_policy.v1"


@dataclass(frozen=True)
class DetectionPolicyResult:
    ok: bool
    changed: bool
    version: str = ""
    site_id: str = ""
    tenant_id: str = ""
    error: str | None = None


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def write_stamp(stamp_path: Path, *, version: str) -> None:
    stamp_path.parent.mkdir(parents=True, exist_ok=True)
    stamp_path.write_text(f"{_utc_now()}\n{version}\n", encoding="utf-8")


class DetectionPolicySync:
    def __init__(self, config: AppConfig) -> None:
        ps = config.policy_sync
        self._enabled = bool(ps.detection_policy_enabled)
        self._policy_path = Path(ps.detection_policy_path)
        self._stamp_path = Path(ps.detection_policy_stamp_path)

    @property
    def enabled(self) -> bool:
        return self._enabled

    def apply_artifact(
        self,
        artifact: dict[str, Any],
        *,
        tenant_id: str,
        source: str = "mqtt",
    ) -> DetectionPolicyResult:
        if not self._enabled:
            return DetectionPolicyResult(ok=True, changed=False, error="detection_policy_disabled")

        if not isinstance(artifact, dict):
            return DetectionPolicyResult(ok=False, changed=False, error="payload is not an object")

        version = str(artifact.get("version") or artifact.get("artifact_version") or "").strip()
        site_id = str(artifact.get("site_id") or "").strip()
        rules = artifact.get("rules_enabled")
        baseline = artifact.get("baseline")

        if rules is not None and not isinstance(rules, list):
            return DetectionPolicyResult(ok=False, changed=False, error="rules_enabled must be a list")
        if baseline is not None and not isinstance(baseline, dict):
            return DetectionPolicyResult(ok=False, changed=False, error="baseline must be an object")

        existing: dict[str, Any] = {}
        if self._policy_path.is_file():
            try:
                existing = json.loads(self._policy_path.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError):
                existing = {}

        if (
            existing
            and version
            and str(existing.get("version") or "") == version
            and str(existing.get("tenant_id") or "") == tenant_id
        ):
            return DetectionPolicyResult(
                ok=True,
                changed=False,
                version=version,
                site_id=site_id,
                tenant_id=tenant_id,
            )

        payload: dict[str, Any] = {
            "schema_version": str(artifact.get("schema_version") or SCHEMA_VERSION),
            "tenant_id": tenant_id,
            "site_id": site_id,
            "sensor_id": artifact.get("sensor_id"),
            "version": version or _utc_now(),
            "generated_at": str(artifact.get("generated_at") or _utc_now()),
            "updated_at": _utc_now(),
            "source": source,
        }
        if rules is not None:
            payload["rules_enabled"] = [str(r).strip().upper() for r in rules if str(r).strip()]
        elif existing.get("rules_enabled"):
            payload["rules_enabled"] = existing["rules_enabled"]

        if baseline is not None:
            payload["baseline"] = baseline
        elif existing.get("baseline"):
            payload["baseline"] = existing["baseline"]

        self._policy_path.parent.mkdir(parents=True, exist_ok=True)
        self._policy_path.write_text(
            json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        write_stamp(self._stamp_path, version=str(payload["version"]))

        logger.info(
            "Detection policy applied via %s tenant=%s site=%s version=%s rules=%s",
            source,
            tenant_id,
            site_id or "-",
            payload["version"],
            len(payload.get("rules_enabled") or []),
        )
        return DetectionPolicyResult(
            ok=True,
            changed=True,
            version=str(payload["version"]),
            site_id=site_id,
            tenant_id=tenant_id,
        )
