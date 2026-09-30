"""Apply operational mode artifacts from Portal MQTT (sensel.operational_mode.v1)."""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from src.config.settings import AppConfig

logger = logging.getLogger(__name__)

SCHEMA_VERSION = "sensel.operational_mode.v1"
VALID_MODES = frozenset({"listen", "learning", "detect", "idle"})


@dataclass(frozen=True)
class OperationalModeResult:
    ok: bool
    changed: bool
    mode: str = ""
    session_id: str = ""
    tenant_id: str = ""
    error: str | None = None


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def write_stamp(stamp_path: Path, *, version: str) -> None:
    stamp_path.parent.mkdir(parents=True, exist_ok=True)
    stamp_path.write_text(f"{_utc_now()}\n{version}\n", encoding="utf-8")


def _session_kind(mode: str) -> str | None:
    if mode == "listen":
        return "observe"
    if mode == "learning":
        return "learn"
    return None


class OperationalModeSync:
    def __init__(self, config: AppConfig) -> None:
        ps = config.policy_sync
        self._enabled = bool(ps.operational_mode_enabled)
        self._mode_path = Path(ps.operational_mode_path)
        self._stamp_path = Path(ps.operational_mode_stamp_path)
        self._session_path = Path(ps.learning_session_path)
        self._sensor_id = config.sensor.id

    @property
    def enabled(self) -> bool:
        return self._enabled

    def ensure_defaults(self) -> bool:
        if not self._enabled:
            return False
        if self._mode_path.is_file():
            return False
        payload = {
            "schema": SCHEMA_VERSION,
            "schema_version": SCHEMA_VERSION,
            "sensor_id": self._sensor_id,
            "mode": "listen",
            "session_id": None,
            "baseline_profile_id": None,
            "updated_at": _utc_now(),
            "source": "edge_default",
        }
        self._mode_path.parent.mkdir(parents=True, exist_ok=True)
        self._mode_path.write_text(
            json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        write_stamp(self._stamp_path, version="listen-default")
        logger.info("Operational mode default artifact written mode=listen")
        return True

    def read_state(self) -> dict[str, Any]:
        if not self._mode_path.is_file():
            return {}
        try:
            raw = json.loads(self._mode_path.read_text(encoding="utf-8"))
            return raw if isinstance(raw, dict) else {}
        except (json.JSONDecodeError, OSError):
            return {}

    def apply_artifact(
        self,
        artifact: dict[str, Any],
        *,
        tenant_id: str,
        source: str = "mqtt",
    ) -> OperationalModeResult:
        if not self._enabled:
            return OperationalModeResult(ok=True, changed=False, error="operational_mode_disabled")

        if not isinstance(artifact, dict):
            return OperationalModeResult(ok=False, changed=False, error="payload is not an object")

        sensor_id = str(artifact.get("sensor_id") or "").strip()
        if sensor_id and sensor_id != self._sensor_id:
            return OperationalModeResult(
                ok=False,
                changed=False,
                error=f"sensor_id mismatch: expected {self._sensor_id}",
            )

        mode = str(artifact.get("mode") or "").strip().lower()
        if mode not in VALID_MODES:
            return OperationalModeResult(ok=False, changed=False, error=f"invalid mode: {mode!r}")

        session_id = artifact.get("session_id")
        session_id_str = str(session_id).strip() if session_id else ""
        abort_session_id = str(artifact.get("abort_session_id") or "").strip()

        existing = self.read_state()
        version = str(artifact.get("version") or artifact.get("updated_at") or _utc_now())
        if (
            existing
            and str(existing.get("mode") or "") == mode
            and str(existing.get("session_id") or "") == session_id_str
            and str(existing.get("tenant_id") or "") == tenant_id
            and str(existing.get("version") or existing.get("updated_at") or "") == version
            and not abort_session_id
        ):
            return OperationalModeResult(
                ok=True,
                changed=False,
                mode=mode,
                session_id=session_id_str,
                tenant_id=tenant_id,
            )

        capture = artifact.get("capture")
        capture_block: dict[str, Any] = {}
        if isinstance(capture, dict):
            capture_block = {
                "interface": str(capture.get("interface") or "").strip(),
                "bpf_filter": str(capture.get("bpf_filter") or "").strip(),
            }

        payload: dict[str, Any] = {
            "schema": str(artifact.get("schema") or SCHEMA_VERSION),
            "schema_version": str(artifact.get("schema_version") or SCHEMA_VERSION),
            "tenant_id": tenant_id,
            "sensor_id": self._sensor_id,
            "site_id": str(artifact.get("site_id") or existing.get("site_id") or "").strip(),
            "mode": mode,
            "session_id": session_id_str or None,
            "baseline_profile_id": artifact.get("baseline_profile_id")
            or existing.get("baseline_profile_id"),
            "baseline_profile_version": artifact.get("baseline_profile_version")
            or existing.get("baseline_profile_version"),
            "capture": capture_block or existing.get("capture") or {},
            "version": version,
            "updated_at": _utc_now(),
            "source": source,
        }

        self._mode_path.parent.mkdir(parents=True, exist_ok=True)
        self._mode_path.write_text(
            json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        write_stamp(self._stamp_path, version=version)

        if abort_session_id:
            self._clear_session(abort_session_id)
        elif mode in ("listen", "learning") and session_id_str:
            self._write_session(
                session_id=session_id_str,
                mode=mode,
                tenant_id=tenant_id,
                capture=capture_block,
            )
        elif mode in ("detect", "idle"):
            self._clear_session()

        logger.info(
            "Operational mode applied via %s tenant=%s mode=%s session=%s",
            source,
            tenant_id,
            mode,
            session_id_str or "-",
        )
        return OperationalModeResult(
            ok=True,
            changed=True,
            mode=mode,
            session_id=session_id_str,
            tenant_id=tenant_id,
        )

    def _write_session(
        self,
        *,
        session_id: str,
        mode: str,
        tenant_id: str,
        capture: dict[str, Any],
    ) -> None:
        session_kind = _session_kind(mode)
        payload = {
            "schema": "sensel.learning_session.v1",
            "session_id": session_id,
            "session_kind": session_kind,
            "operational_mode": mode,
            "tenant_id": tenant_id,
            "sensor_id": self._sensor_id,
            "status": "active",
            "capture_interface": capture.get("interface") or "",
            "bpf_filter": capture.get("bpf_filter") or "",
            "updated_at": _utc_now(),
        }
        self._session_path.parent.mkdir(parents=True, exist_ok=True)
        self._session_path.write_text(
            json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )

    def _clear_session(self, abort_session_id: str = "") -> None:
        if not self._session_path.is_file():
            return
        if abort_session_id:
            try:
                raw = json.loads(self._session_path.read_text(encoding="utf-8"))
                if isinstance(raw, dict) and str(raw.get("session_id") or "") != abort_session_id:
                    return
            except (json.JSONDecodeError, OSError):
                pass
        try:
            self._session_path.unlink()
        except OSError:
            logger.debug("learning session file remove skipped", exc_info=True)
