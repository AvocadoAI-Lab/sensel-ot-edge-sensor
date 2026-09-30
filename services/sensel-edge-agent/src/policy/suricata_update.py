"""Edge-side ``suricata-update`` execution + northbound report (PRD EPIC E / G10).

Disabled by default. When enabled the agent periodically runs ``suricata-update``
(refreshing the community ET ruleset on the device), then runs the configured IDS
reload + health-check commands so the engine picks up the new rules, and reports
the outcome (status / rule_count / version / error) back to the Control Plane so
the distribution log shows what the *edge* actually executed.

This complements the server-side autoupdate (which pushes curated bundles): some
deployments prefer the edge to pull community rules directly with ``suricata-update``.
"""

from __future__ import annotations

import json
import logging
import os
import re
import subprocess
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Optional

from src.config.settings import AppConfig

logger = logging.getLogger(__name__)

_HEALTHCHECK_REQUIRED_MSG = (
    "IDS_RULE_HEALTHCHECK_CMD is required when suricata_update_enabled "
    "(e.g. suricata -T -S /path/to/suricata.rules)"
)

# "<n> rules successfully loaded", "Loaded <n> rules", "Enabled <n> rules", etc.
_RULE_COUNT_RES = (
    re.compile(r"(\d+)\s+rules successfully loaded", re.IGNORECASE),
    re.compile(r"Loaded\s+(\d+)\s+rules", re.IGNORECASE),
    re.compile(r"Enabled\s+(\d+)\s+rules", re.IGNORECASE),
    re.compile(r"total[:\s]+(\d+)", re.IGNORECASE),
)


@dataclass(frozen=True)
class SuricataUpdateResult:
    ok: bool
    engine: str = "suricata"
    version: str = ""
    rule_count: int = 0
    rolled_back: bool = False
    tenant_id: str = ""
    error: Optional[str] = None


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _parse_rule_count(output: str) -> int:
    for rx in _RULE_COUNT_RES:
        m = rx.search(output or "")
        if m:
            try:
                return int(m.group(1))
            except ValueError:
                continue
    return 0


class SuricataUpdateRunner:
    """Run ``suricata-update`` and report the result northbound (G10)."""

    def __init__(
        self,
        config: AppConfig,
        report_callback: Optional[Callable[[SuricataUpdateResult], None]] = None,
    ) -> None:
        ps = config.policy_sync
        self._config = config
        self._report_callback = report_callback
        self._enabled = bool(getattr(ps, "suricata_update_enabled", False))
        self._cmd = (getattr(ps, "suricata_update_cmd", "suricata-update") or "suricata-update").strip()
        self._timeout = max(int(getattr(ps, "suricata_update_cmd_timeout_sec", 300) or 300), 1)
        self._status_path = Path(getattr(ps, "suricata_update_status_path", "/app/data/suricata-update-status.json"))
        self._reload_cmd = (ps.ids_rule_reload_cmd or "").strip()
        self._healthcheck_cmd = (ps.ids_rule_healthcheck_cmd or "").strip()
        self._reload_timeout = max(int(ps.ids_rule_cmd_timeout_sec or 30), 1)

    @property
    def enabled(self) -> bool:
        return self._enabled

    def _resolve_tenant_id(self) -> str:
        override = (self._config.policy_sync.feed_tenant_id or "").strip()
        if override:
            return override
        return (self._config.northbound_mqtt.tenant_id or "").strip()

    def _run(self, cmd: str, timeout: int, *, required: bool = False) -> tuple[bool, str]:
        if not cmd:
            if required:
                return False, _HEALTHCHECK_REQUIRED_MSG
            return True, ""
        try:
            proc = subprocess.run(
                cmd, shell=True, capture_output=True, text=True, timeout=timeout
            )
        except subprocess.TimeoutExpired:
            return False, f"timeout after {timeout}s"
        except OSError as exc:
            return False, str(exc)
        out = f"{proc.stdout or ''}\n{proc.stderr or ''}"
        if proc.returncode != 0:
            return False, (out.strip()[:300] or f"exit {proc.returncode}")
        return True, out

    def _write_status(self, result: SuricataUpdateResult) -> None:
        entry = {
            "engine": result.engine,
            "ok": result.ok,
            "version": result.version,
            "rule_count": result.rule_count,
            "rolled_back": result.rolled_back,
            "error": result.error,
            "ran_at": _utc_now(),
        }
        try:
            self._status_path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self._status_path.with_suffix(self._status_path.suffix + ".tmp")
            tmp.write_text(json.dumps(entry, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
            try:
                os.chmod(tmp, 0o600)
            except OSError:
                pass
            tmp.replace(self._status_path)
        except OSError:
            logger.debug("suricata-update status write failed", exc_info=True)

    def _emit(self, result: SuricataUpdateResult) -> None:
        if self._report_callback is None:
            return
        try:
            self._report_callback(result)
        except Exception:  # noqa: BLE001 - reporting must never break the runner
            logger.debug("suricata-update report callback failed", exc_info=True)

    def run(self) -> SuricataUpdateResult:
        tenant_id = self._resolve_tenant_id()
        if not self._enabled:
            return SuricataUpdateResult(ok=True, tenant_id=tenant_id, error="suricata_update_disabled")

        version = datetime.now(timezone.utc).strftime("suricata-update-%Y%m%d%H%M%S")
        update_ok, update_out = self._run(self._cmd, self._timeout)
        if not update_ok:
            result = SuricataUpdateResult(
                ok=False, tenant_id=tenant_id, version=version,
                error=f"suricata-update failed: {update_out}"[:300],
            )
            self._write_status(result)
            self._emit(result)
            logger.error("suricata-update failed: %s", update_out)
            return result

        rule_count = _parse_rule_count(update_out)

        if not self._healthcheck_cmd:
            result = SuricataUpdateResult(
                ok=False, tenant_id=tenant_id, version=version, rule_count=rule_count,
                error=_HEALTHCHECK_REQUIRED_MSG,
            )
            self._write_status(result)
            self._emit(result)
            logger.error("suricata-update blocked: %s", _HEALTHCHECK_REQUIRED_MSG)
            return result

        reload_ok, reload_err = self._run(self._reload_cmd, self._reload_timeout)
        health_ok, health_err = (
            self._run(self._healthcheck_cmd, self._reload_timeout, required=True)
            if reload_ok
            else (False, "")
        )
        if reload_ok and health_ok:
            result = SuricataUpdateResult(
                ok=True, tenant_id=tenant_id, version=version, rule_count=rule_count,
            )
            self._write_status(result)
            self._emit(result)
            logger.info("suricata-update applied rules=%s version=%s", rule_count, version)
            return result

        failure = reload_err if not reload_ok else health_err
        result = SuricataUpdateResult(
            ok=False, tenant_id=tenant_id, version=version, rule_count=rule_count,
            error=f"{'reload' if not reload_ok else 'healthcheck'} failed: {failure}"[:300],
        )
        self._write_status(result)
        self._emit(result)
        logger.error("suricata-update reload/health failed: %s", failure)
        return result
