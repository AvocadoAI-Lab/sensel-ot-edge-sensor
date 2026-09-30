"""Pull signed Snort/Suricata rule bundles from the Control Plane and apply them
on the edge with reload health-check + automatic rollback (PRD D4 stage 2).

Flow per engine:
  1. HTTP GET ``/api/v1/feed/{tenant}/ot-rules.rules?engine={engine}`` (X-API-Key,
     If-None-Match → 304 short-circuit).
  2. HMAC-verify ``X-Signature`` over the exact response bytes.
  3. Back up the current rule file, atomically write the new bundle.
  4. Run the optional reload + health-check commands.
  5. On failure, restore the backup, re-run reload (best-effort) and report a
     rollback so the engine keeps serving the last-known-good ruleset.

A per-engine status file records the active version + last apply outcome so the
Edge Console / engine health can surface rule freshness and rollbacks.
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Optional

import httpx

from src.config.settings import AppConfig
from src.policy.feed_signing import sha256_hex, verify_artifact
from src.policy.policy_ack import ids_rule_ack_payload

logger = logging.getLogger(__name__)

SUPPORTED_ENGINES = ("suricata", "snort")
_HEALTHCHECK_REQUIRED_MSG = (
    "IDS_RULE_HEALTHCHECK_CMD is required when ids_rule_enabled "
    "(e.g. suricata -T -S {path})"
)


@dataclass(frozen=True)
class IdsRuleResult:
    ok: bool
    changed: bool
    engine: str
    status_code: int = 0
    version: str = ""
    rule_count: int = 0
    rolled_back: bool = False
    tenant_id: str = ""
    error: str | None = None


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _count_rules(text: str) -> int:
    count = 0
    for line in text.splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        count += 1
    return count


def _version_sort_key(version: str) -> tuple:
    """Normalize OT artifact versions for monotonic compare (G12).

    Supports CP ``%Y.%m.%d.%H%M%S.%f`` labels and simple ``vN`` test versions.
    """
    v = (version or "").strip()
    if not v:
        return (0,)
    if v.lower().startswith("v") and len(v) > 1 and v[1].isdigit():
        v = v[1:]
    key: list[int | str] = []
    for part in v.split("."):
        try:
            key.append(int(part))
        except ValueError:
            key.append(part)
    return tuple(key) if key else (0,)


def _version_is_newer(incoming: str, active: str) -> bool:
    """True when ``incoming`` is strictly newer than ``active``."""
    if not (active or "").strip():
        return True
    if not (incoming or "").strip():
        return False
    return _version_sort_key(incoming) > _version_sort_key(active)


class IdsRuleSync:
    """HTTP pull + signed apply for OT custom rule bundles (per engine)."""

    def __init__(
        self,
        config: AppConfig,
        ack_callback: Optional[Callable[[dict[str, Any]], None]] = None,
    ) -> None:
        ps = config.policy_sync
        self._config = config
        self._ack_callback = ack_callback
        self._base = config.sensel.api_url.rstrip("/")
        self._enabled = bool(ps.ids_rule_enabled)
        self._engines = tuple(
            e.strip().lower()
            for e in (ps.ids_rule_engines or [])
            if e.strip().lower() in SUPPORTED_ENGINES
        ) or ("suricata",)
        self._feed_template = ps.ids_rule_feed_path_template
        self._feed_profile = (ps.ids_rule_feed_profile or "ot_ids").strip().lower()
        self._target_dir = Path(ps.ids_rule_target_dir)
        self._status_path = Path(ps.ids_rule_status_path)
        self._signing_secret = (ps.ids_rule_signing_secret or config.sensel.api_key or "").strip()
        self._reload_cmd = (ps.ids_rule_reload_cmd or "").strip()
        self._healthcheck_cmd = (ps.ids_rule_healthcheck_cmd or "").strip()
        self._cmd_timeout = max(int(ps.ids_rule_cmd_timeout_sec or 30), 1)

    @property
    def enabled(self) -> bool:
        return self._enabled

    @property
    def engines(self) -> tuple[str, ...]:
        return self._engines

    def _emit_ack(self, result: "IdsRuleResult") -> None:
        if self._ack_callback is None:
            return
        try:
            self._ack_callback(ids_rule_ack_payload(result))
        except Exception:  # noqa: BLE001 - ACK reporting must never break apply
            logger.debug("IDS rule ACK callback failed", exc_info=True)

    # ---- tenant + url -----------------------------------------------------
    def _resolve_tenant_id(self) -> str | None:
        override = (self._config.policy_sync.feed_tenant_id or "").strip()
        if override:
            return override
        tenant = (self._config.northbound_mqtt.tenant_id or "").strip()
        if tenant and tenant != "default":
            return tenant
        if self._config.northbound_mqtt.require_tenant:
            return None
        return tenant or None

    def _feed_url(self, tenant_id: str, engine: str) -> str:
        path = self._feed_template.format(tenant_id=tenant_id)
        if not path.startswith("/"):
            path = f"/{path}"
        sep = "&" if "?" in path else "?"
        url = f"{self._base}{path}{sep}engine={engine}"
        profile = (self._feed_profile or "ot_ids").strip().lower()
        if profile in ("it_ndr", "ot_ids") and "profile=" not in url:
            url = f"{url}&profile={profile}"
        return url

    def _target_path(self, engine: str) -> Path:
        return self._target_dir / f"{engine}.rules"

    # ---- status -----------------------------------------------------------
    def _read_status(self) -> dict[str, Any]:
        if not self._status_path.is_file():
            return {}
        try:
            raw = json.loads(self._status_path.read_text(encoding="utf-8"))
            return raw if isinstance(raw, dict) else {}
        except (OSError, json.JSONDecodeError):
            return {}

    def _write_status(self, engine: str, entry: dict[str, Any]) -> None:
        status = self._read_status()
        engines = status.get("engines")
        if not isinstance(engines, dict):
            engines = {}
        engines[engine] = entry
        status["engines"] = engines
        status["updated_at"] = _utc_now()
        self._status_path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self._status_path.with_suffix(self._status_path.suffix + ".tmp")
        tmp.write_text(json.dumps(status, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        try:
            os.chmod(tmp, 0o600)
        except OSError:
            pass
        tmp.replace(self._status_path)

    def _current_version(self, engine: str) -> str:
        return str((self._read_status().get("engines", {}).get(engine) or {}).get("version") or "")

    def _current_etag(self, engine: str) -> str:
        return str((self._read_status().get("engines", {}).get(engine) or {}).get("etag") or "")

    # ---- command runner ---------------------------------------------------
    def _healthcheck_required_error(self) -> str | None:
        if self._enabled and not self._healthcheck_cmd:
            return _HEALTHCHECK_REQUIRED_MSG
        return None

    def _run_cmd(self, cmd: str, *, engine: str, required: bool = False) -> tuple[bool, str]:
        if not cmd:
            if required:
                return False, _HEALTHCHECK_REQUIRED_MSG
            return True, ""
        rendered = cmd.format(engine=engine, path=str(self._target_path(engine)))
        try:
            proc = subprocess.run(
                rendered,
                shell=True,
                capture_output=True,
                text=True,
                timeout=self._cmd_timeout,
            )
        except subprocess.TimeoutExpired:
            return False, f"timeout after {self._cmd_timeout}s"
        except OSError as exc:
            return False, str(exc)
        if proc.returncode != 0:
            detail = (proc.stderr or proc.stdout or "").strip()[:300]
            return False, detail or f"exit {proc.returncode}"
        return True, ""

    # ---- pull -------------------------------------------------------------
    def pull_http_feed(self, engine: str, *, force: bool = False) -> IdsRuleResult:
        engine = engine.strip().lower()
        if not self._enabled:
            return IdsRuleResult(ok=True, changed=False, engine=engine, error="ids_rule_disabled")
        if engine not in SUPPORTED_ENGINES:
            return IdsRuleResult(ok=False, changed=False, engine=engine, error=f"unsupported engine: {engine}")

        tenant_id = self._resolve_tenant_id()
        if not tenant_id:
            msg = "tenant_id unresolved (set POLICY_SYNC_TENANT_ID or register sensor)"
            logger.warning("IDS rule sync skipped: %s", msg)
            return IdsRuleResult(ok=False, changed=False, engine=engine, error=msg)

        headers = {"Accept": "text/plain"}
        intel_key = (self._config.policy_sync.smb_intel_api_key or "").strip()
        if intel_key:
            headers["X-API-Key"] = intel_key
        etag = self._current_etag(engine)
        if etag and not force:
            headers["If-None-Match"] = f'"{etag}"'

        url = self._feed_url(tenant_id, engine)
        try:
            with httpx.Client(timeout=30.0, verify=self._config.sensel.verify_tls) as client:
                response = client.get(url, headers=headers)
        except httpx.HTTPError as exc:
            logger.warning("IDS rule sync HTTP error engine=%s: %s", engine, exc)
            return IdsRuleResult(ok=False, changed=False, engine=engine, tenant_id=tenant_id, error=str(exc))

        if response.status_code == 304:
            return IdsRuleResult(
                ok=True, changed=False, engine=engine, status_code=304,
                tenant_id=tenant_id, version=self._current_version(engine),
            )
        if response.status_code == 404:
            return IdsRuleResult(
                ok=True, changed=False, engine=engine, status_code=404,
                tenant_id=tenant_id, error="no active rule bundle",
            )
        if response.status_code >= 400:
            detail = response.text[:300]
            logger.warning("IDS rule sync failed engine=%s (%s): %s", engine, response.status_code, detail)
            return IdsRuleResult(
                ok=False, changed=False, engine=engine, status_code=response.status_code,
                tenant_id=tenant_id, error=detail or f"HTTP {response.status_code}",
            )

        body = response.content
        signature = response.headers.get("X-Signature") or ""
        if not verify_artifact(body, signature, tenant_id=tenant_id, base_secret=self._signing_secret):
            logger.error("IDS rule sync signature verification failed engine=%s tenant=%s", engine, tenant_id)
            result = IdsRuleResult(
                ok=False, changed=False, engine=engine, status_code=response.status_code,
                tenant_id=tenant_id, error="signature verification failed",
            )
            self._emit_ack(result)
            return result

        version = (response.headers.get("X-Artifact-Version") or "").strip()
        new_etag = (response.headers.get("etag") or "").strip().strip('"') or sha256_hex(body)
        return self.apply_artifact(
            body.decode("utf-8", errors="replace"),
            engine=engine,
            tenant_id=tenant_id,
            version=version,
            etag=new_etag,
            status_code=response.status_code,
        )

    # ---- apply + reload + rollback ----------------------------------------
    def apply_artifact(
        self,
        content: str,
        *,
        engine: str,
        tenant_id: str,
        version: str = "",
        etag: str = "",
        status_code: int = 200,
    ) -> IdsRuleResult:
        engine = engine.strip().lower()
        resolved_etag = etag or sha256_hex(content.encode("utf-8"))
        version = version or resolved_etag[:12]

        current = self._read_status().get("engines", {}).get(engine) or {}
        if (
            str(current.get("etag") or "") == resolved_etag
            and str(current.get("version") or "") == version
            and current.get("ok")
        ):
            return IdsRuleResult(
                ok=True, changed=False, engine=engine, status_code=status_code,
                tenant_id=tenant_id, version=version, rule_count=int(current.get("rule_count") or 0),
            )

        hc_err = self._healthcheck_required_error()
        if hc_err:
            logger.error("IDS rules apply blocked engine=%s: %s", engine, hc_err)
            result = IdsRuleResult(
                ok=False, changed=False, engine=engine, status_code=status_code,
                tenant_id=tenant_id, version=version, error=hc_err,
            )
            self._emit_ack(result)
            return result

        active_version = str(current.get("version") or "")
        if active_version and _version_sort_key(version) < _version_sort_key(active_version):
            msg = f"stale version rejected: {version} < active {active_version}"
            logger.warning("IDS rules apply blocked engine=%s: %s", engine, msg)
            entry = {
                "engine": engine,
                "tenant_id": tenant_id,
                "version": active_version,
                "etag": current.get("etag") or "",
                "rule_count": int(current.get("rule_count") or 0),
                "ok": bool(current.get("ok")),
                "rolled_back": False,
                "applied_at": _utc_now(),
                "error": msg[:300],
                "rejected_version": version,
            }
            self._write_status(engine, entry)
            result = IdsRuleResult(
                ok=False, changed=False, engine=engine, status_code=status_code,
                tenant_id=tenant_id, version=version, error=msg[:300],
            )
            self._emit_ack(result)
            return result

        target = self._target_path(engine)
        backup = target.with_suffix(target.suffix + ".bak")
        target.parent.mkdir(parents=True, exist_ok=True)
        had_previous = target.is_file()
        if had_previous:
            shutil.copy2(target, backup)

        tmp = target.with_suffix(target.suffix + ".tmp")
        tmp.write_text(content if content.endswith("\n") else content + "\n", encoding="utf-8")
        tmp.replace(target)
        rule_count = _count_rules(content)

        reload_ok, reload_err = self._run_cmd(self._reload_cmd, engine=engine)
        health_ok, health_err = (
            self._run_cmd(self._healthcheck_cmd, engine=engine, required=True)
            if reload_ok
            else (False, "")
        )

        if reload_ok and health_ok:
            entry = {
                "engine": engine, "tenant_id": tenant_id, "version": version,
                "etag": resolved_etag, "rule_count": rule_count, "ok": True,
                "rolled_back": False, "applied_at": _utc_now(), "error": None,
            }
            self._write_status(engine, entry)
            logger.info(
                "IDS rules applied engine=%s tenant=%s version=%s rules=%s",
                engine, tenant_id, version, rule_count,
            )
            result = IdsRuleResult(
                ok=True, changed=True, engine=engine, status_code=status_code,
                tenant_id=tenant_id, version=version, rule_count=rule_count,
            )
            self._emit_ack(result)
            return result

        # Failure → rollback to last-known-good.
        failure = reload_err if not reload_ok else health_err
        rolled_back = False
        if had_previous and backup.is_file():
            shutil.copy2(backup, target)
            self._run_cmd(self._reload_cmd, engine=engine)
            rolled_back = True
        else:
            try:
                target.unlink()
            except OSError:
                pass
        entry = {
            "engine": engine, "tenant_id": tenant_id,
            "version": current.get("version") or "", "etag": current.get("etag") or "",
            "rule_count": int(current.get("rule_count") or 0), "ok": False,
            "rolled_back": rolled_back, "applied_at": _utc_now(),
            "error": f"{'reload' if not reload_ok else 'healthcheck'} failed: {failure}"[:300],
            "rejected_version": version,
        }
        self._write_status(engine, entry)
        logger.error(
            "IDS rules apply failed engine=%s version=%s rolled_back=%s err=%s",
            engine, version, rolled_back, failure,
        )
        result = IdsRuleResult(
            ok=False, changed=False, engine=engine, status_code=status_code,
            tenant_id=tenant_id, version=version, rolled_back=rolled_back,
            error=entry["error"],
        )
        self._emit_ack(result)
        return result

    def sync_all(self, *, force: bool = False) -> list[IdsRuleResult]:
        return [self.pull_http_feed(engine, force=force) for engine in self._engines]
