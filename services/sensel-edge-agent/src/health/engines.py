"""Probe external IDS engines (Snort / Suricata): liveness + rule metadata.

The edge-agent cannot see the IDS processes directly (they run in separate
sidecar containers), so engine *liveness* is inferred from the bridge output
files the agent already tails (``snort-events.jsonl`` / ``suricata-events.jsonl``).

Engine *rule* metadata (version, how many rules are enabled, the enabled SIDs,
and when the rule file was last updated) is read from the rule files mounted
read-only into the agent at ``/app/config`` (host ``./config``). This lets the
Edge Console answer, for field operators:

  * which IDS engine is currently running,
  * which rule package version it is using,
  * which rules are enabled, and
  * when the rules were last updated.
"""

from __future__ import annotations

import os
import re
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from src.config.settings import AppConfig

# If an engine's event file has not been touched within this many seconds we
# report the engine as "stale" rather than "running".
_STALE_AFTER_SEC = 300

# Snort/Suricata rule actions that begin a rule line (lowercased).
_RULE_ACTIONS = (
    "alert",
    "drop",
    "reject",
    "rejectsrc",
    "rejectdst",
    "rejectboth",
    "sdrop",
    "pass",
    "log",
)

_SID_RE = re.compile(r"\bsid\s*:\s*(\d+)")
_MSG_RE = re.compile(r'\bmsg\s*:\s*"([^"]*)"')

# Cap how many enabled rules we enumerate so the runtime snapshot stays small.
_MAX_RULES_LISTED = 50


def _utc_iso(epoch: float) -> str:
    return (
        datetime.fromtimestamp(epoch, tz=timezone.utc).replace(microsecond=0).isoformat()
    )


def _env_truthy(name: str) -> Optional[bool]:
    """Return True/False if the env var is set, else None (unknown)."""
    raw = os.environ.get(name)
    if raw is None:
        return None
    return raw.strip().lower() in ("1", "true", "yes", "on")


def _probe_rules(path: Path) -> dict[str, Any]:
    """Parse a Snort/Suricata rules file for enabled rule count + SIDs + mtime."""
    info: dict[str, Any] = {
        "path": str(path),
        "present": False,
        "enabled_count": 0,
        "rules": [],
        "last_update": None,
    }
    try:
        if not path.is_file():
            return info
        info["present"] = True
        info["last_update"] = _utc_iso(path.stat().st_mtime)
        enabled = 0
        listed: list[dict[str, Any]] = []
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            head = stripped.split(None, 1)[0].lower()
            if head not in _RULE_ACTIONS:
                continue
            enabled += 1
            if len(listed) < _MAX_RULES_LISTED:
                sid_match = _SID_RE.search(stripped)
                msg_match = _MSG_RE.search(stripped)
                listed.append(
                    {
                        "sid": sid_match.group(1) if sid_match else None,
                        "msg": msg_match.group(1) if msg_match else None,
                    }
                )
        info["enabled_count"] = enabled
        info["rules"] = listed
    except OSError:
        # Unreadable rule file — keep the best-effort defaults.
        pass
    return info


def _probe_one_engine(
    *,
    name: str,
    watch_path: str,
    rules_path: str,
    version_env: str,
    enabled_env: str,
) -> dict[str, Any]:
    status = "absent"
    last_event_age_sec: Optional[float] = None
    try:
        path = Path(watch_path)
        if path.is_file():
            age = time.time() - path.stat().st_mtime
            last_event_age_sec = round(age, 1)
            status = "running" if age <= _STALE_AFTER_SEC else "stale"
    except OSError:
        status = "unknown"

    rules = _probe_rules(Path(rules_path))

    # "configured" prefers the explicit bridge flag (if propagated to the agent),
    # falling back to "has the engine ever produced events?".
    configured_flag = _env_truthy(enabled_env)
    if configured_flag is None:
        configured = status in ("running", "stale")
    else:
        configured = configured_flag

    return {
        "name": name,
        "configured": configured,
        "status": status,
        "active": status in ("running", "stale"),
        "rule_version": os.environ.get(version_env, "").strip() or "unknown",
        "rules_enabled_count": rules["enabled_count"],
        "rules": rules["rules"],
        "rules_last_update": rules["last_update"],
        "rules_path": rules["path"],
        "last_event_age_sec": last_event_age_sec,
    }


def probe_engines(config: AppConfig) -> list[dict[str, Any]]:
    """Probe all supported external IDS engines and return their status."""
    events = config.sensel.events
    specs = (
        {
            "name": "snort",
            "watch_path": events.snort_watch_path,
            "rules_path": os.environ.get(
                "SNORT_RULES_PATH", "/app/config/snort/rules/local.rules"
            ),
            "version_env": "SNORT_RULE_VERSION",
            "enabled_env": "SNORT_SOURCE_ENABLED",
        },
        {
            "name": "suricata",
            "watch_path": events.suricata_watch_path,
            "rules_path": os.environ.get(
                "SURICATA_RULES_PATH", "/app/config/suricata/rules/local.rules"
            ),
            "version_env": "SURICATA_RULE_VERSION",
            "enabled_env": "SURICATA_SOURCE_ENABLED",
        },
    )
    return [_probe_one_engine(**spec) for spec in specs]


def engines_runtime_summary(engines: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Compact projection of ``probe_engines`` for the agent runtime snapshot.

    Drops the per-rule list (kept only in the full DMS health payload) so the
    shared ``agent-runtime.json`` the Edge Console reads stays small.
    """
    summary: list[dict[str, Any]] = []
    for eng in engines:
        summary.append(
            {
                "name": eng.get("name"),
                "configured": eng.get("configured"),
                "status": eng.get("status"),
                "active": eng.get("active"),
                "rule_version": eng.get("rule_version"),
                "rules_enabled_count": eng.get("rules_enabled_count"),
                "rules_last_update": eng.get("rules_last_update"),
                "last_event_age_sec": eng.get("last_event_age_sec"),
            }
        )
    return summary
