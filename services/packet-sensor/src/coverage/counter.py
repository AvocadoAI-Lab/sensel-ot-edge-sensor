"""Edge coverage counter — per-rule / per-ATT&CK raw detection tally.

Counts every emitted ``SecurityEvent`` at the edge (the single ``_emit`` point
in ``PacketPipeline``) BEFORE any Control-Plane episode aggregation, so BAS
coverage scoring keeps the true detection volume that Layer A/B would otherwise
collapse (e.g. ~198 OT-005 bursts → a handful of DB rows).

Counters are in-memory and periodically flushed to
``{assets_dir}/coverage-counters.json`` (atomic write) so edge-console can serve
them via ``/api/coverage`` and sensel-edge-agent can publish them northbound.
"""

from __future__ import annotations

import json
import logging
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from src.coverage.mitre_map import techniques_for

logger = logging.getLogger(__name__)

COVERAGE_FILENAME = "coverage-counters.json"
SCHEMA = "ot-edge.coverage.v1"


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


class CoverageCounter:
    """In-memory per-rule / per-technique tally with atomic JSON flush."""

    def __init__(
        self,
        assets_dir: str,
        sensor_id: str = "",
        site_id: str = "",
        enabled: bool = True,
    ) -> None:
        self._path = Path(assets_dir) / COVERAGE_FILENAME
        self._sensor_id = sensor_id
        self._site_id = site_id
        self._enabled = enabled
        self._since = _utc_now_iso()
        self._total = 0
        self._rules: dict[str, dict] = {}
        self._techniques: dict[str, dict] = {}
        self._dirty = False

    @property
    def enabled(self) -> bool:
        return self._enabled

    @property
    def path(self) -> Path:
        return self._path

    def record(self, event) -> None:
        """Increment counters for a single emitted security event (O(1))."""
        if not self._enabled:
            return
        rule_id = str(getattr(event, "rule_id", "") or "")
        if not rule_id:
            return
        now = str(getattr(event, "timestamp", "") or "") or _utc_now_iso()
        severity = str(getattr(event, "severity", "") or "")
        event_type = str(getattr(event, "event_type", "") or "")
        description = str(getattr(event, "description", "") or "")

        self._total += 1
        rule = self._rules.get(rule_id)
        if rule is None:
            self._rules[rule_id] = {
                "count": 1,
                "severity": severity,
                "first_seen": now,
                "last_seen": now,
            }
        else:
            rule["count"] += 1
            rule["last_seen"] = now
            if severity:
                rule["severity"] = severity

        for tech in techniques_for(rule_id, event_type, description):
            tid = str(tech.get("id") or "")
            if not tid:
                continue
            entry = self._techniques.get(tid)
            if entry is None:
                self._techniques[tid] = {
                    "count": 1,
                    "name": tech.get("technique", ""),
                    "tactic": tech.get("tactic", ""),
                    "rules": [rule_id],
                    "first_seen": now,
                    "last_seen": now,
                }
            else:
                entry["count"] += 1
                entry["last_seen"] = now
                if rule_id not in entry["rules"]:
                    entry["rules"].append(rule_id)

        self._dirty = True

    def snapshot(self) -> dict:
        """Return the current coverage tally as a JSON-serializable dict."""
        return {
            "schema": SCHEMA,
            "sensor_id": self._sensor_id,
            "site_id": self._site_id,
            "since": self._since,
            "generated_at": _utc_now_iso(),
            "totals": {
                "events": self._total,
                "rules_hit": len(self._rules),
                "techniques_hit": len(self._techniques),
            },
            "rules": {k: dict(v) for k, v in sorted(self._rules.items())},
            "techniques": {k: dict(v) for k, v in sorted(self._techniques.items())},
        }

    def flush(self, force: bool = False) -> bool:
        """Atomically write the snapshot to disk. No-op when clean (unless forced)."""
        if not self._enabled:
            return False
        if not force and not self._dirty:
            return False
        tmp_path = ""
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            payload = json.dumps(self.snapshot(), ensure_ascii=False, indent=2)
            fd, tmp_path = tempfile.mkstemp(
                dir=str(self._path.parent), prefix=".coverage-", suffix=".tmp"
            )
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                handle.write(payload)
            os.replace(tmp_path, self._path)
            tmp_path = ""
            self._dirty = False
            return True
        except Exception:
            logger.debug("coverage flush failed", exc_info=True)
            if tmp_path and os.path.exists(tmp_path):
                try:
                    os.unlink(tmp_path)
                except OSError:
                    pass
            return False
