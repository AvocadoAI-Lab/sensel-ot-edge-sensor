"""Snort 3 ``alert_json`` -> SenseL ``SecurityEvent`` bridge.

Snort 3 runs as a sidecar with its own capture and engine; it writes one JSON
object per line (NDJSON) to a shared file. This module tails that file (offset
based, like the edge-agent ``SecurityEventTailer``), maps each alert to a
``SecurityEvent`` and appends it to ``snort-events.jsonl`` in the shared assets
dir. The edge-agent tails that file and uploads it north, so nothing in the
MQTT / buffer / sighting path needs to change.

Design notes:
- Snort and the scapy packet pipeline write to *separate* JSONL files to avoid
  interleaved writes from two processes on the same file.
- ``rule_id`` uses the ``snort-{gid}-{sid}`` namespace so it never collides with
  the self-built ``OT-xxx`` rules (keeps DMS / coverage stats unambiguous).
- Snort's default ``timestamp`` (``MM/DD-HH:MM:SS.ffffff``) has no year or
  timezone; we assume the current UTC year and UTC tz to satisfy the schema's
  ``date-time`` format.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path

from src.detection.models import SecurityEvent, utc_now_iso

logger = logging.getLogger(__name__)

EVENT_TYPE = "SNORT_ALERT"

# Snort rule priority -> SenseL severity. Missing/out-of-range -> "medium"
# (conservative: prefer noise over silently downgrading to low).
_PRIORITY_TO_SEVERITY = {1: "high", 2: "medium", 3: "low"}

# severity -> risk_score, aligned with IocMatcher (high lands in the >=70 band).
_SEVERITY_TO_RISK = {"critical": 95, "high": 85, "medium": 60, "low": 40}


def map_severity(priority) -> str:
    try:
        return _PRIORITY_TO_SEVERITY.get(int(priority), "medium")
    except (TypeError, ValueError):
        return "medium"


def parse_snort_timestamp(raw: str | None) -> str:
    """Normalize Snort's ``MM/DD-HH:MM:SS.ffffff`` to ISO8601 UTC.

    Falls back to "now" when missing/unparseable. If the value already looks
    like ISO8601 (a custom Snort timestamp format), it is returned unchanged.
    """
    if not raw:
        return utc_now_iso()
    if "T" in raw:
        return raw
    try:
        year = datetime.now(timezone.utc).year
        dt = datetime.strptime(f"{year}/{raw}", "%Y/%m/%d-%H:%M:%S.%f")
        return dt.replace(tzinfo=timezone.utc).replace(microsecond=0).isoformat()
    except ValueError:
        return utc_now_iso()


def _coerce_port(value) -> int | None:
    if value in (None, ""):
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


class SnortAlertMapper:
    """Map a single Snort ``alert_json`` object to a ``SecurityEvent``."""

    def __init__(self, site_id: str, sensor_id: str) -> None:
        self._site_id = site_id
        self._sensor_id = sensor_id
        self._seq = 0

    def _next_event_id(self) -> str:
        self._seq += 1
        day = datetime.now(timezone.utc).strftime("%Y%m%d")
        return f"evt-{day}-snort-{self._seq:05d}"

    def map(self, alert: dict) -> SecurityEvent:
        severity = map_severity(alert.get("priority"))
        gid = alert.get("gid", 1)
        sid = alert.get("sid", 0)
        proto = str(alert.get("proto") or "ip").lower()

        return SecurityEvent(
            event_id=self._next_event_id(),
            site_id=self._site_id,
            sensor_id=self._sensor_id,
            event_type=EVENT_TYPE,
            severity=severity,
            rule_id=f"snort-{gid}-{sid}",
            protocol=proto,
            description=str(alert.get("msg") or "Snort alert"),
            src_ip=str(alert.get("src_addr") or ""),
            dst_ip=str(alert.get("dst_addr") or ""),
            dst_port=_coerce_port(alert.get("dst_port")),
            risk_score=_SEVERITY_TO_RISK[severity],
            evidence={
                "engine": "snort",
                "sid": sid,
                "gid": gid,
                "rev": alert.get("rev"),
                "priority": alert.get("priority"),
                "classtype": alert.get("class"),
                "action": alert.get("action"),
                "service": alert.get("service"),
                "src_port": alert.get("src_port"),
                "iface": alert.get("iface"),
                "snort_pkt_num": alert.get("pkt_num"),
                "raw_event": alert,
            },
            timestamp=parse_snort_timestamp(alert.get("timestamp")),
        )


class SnortAlertSource:
    """Tail Snort ``alert_json`` and append mapped events to ``snort-events.jsonl``."""

    OUTPUT_FILENAME = "snort-events.jsonl"

    def __init__(
        self,
        alert_json_path: str,
        output_dir: str,
        offset_path: str,
        site_id: str,
        sensor_id: str,
    ) -> None:
        self._src = Path(alert_json_path)
        self._out = Path(output_dir) / self.OUTPUT_FILENAME
        self._offset_path = Path(offset_path)
        self._out.parent.mkdir(parents=True, exist_ok=True)
        self._offset_path.parent.mkdir(parents=True, exist_ok=True)
        self._offset = self._load_offset()
        self._mapper = SnortAlertMapper(site_id, sensor_id)

    @property
    def output_path(self) -> Path:
        return self._out

    def _load_offset(self) -> int:
        if not self._offset_path.is_file():
            return 0
        try:
            return int(self._offset_path.read_text(encoding="utf-8").strip() or "0")
        except ValueError:
            return 0

    def _save_offset(self) -> None:
        self._offset_path.write_text(str(self._offset), encoding="utf-8")

    def poll_once(self) -> int:
        """Read new complete lines, map them, append events. Returns count written."""
        if not self._src.is_file():
            return 0
        data = self._src.read_bytes()
        # Snort rotates/truncates the file when ``limit`` is hit; detect shrink
        # and restart from the beginning (same guard as SecurityEventTailer).
        if self._offset > len(data):
            self._offset = 0
        chunk = data[self._offset :]
        if not chunk:
            return 0

        ends_with_newline = data.endswith(b"\n")
        lines = chunk.splitlines()
        # Preserve a trailing partial line until the next poll.
        complete = lines if ends_with_newline else lines[:-1]

        written = 0
        consumed = 0
        events: list[str] = []
        for line in complete:
            consumed += len(line) + 1
            text = line.decode("utf-8", errors="replace").strip()
            if not text:
                continue
            try:
                alert = json.loads(text)
            except json.JSONDecodeError:
                logger.warning("Skipping malformed Snort alert line")
                continue
            event = self._mapper.map(alert)
            events.append(json.dumps(event.to_dict(), ensure_ascii=False))
            written += 1

        if events:
            with self._out.open("a", encoding="utf-8") as handle:
                handle.write("\n".join(events) + "\n")

        self._offset += consumed
        self._save_offset()
        return written
