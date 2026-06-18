"""Suricata EVE JSON -> SenseL ``SecurityEvent`` bridge.

Suricata runs as a sidecar with its own capture and engine; it writes one JSON
object per line (EVE JSON / NDJSON) to ``eve.json``. Many event types are
emitted (flow, dns, tls, http, alert...); for v0.1 we only bridge
``event_type == "alert"`` records. Each alert is mapped to a ``SecurityEvent``
and appended to ``suricata-events.jsonl`` in the shared assets dir, which the
edge-agent tails and uploads north — no changes to the MQTT / buffer / sighting
transport.

Design notes:
- ``rule_id`` uses the ``suricata-{gid}-{signature_id}`` namespace so it never
  collides with the self-built ``OT-xxx`` rules or the ``snort-*`` namespace.
- Suricata uses ``dest_ip`` / ``dest_port`` (note the field names) and reports
  the rule priority via ``alert.severity`` (1 = highest).
- Suricata timestamps are ISO8601 but the tz offset has no colon
  (``+0000``); we normalise to a colon offset, seconds precision.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path

from src.detection.models import SecurityEvent, utc_now_iso

logger = logging.getLogger(__name__)

EVENT_TYPE = "SURICATA_ALERT"
ALERT_RECORD_TYPE = "alert"

# Suricata alert.severity -> SenseL severity. Missing/out-of-range -> "medium".
_SEVERITY_RANK_TO_SEVERITY = {1: "high", 2: "medium", 3: "low"}

# severity -> risk_score, aligned with the Snort bridge / IocMatcher.
_SEVERITY_TO_RISK = {"critical": 95, "high": 85, "medium": 60, "low": 40}


def map_severity(severity_rank) -> str:
    try:
        return _SEVERITY_RANK_TO_SEVERITY.get(int(severity_rank), "medium")
    except (TypeError, ValueError):
        return "medium"


def parse_eve_timestamp(raw: str | None) -> str:
    """Normalize Suricata's ISO8601 timestamp to a colon-offset, seconds ISO8601.

    Suricata emits e.g. ``2026-06-18T10:30:00.123456+0000`` (no colon in tz).
    Falls back to "now" when missing/unparseable.
    """
    if not raw:
        return utc_now_iso()
    text = raw.strip()
    # Insert a colon into a +HHMM / -HHMM offset so fromisoformat accepts it.
    if len(text) >= 5 and text[-5] in "+-" and text[-3] != ":":
        text = f"{text[:-2]}:{text[-2:]}"
    try:
        dt = datetime.fromisoformat(text)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.replace(microsecond=0).isoformat()
    except ValueError:
        return utc_now_iso()


def _coerce_port(value) -> int | None:
    if value in (None, ""):
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


class SuricataEveMapper:
    """Map a single Suricata EVE ``alert`` record to a ``SecurityEvent``."""

    def __init__(self, site_id: str, sensor_id: str) -> None:
        self._site_id = site_id
        self._sensor_id = sensor_id
        self._seq = 0

    def _next_event_id(self) -> str:
        self._seq += 1
        day = datetime.now(timezone.utc).strftime("%Y%m%d")
        return f"evt-{day}-suricata-{self._seq:05d}"

    def map(self, record: dict) -> SecurityEvent | None:
        if str(record.get("event_type") or "") != ALERT_RECORD_TYPE:
            return None
        alert = record.get("alert") if isinstance(record.get("alert"), dict) else {}
        severity = map_severity(alert.get("severity"))
        gid = alert.get("gid", 1)
        signature_id = alert.get("signature_id", 0)
        proto = str(record.get("proto") or "ip").lower()
        app_proto = record.get("app_proto")

        return SecurityEvent(
            event_id=self._next_event_id(),
            site_id=self._site_id,
            sensor_id=self._sensor_id,
            event_type=EVENT_TYPE,
            severity=severity,
            rule_id=f"suricata-{gid}-{signature_id}",
            protocol=proto,
            description=str(alert.get("signature") or "Suricata alert"),
            src_ip=str(record.get("src_ip") or ""),
            dst_ip=str(record.get("dest_ip") or ""),
            dst_port=_coerce_port(record.get("dest_port")),
            risk_score=_SEVERITY_TO_RISK[severity],
            evidence={
                "engine": "suricata",
                "sid": signature_id,
                "gid": gid,
                "rev": alert.get("rev"),
                "severity": alert.get("severity"),
                "category": alert.get("category"),
                "action": alert.get("action"),
                "app_proto": app_proto,
                "flow_id": record.get("flow_id"),
                "src_port": record.get("src_port"),
                "raw_event": record,
            },
            timestamp=parse_eve_timestamp(record.get("timestamp")),
        )


class SuricataEveSource:
    """Tail Suricata ``eve.json`` and append mapped alerts to ``suricata-events.jsonl``."""

    OUTPUT_FILENAME = "suricata-events.jsonl"

    def __init__(
        self,
        eve_json_path: str,
        output_dir: str,
        offset_path: str,
        site_id: str,
        sensor_id: str,
    ) -> None:
        self._src = Path(eve_json_path)
        self._out = Path(output_dir) / self.OUTPUT_FILENAME
        self._offset_path = Path(offset_path)
        self._out.parent.mkdir(parents=True, exist_ok=True)
        self._offset_path.parent.mkdir(parents=True, exist_ok=True)
        self._offset = self._load_offset()
        self._mapper = SuricataEveMapper(site_id, sensor_id)

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
        """Read new complete lines, map alert records, append events. Returns count written."""
        if not self._src.is_file():
            return 0
        data = self._src.read_bytes()
        # eve.json rotation/truncation guard (same as the Snort bridge).
        if self._offset > len(data):
            self._offset = 0
        chunk = data[self._offset :]
        if not chunk:
            return 0

        ends_with_newline = data.endswith(b"\n")
        lines = chunk.splitlines()
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
                record = json.loads(text)
            except json.JSONDecodeError:
                logger.warning("Skipping malformed Suricata EVE line")
                continue
            event = self._mapper.map(record)
            if event is None:  # non-alert EVE record (flow/dns/tls/...) — skipped in v0.1
                continue
            events.append(json.dumps(event.to_dict(), ensure_ascii=False))
            written += 1

        if events:
            with self._out.open("a", encoding="utf-8") as handle:
                handle.write("\n".join(events) + "\n")

        self._offset += consumed
        self._save_offset()
        return written
