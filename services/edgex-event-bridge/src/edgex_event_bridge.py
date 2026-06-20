from __future__ import annotations

import json
import logging
import os
import signal
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.error import URLError
from urllib.request import Request, urlopen


LOG_LEVEL = os.getenv("LOG_LEVEL", "info").upper()
logging.basicConfig(
    level=getattr(logging, LOG_LEVEL, logging.INFO),
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
LOGGER = logging.getLogger("edgex-event-bridge")

_STOP = False


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _origin_to_iso(value: Any) -> str:
    try:
        origin = int(value)
    except (TypeError, ValueError):
        return _utc_now_iso()
    if origin <= 0:
        return _utc_now_iso()
    if origin > 1_000_000_000_000_000:
        origin = origin / 1_000_000_000.0
    elif origin > 1_000_000_000_000:
        origin = origin / 1_000.0
    return datetime.fromtimestamp(float(origin), tz=timezone.utc).replace(microsecond=0).isoformat()


def _event_identifier(event: dict[str, Any]) -> str:
    raw = str(event.get("id") or event.get("eventId") or "").strip()
    if raw:
        return raw
    device = str(event.get("deviceName") or "unknown-device")
    origin = str(event.get("origin") or event.get("created") or time.time_ns())
    return f"{device}-{origin}"


OT_EVIDENCE_SCHEMA_VERSION = "ot_evidence.normalized.v1"


def _first_reading(readings: list[dict[str, Any]]) -> dict[str, Any]:
    for item in readings:
        if isinstance(item, dict):
            return item
    return {}


def _protocol_from_event(event: dict[str, Any], readings: list[dict[str, Any]]) -> str:
    candidates = [
        event.get("protocol"),
        event.get("protocolName"),
        event.get("profileName"),
        event.get("profile_name"),
        *(
            item.get("profileName") or item.get("profile_name")
            for item in readings
            if isinstance(item, dict)
        ),
    ]
    text = " ".join(str(value or "").lower() for value in candidates)
    if "modbus" in text:
        return "modbus-tcp"
    if "opcua" in text or "opc-ua" in text:
        return "opcua"
    if "mqtt" in text:
        return "mqtt"
    if "iec61850" in text or "iec-61850" in text:
        return "iec61850"
    return "edgex"


def build_ot_evidence(
    event: dict[str, Any],
    *,
    site_id: str,
    sensor_id: str,
    source_host: str,
    tenant_id: str = "default",
    workspace_id: str = "",
    purdue_level: str = "L1",
) -> dict[str, Any]:
    """Map an EdgeX Core Data event to the normalized OT evidence contract (PRD 6.2).

    Carries the canonical correlation fields (``device_id``/``source_name``/
    ``reading_name``/``value``/``unit``/``target_ip``/``purdue_level``) plus a few
    legacy aliases (``asset_id``/``src_ip``) so the existing edge-agent tailer and
    Edge Console keep working unchanged.
    """
    event_id = _event_identifier(event)
    readings = [item for item in (event.get("readings") or []) if isinstance(item, dict)]
    device_name = str(event.get("deviceName") or event.get("device_name") or "edgex-device")
    profile_name = str(event.get("profileName") or event.get("profile_name") or "")
    timestamp = _origin_to_iso(event.get("origin") or event.get("created"))

    primary = _first_reading(readings)
    reading_name = str(primary.get("resourceName") or primary.get("resource_name") or "") or None
    source_name = (
        str(event.get("sourceName") or event.get("source_name") or "")
        or reading_name
        or None
    )
    value = primary.get("value")
    unit = primary.get("units") or primary.get("unit") or None

    reading_names = [
        str(item.get("resourceName") or item.get("resource_name") or "")
        for item in readings
    ]
    reading_label = ", ".join([name for name in reading_names if name]) or "EdgeX reading"
    protocol = _protocol_from_event(event, readings)

    return {
        "schema_version": OT_EVIDENCE_SCHEMA_VERSION,
        "event_id": f"edgex-{event_id}",
        "tenant_id": tenant_id,
        "workspace_id": workspace_id or tenant_id,
        "site_id": site_id,
        "sensor_id": sensor_id,
        "device_id": device_name,
        "source_name": source_name,
        "reading_name": reading_name,
        "value": value,
        "unit": unit,
        "event_type": "OT_READING_OBSERVED",
        "protocol": protocol,
        "target_ip": source_host or None,
        "purdue_level": purdue_level or None,
        "severity": "medium",
        "risk_score": 75,
        "observed_at": timestamp,
        "raw_payload": {
            "source": "ubuntu-edgex",
            "source_host": source_host,
            "device_name": device_name,
            "profile_name": profile_name,
            "readings": readings,
            "edgex_event": event,
        },
        # Legacy aliases retained for the edge-agent tailer / Edge Console.
        "rule_id": "OT-EDGEX-001",
        "description": f"EdgeX OT reading observed for {device_name}: {reading_label}",
        "asset_id": device_name,
        "src_ip": source_host,
        "evidence_ref": f"edgex://event/{event_id}",
    }


def build_security_event(
    event: dict[str, Any],
    *,
    site_id: str,
    sensor_id: str,
    source_host: str,
) -> dict[str, Any]:
    """Backward-compatible wrapper; the bridge now emits OT evidence directly."""
    return build_ot_evidence(
        event,
        site_id=site_id,
        sensor_id=sensor_id,
        source_host=source_host,
        tenant_id=os.getenv("MQTT_TENANT_ID", os.getenv("TENANT_ID", "default")).strip() or "default",
        workspace_id=os.getenv("WORKSPACE_ID", "").strip(),
        purdue_level=os.getenv("EDGEX_PURDUE_LEVEL", "L1").strip() or "L1",
    )


class State:
    def __init__(self, path: Path, *, max_ids: int = 5000) -> None:
        self.path = path
        self.max_ids = max_ids
        self.seen = self._load()

    def _load(self) -> set[str]:
        if not self.path.is_file():
            return set()
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return set()
        if not isinstance(data, list):
            return set()
        return {str(item) for item in data if str(item)}

    def contains(self, event_id: str) -> bool:
        return event_id in self.seen

    def add(self, event_id: str) -> None:
        self.seen.add(event_id)
        values = sorted(self.seen)[-self.max_ids :]
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps(values, ensure_ascii=False, indent=2), encoding="utf-8")


def fetch_edgex_events(base_url: str, *, limit: int = 20) -> list[dict[str, Any]]:
    url = f"{base_url.rstrip('/')}/api/v3/event/all?limit={int(limit)}"
    request = Request(url, headers={"Accept": "application/json"})
    with urlopen(request, timeout=10) as response:
        data = json.loads(response.read().decode("utf-8"))
    events = data.get("events") if isinstance(data, dict) else None
    if isinstance(events, list):
        return [event for event in events if isinstance(event, dict)]
    return []


def append_jsonl(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(payload, ensure_ascii=False) + "\n")


def _handle_signal(signum: int, _frame: Any) -> None:
    global _STOP
    LOGGER.info("received signal %s, stopping", signum)
    _STOP = True


def main() -> int:
    signal.signal(signal.SIGTERM, _handle_signal)
    signal.signal(signal.SIGINT, _handle_signal)

    base_url = os.getenv("EDGEX_CORE_DATA_URL", "http://192.168.80.130:59880").strip()
    source_host = os.getenv("EDGEX_SOURCE_HOST", "192.168.80.130").strip()
    site_id = os.getenv("SITE_ID", "factory-lab-001").strip()
    sensor_id = os.getenv("SENSOR_ID", "ot-edge-001").strip()
    events_path = Path(os.getenv("SECURITY_EVENTS_PATH", "/app/data/assets/security-events.jsonl"))
    state = State(Path(os.getenv("EDGEX_BRIDGE_STATE_PATH", "/app/data/edgex-event-bridge-state.json")))
    poll_interval = max(1.0, float(os.getenv("EDGEX_BRIDGE_POLL_INTERVAL_SEC", "5")))
    limit = max(1, int(os.getenv("EDGEX_BRIDGE_EVENT_LIMIT", "20")))

    LOGGER.info(
        "starting EdgeX event bridge base_url=%s events_path=%s sensor=%s site=%s",
        base_url,
        events_path,
        sensor_id,
        site_id,
    )

    while not _STOP:
        try:
            events = fetch_edgex_events(base_url, limit=limit)
        except (OSError, URLError, json.JSONDecodeError):
            LOGGER.exception("failed to fetch EdgeX events from %s", base_url)
            time.sleep(poll_interval)
            continue

        emitted = 0
        for event in reversed(events):
            event_id = _event_identifier(event)
            if state.contains(event_id):
                continue
            security_event = build_security_event(
                event,
                site_id=site_id,
                sensor_id=sensor_id,
                source_host=source_host,
            )
            append_jsonl(events_path, security_event)
            state.add(event_id)
            emitted += 1
            LOGGER.info("emitted EdgeX security event event_id=%s", security_event["event_id"])
        if emitted == 0:
            LOGGER.debug("no new EdgeX events")
        time.sleep(poll_interval)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
