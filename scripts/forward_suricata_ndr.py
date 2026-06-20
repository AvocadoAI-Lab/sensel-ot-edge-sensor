#!/usr/bin/env python3
"""Tail real Suricata EVE alerts and forward normalized NDR events northbound."""

from __future__ import annotations

import hashlib
import json
import logging
import os
import signal
import time
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


LOGGER = logging.getLogger("suricata-ndr-forwarder")
STOP = False

SEVERITY = {1: ("high", 85), 2: ("medium", 60), 3: ("low", 40)}
PROTOCOLS = {
    "modbus": "modbus-tcp",
    "modbus-tcp": "modbus-tcp",
    "http": "http",
    "http2": "http",
    "https": "http",
    "tls": "tls",
    "ssl": "tls",
    "tcp": "tcp",
    "udp": "udp",
}


def _clean(value: Any) -> str:
    return str(value or "").strip()


def _protocol(record: dict[str, Any]) -> str:
    app_proto = _clean(record.get("app_proto")).lower()
    if app_proto and app_proto not in {"failed", "unknown"}:
        return PROTOCOLS.get(app_proto, app_proto)
    try:
        dest_port = int(record.get("dest_port"))
    except (TypeError, ValueError):
        dest_port = 0
    if dest_port in {502, 1502}:
        return "modbus-tcp"
    network_proto = _clean(record.get("proto")).lower()
    return PROTOCOLS.get(network_proto, network_proto or "ip")


def _stable_event_id(record: dict[str, Any], sensor_id: str) -> str:
    canonical = json.dumps(record, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:24]
    return f"{sensor_id}:suricata:{digest}"


def map_alert(
    record: dict[str, Any],
    *,
    tenant_id: str,
    workspace_id: str,
    site_id: str,
    sensor_id: str,
) -> dict[str, Any] | None:
    if _clean(record.get("event_type")).lower() != "alert":
        return None
    alert = record.get("alert") if isinstance(record.get("alert"), dict) else {}
    try:
        severity_rank = int(alert.get("severity"))
    except (TypeError, ValueError):
        severity_rank = 2
    severity, risk_score = SEVERITY.get(severity_rank, ("medium", 60))
    gid = alert.get("gid", 1)
    sid = alert.get("signature_id", 0)
    flow_id = record.get("flow_id")
    destination_ip = _clean(record.get("dest_ip"))

    return {
        "schema_version": "ndr_event.normalized.v1",
        "event_id": _stable_event_id(record, sensor_id),
        "tenant_id": tenant_id,
        "workspace_id": workspace_id,
        "site_id": site_id,
        "sensor_id": sensor_id,
        "engine": "suricata",
        "event_type": "SURICATA_ALERT",
        "rule_id": f"suricata-{gid}-{sid}",
        "severity": severity,
        "risk_score": risk_score,
        "source_ip": _clean(record.get("src_ip")) or None,
        "source_port": record.get("src_port"),
        "destination_ip": destination_ip or None,
        "destination_port": record.get("dest_port"),
        "target_ip": destination_ip,
        "protocol": _protocol(record),
        "observed_at": _clean(record.get("timestamp")),
        "raw_ref": f"suricata:eve:flow_id={flow_id}" if flow_id is not None else None,
        "evidence": {
            "engine": "suricata",
            "sid": sid,
            "gid": gid,
            "rev": alert.get("rev"),
            "category": alert.get("category"),
            "signature": alert.get("signature"),
            "action": alert.get("action"),
            "app_proto": record.get("app_proto"),
            "flow_id": flow_id,
            "raw_event": record,
        },
    }


def _post(url: str, secret: str, event: dict[str, Any]) -> dict[str, Any]:
    request = Request(
        url,
        data=json.dumps(event, ensure_ascii=False).encode("utf-8"),
        headers={
            "Content-Type": "application/json",
            "X-Ndr-Ingest-Secret": secret,
        },
        method="POST",
    )
    with urlopen(request, timeout=20) as response:
        return json.loads(response.read().decode("utf-8"))


def _offset(path: Path) -> int:
    try:
        return int(path.read_text(encoding="utf-8").strip() or "0")
    except (OSError, ValueError):
        return 0


def _save_offset(path: Path, value: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(str(value), encoding="utf-8")


def _handle_signal(signum: int, _frame: Any) -> None:
    global STOP
    LOGGER.info("received signal %s", signum)
    STOP = True


def main() -> int:
    logging.basicConfig(
        level=getattr(logging, os.getenv("LOG_LEVEL", "INFO").upper(), logging.INFO),
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )
    signal.signal(signal.SIGTERM, _handle_signal)
    signal.signal(signal.SIGINT, _handle_signal)

    eve_path = Path(os.getenv("SURICATA_EVE_PATH", "/var/log/suricata/eve.json"))
    offset_path = Path(os.getenv("SURICATA_FORWARD_OFFSET", "/var/lib/sensel-ndr/eve.offset"))
    ingest_url = os.environ["NDR_INGEST_URL"].strip()
    ingest_secret = os.environ["NDR_INGEST_SECRET"].strip()
    tenant_id = os.getenv("TENANT_ID", "default").strip()
    workspace_id = os.environ["WORKSPACE_ID"].strip()
    site_id = os.getenv("SITE_ID", "factory-lab-001").strip()
    sensor_id = os.getenv("SENSOR_ID", "ndr-suricata-01").strip()
    poll_seconds = max(0.2, float(os.getenv("POLL_SECONDS", "1")))
    offset = _offset(offset_path)

    LOGGER.info("starting eve=%s endpoint=%s sensor=%s site=%s", eve_path, ingest_url, sensor_id, site_id)
    while not STOP:
        if not eve_path.is_file():
            time.sleep(poll_seconds)
            continue
        size = eve_path.stat().st_size
        if offset > size:
            offset = 0
        with eve_path.open("rb") as handle:
            handle.seek(offset)
            while not STOP:
                position = handle.tell()
                line = handle.readline()
                if not line:
                    break
                if not line.endswith(b"\n"):
                    handle.seek(position)
                    break
                try:
                    record = json.loads(line.decode("utf-8", errors="replace"))
                except json.JSONDecodeError:
                    offset = handle.tell()
                    _save_offset(offset_path, offset)
                    continue
                event = map_alert(
                    record,
                    tenant_id=tenant_id,
                    workspace_id=workspace_id,
                    site_id=site_id,
                    sensor_id=sensor_id,
                )
                if event is None:
                    offset = handle.tell()
                    _save_offset(offset_path, offset)
                    continue
                try:
                    result = _post(ingest_url, ingest_secret, event)
                except (HTTPError, URLError, TimeoutError, OSError) as exc:
                    LOGGER.warning("forward failed event_id=%s error=%s", event["event_id"], exc)
                    handle.seek(position)
                    break
                offset = handle.tell()
                _save_offset(offset_path, offset)
                LOGGER.info(
                    "forwarded event_id=%s deduplicated=%s",
                    result.get("event_id", event["event_id"]),
                    result.get("deduplicated"),
                )
        time.sleep(poll_seconds)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
