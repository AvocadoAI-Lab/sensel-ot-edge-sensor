"""Small EdgeX OT panel for the local NDR/OT lab.

The browser talks to this process, and this process reads EdgeX Core Data.
That avoids browser CORS issues when EdgeX is running on the Ubuntu VM.
"""

from __future__ import annotations

import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.error import URLError
from urllib.request import Request, urlopen


HOST = os.environ.get("OT_PANEL_HOST", "127.0.0.1")
PORT = int(os.environ.get("OT_PANEL_PORT", "8091"))
EDGEX_CORE_DATA_URL = os.environ.get("EDGEX_CORE_DATA_URL", "http://192.168.80.130:59880")
STATIC_DIR = Path(__file__).resolve().parent / "static"


def _latest_edgex_event() -> dict[str, Any]:
    url = f"{EDGEX_CORE_DATA_URL.rstrip('/')}/api/v3/event/all?limit=1"
    req = Request(url, headers={"Accept": "application/json"})
    with urlopen(req, timeout=5) as response:
        return json.loads(response.read().decode("utf-8"))


def _readings_by_name(event: dict[str, Any]) -> dict[str, Any]:
    items = event.get("readings") if isinstance(event.get("readings"), list) else []
    return {str(item.get("resourceName")): item.get("value") for item in items if isinstance(item, dict)}


def _float_value(value: Any, default: float = 0.0) -> float:
    try:
        return float(str(value))
    except (TypeError, ValueError):
        return default


def _bool_value(value: Any) -> bool:
    return str(value).strip().lower() in {"1", "true", "yes", "closed"}


def _panel_payload() -> dict[str, Any]:
    data = _latest_edgex_event()
    events = data.get("events") if isinstance(data.get("events"), list) else []
    event = events[0] if events and isinstance(events[0], dict) else {}
    readings = _readings_by_name(event)
    voltage = _float_value(readings.get("Voltage"))
    alarm = int(_float_value(readings.get("AlarmStatus")))
    breaker_closed = _bool_value(readings.get("BreakerClosed"))

    # The current lab simulator is a Modbus relay. Fan RPM is a display-side
    # derived signal so operators get a familiar rotating-machine visual.
    fan_rpm = int(max(0.0, min(3600.0, voltage * 120.0)))
    return {
        "source": "edgex-core-data",
        "edgex_url": EDGEX_CORE_DATA_URL,
        "device": event.get("deviceName") or "unknown",
        "profile": event.get("profileName") or "unknown",
        "origin": event.get("origin"),
        "readings": {
            "AlarmStatus": alarm,
            "Voltage": voltage,
            "BreakerClosed": breaker_closed,
            "FanRPM": fan_rpm,
        },
    }


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt: str, *args: Any) -> None:
        print(f"{self.address_string()} - {fmt % args}", flush=True)

    def _json(self, status: int, payload: dict[str, Any]) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _file(self, path: Path, content_type: str) -> None:
        if not path.is_file():
            self._json(404, {"error": "not_found"})
            return
        body = path.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        if self.path == "/api/health":
            self._json(200, {"status": "ok", "edgex_url": EDGEX_CORE_DATA_URL})
            return
        if self.path == "/api/edgex/latest":
            try:
                self._json(200, _panel_payload())
            except (OSError, TimeoutError, URLError, json.JSONDecodeError) as exc:
                self._json(502, {"status": "error", "error": str(exc), "edgex_url": EDGEX_CORE_DATA_URL})
            return
        if self.path in {"/", "/index.html"}:
            self._file(STATIC_DIR / "index.html", "text/html; charset=utf-8")
            return
        if self.path == "/style.css":
            self._file(STATIC_DIR / "style.css", "text/css; charset=utf-8")
            return
        if self.path == "/app.js":
            self._file(STATIC_DIR / "app.js", "text/javascript; charset=utf-8")
            return
        self._json(404, {"error": "not_found"})


if __name__ == "__main__":
    server = ThreadingHTTPServer((HOST, PORT), Handler)
    print(f"edgex-ot-panel listening on http://{HOST}:{PORT}", flush=True)
    print(f"EdgeX Core Data: {EDGEX_CORE_DATA_URL}", flush=True)
    server.serve_forever()
