<<<<<<< Updated upstream
#!/usr/bin/env python3
"""Lab mock SenseL API — persists ingested events for events-viewer."""

from __future__ import annotations

import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

HOST = os.environ.get("MOCK_SENSEL_HOST", "0.0.0.0")
PORT = int(os.environ.get("MOCK_SENSEL_PORT", "8765"))
UPLOADED_EVENTS = Path(
    os.environ.get("UPLOADED_EVENTS_PATH", "/data/assets/uploaded-events.jsonl")
)


def _append_event(event: dict) -> None:
    UPLOADED_EVENTS.parent.mkdir(parents=True, exist_ok=True)
    with UPLOADED_EVENTS.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(event, ensure_ascii=False) + "\n")


def _read_events(limit: int = 100) -> list[dict]:
    if not UPLOADED_EVENTS.is_file():
        return []
    lines = UPLOADED_EVENTS.read_text(encoding="utf-8").splitlines()
    events = []
    for line in lines[-limit:]:
        text = line.strip()
        if text:
            events.append(json.loads(text))
    events.reverse()
    return events


class Handler(BaseHTTPRequestHandler):
    def log_message(self, _format: str, *_args) -> None:
        return

    def _json_response(self, status: int, payload: dict) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        if parsed.path.endswith("/security-events"):
            query = parse_qs(parsed.query)
            limit = int(query.get("limit", ["100"])[0])
            self._json_response(200, {"events": _read_events(limit), "count": len(_read_events(limit))})
            return
        if parsed.path in ("/", "/health", "/api/health"):
            self._json_response(200, {"status": "ok", "service": "mock-sensel"})
            return
        self.send_error(404)

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(length).decode("utf-8") if length else "{}"
        try:
            body = json.loads(raw or "{}")
        except json.JSONDecodeError:
            self.send_error(400)
            return

        if self.path.endswith("/security-events"):
            _append_event(body)
        elif self.path.endswith("/api/v1/edge-sensors/register"):
            sensor_id = str(body.get("sensor_id") or "ot-edge-lab")
            self._json_response(
                200,
                {
                    "status": "ok",
                    "tenant_id": "lab-mock-tenant",
                    "mqtt_tenant_id": "lab-mock-tenant",
                    "sensor_id": sensor_id,
                    "note": "mock-sensel lab only — use real Portal for production",
                },
            )
            return
        elif self.path.endswith("/register") or self.path.endswith("/health"):
            pass
        else:
            self.send_error(404)
            return

        self._json_response(200, {"status": "ok"})


def main() -> None:
    server = ThreadingHTTPServer((HOST, PORT), Handler)
    print(f"mock-sensel listening on {HOST}:{PORT}", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
=======
#!/usr/bin/env python3
"""Lab mock SenseL API — persists ingested events for events-viewer."""

from __future__ import annotations

import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

HOST = os.environ.get("MOCK_SENSEL_HOST", "0.0.0.0")
PORT = int(os.environ.get("MOCK_SENSEL_PORT", "8765"))
UPLOADED_EVENTS = Path(
    os.environ.get("UPLOADED_EVENTS_PATH", "/data/assets/uploaded-events.jsonl")
)


def _append_event(event: dict) -> None:
    UPLOADED_EVENTS.parent.mkdir(parents=True, exist_ok=True)
    with UPLOADED_EVENTS.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(event, ensure_ascii=False) + "\n")


def _read_events(limit: int = 100) -> list[dict]:
    if not UPLOADED_EVENTS.is_file():
        return []
    lines = UPLOADED_EVENTS.read_text(encoding="utf-8").splitlines()
    events = []
    for line in lines[-limit:]:
        text = line.strip()
        if text:
            events.append(json.loads(text))
    events.reverse()
    return events


class Handler(BaseHTTPRequestHandler):
    def log_message(self, _format: str, *_args) -> None:
        return

    def _json_response(self, status: int, payload: dict) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        if parsed.path.endswith("/security-events"):
            query = parse_qs(parsed.query)
            limit = int(query.get("limit", ["100"])[0])
            self._json_response(200, {"events": _read_events(limit), "count": len(_read_events(limit))})
            return
        if parsed.path in ("/", "/health", "/api/health"):
            self._json_response(200, {"status": "ok", "service": "mock-sensel"})
            return
        self.send_error(404)

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(length).decode("utf-8") if length else "{}"
        try:
            body = json.loads(raw or "{}")
        except json.JSONDecodeError:
            self.send_error(400)
            return

        if self.path.endswith("/security-events"):
            _append_event(body)
        elif self.path.endswith("/api/v1/edge-sensors/register"):
            sensor_id = str(body.get("sensor_id") or "ot-edge-lab")
            self._json_response(
                200,
                {
                    "status": "ok",
                    "tenant_id": "lab-mock-tenant",
                    "mqtt_tenant_id": "lab-mock-tenant",
                    "sensor_id": sensor_id,
                    "note": "mock-sensel lab only — use real Portal for production",
                },
            )
            return
        elif self.path.endswith("/register") or self.path.endswith("/health"):
            pass
        else:
            self.send_error(404)
            return

        self._json_response(200, {"status": "ok"})


def main() -> None:
    server = ThreadingHTTPServer((HOST, PORT), Handler)
    print(f"mock-sensel listening on {HOST}:{PORT}", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
>>>>>>> Stashed changes
