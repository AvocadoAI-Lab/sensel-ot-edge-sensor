"""Minimal SenseL ingestion mock for integration tests."""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any


class MockSenseLState:
    def __init__(self) -> None:
        self.registrations: list[dict[str, Any]] = []
        self.health_reports: list[dict[str, Any]] = []
        self.events: list[dict[str, Any]] = []


def start_mock_sensel(port: int = 0) -> tuple[HTTPServer, MockSenseLState, str]:
    state = MockSenseLState()

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:
            length = int(self.headers.get("Content-Length", 0))
            body = json.loads(self.rfile.read(length).decode() or "{}")
            if self.path.endswith("/register"):
                state.registrations.append(body)
            elif self.path.endswith("/health"):
                state.health_reports.append(body)
            elif self.path.endswith("/security-events"):
                state.events.append(body)
            else:
                self.send_error(404)
                return
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"status":"ok"}')

        def log_message(self, _format: str, *_args) -> None:
            return

    server = HTTPServer(("127.0.0.1", port), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, bound_port = server.server_address
    base_url = f"http://{host}:{bound_port}"
    return server, state, base_url
