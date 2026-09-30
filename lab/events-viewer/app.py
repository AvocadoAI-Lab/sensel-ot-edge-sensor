#!/usr/bin/env python3
"""Lab events viewer — local JSONL + uploaded events + IEC summaries."""

from __future__ import annotations

import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

ASSETS_DIR = Path(os.environ.get("ASSETS_DIR", "/data/assets"))
HOST = os.environ.get("EVENTS_VIEWER_HOST", "0.0.0.0")
PORT = int(os.environ.get("EVENTS_VIEWER_PORT", "8080"))
STATIC_DIR = Path(__file__).resolve().parent / "static"


def _read_jsonl(path: Path, limit: int = 100, rule_id: str = "") -> list[dict]:
    if not path.is_file():
        return []
    lines = path.read_text(encoding="utf-8").splitlines()
    events: list[dict] = []
    for line in reversed(lines):
        text = line.strip()
        if not text:
            continue
        try:
            event = json.loads(text)
        except json.JSONDecodeError:
            continue
        if rule_id and event.get("rule_id") != rule_id:
            continue
        events.append(event)
        if len(events) >= limit:
            break
    return events


def _read_summary(name: str) -> dict | None:
    path = ASSETS_DIR / name
    if not path.is_file():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return None


def _summaries() -> dict:
    return {
        "goose": _read_summary("iec61850-goose-summary.json"),
        "mms": _read_summary("iec61850-mms-summary.json"),
        "feature": _read_summary("feature-summary.json"),
    }


class Handler(BaseHTTPRequestHandler):
    def log_message(self, _format: str, *_args) -> None:
        return

    def _json(self, status: int, payload: dict) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _file(self, path: Path, content_type: str) -> None:
        if not path.is_file():
            self.send_error(404)
            return
        body = path.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/") or "/"
        query = parse_qs(parsed.query)
        limit = max(1, min(int(query.get("limit", ["100"])[0]), 500))
        rule_id = query.get("rule_id", [""])[0]

        if path == "/api/health":
            self._json(200, {"status": "ok", "assets_dir": str(ASSETS_DIR)})
            return

        if path == "/api/events/local":
            events = _read_jsonl(ASSETS_DIR / "security-events.jsonl", limit, rule_id)
            self._json(200, {"source": "local", "count": len(events), "events": events})
            return

        if path == "/api/events/uploaded":
            events = _read_jsonl(ASSETS_DIR / "uploaded-events.jsonl", limit, rule_id)
            self._json(200, {"source": "uploaded", "count": len(events), "events": events})
            return

        if path == "/api/summaries":
            self._json(200, _summaries())
            return

        if path in ("/", "/index.html"):
            self._file(STATIC_DIR / "index.html", "text/html; charset=utf-8")
            return

        if path == "/style.css":
            self._file(STATIC_DIR / "style.css", "text/css; charset=utf-8")
            return

        self.send_error(404)


def main() -> None:
    server = ThreadingHTTPServer((HOST, PORT), Handler)
    print(f"events-viewer listening on http://{HOST}:{PORT}", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
