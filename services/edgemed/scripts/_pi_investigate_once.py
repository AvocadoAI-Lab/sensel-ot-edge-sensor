#!/usr/bin/env python3
"""Measure Pi investigate with llama.cpp; fix understanding of latency."""

from __future__ import annotations

import json
import time

import httpx

PI = "http://192.168.50.90:8000"
BODY = {
    "device_id": "monitor-07",
    "device_type": "patient_monitor",
    "operating_state": "idle",
    "criticality": "high",
    "session_id": f"sess-inv-{int(time.time())}",
    "features": {
        "flow_duration": 1.2,
        "packet_rate": 84.0,
        "byte_rate": 25000.0,
        "syn_count": 2.0,
        "ack_count": 8.0,
        "connection_rate": 6.0,
        "mean_packet_size": 320.0,
        "iat_mean": 0.08,
    },
}


def main() -> int:
    with httpx.Client(base_url=PI, timeout=900.0) as c:
        h = c.get("/health").json()
        print("health slm", h.get("components", {}).get("slm"))
        t0 = time.perf_counter()
        scored = c.post("/api/score", json=BODY).json()
        print("score ms", round((time.perf_counter() - t0) * 1000, 1))
        print("score gen", (scored.get("assessment") or {}).get("generation_status"))
        eid = scored.get("event_id")
        t1 = time.perf_counter()
        inv = c.post("/api/investigate", json={"event_id": eid})
        ms = round((time.perf_counter() - t1) * 1000, 1)
        print("investigate status", inv.status_code, "ms", ms)
        data = inv.json()
        event = data.get("event") or {}
        print("slm block", data.get("slm"))
        print(
            "event generation",
            (event.get("assessment") or {}).get("generation_status"),
            "summary",
            ((event.get("assessment") or {}).get("summary") or "")[:200],
        )
        Path = __import__("pathlib").Path
        (Path(__file__).resolve().parents[1] / "docs" / "_pi_investigate_sample.json").write_text(
            json.dumps(data, ensure_ascii=False, indent=2)[:8000],
            encoding="utf-8",
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
