#!/usr/bin/env python3
"""Short reproducible SCP/Edge lab connectivity and resource benchmark."""

from __future__ import annotations

import argparse
import json
import socket
import statistics
import subprocess
import threading
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import httpx
import paho.mqtt.client as mqtt


def percentile(values: list[float], percent: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    index = min(round((len(ordered) - 1) * percent), len(ordered) - 1)
    return round(ordered[index], 3)


def probe_http(url: str, attempts: int) -> dict[str, Any]:
    latencies: list[float] = []
    statuses: dict[str, int] = {}
    errors: list[str] = []
    with httpx.Client(timeout=5.0) as client:
        for _ in range(attempts):
            started = time.perf_counter()
            try:
                response = client.get(url)
                elapsed = (time.perf_counter() - started) * 1000.0
                statuses[str(response.status_code)] = statuses.get(str(response.status_code), 0) + 1
                if response.is_success:
                    latencies.append(elapsed)
                else:
                    errors.append(f"HTTP {response.status_code}")
            except Exception as exc:
                errors.append(type(exc).__name__)
    return {
        "url": url,
        "attempts": attempts,
        "successes": len(latencies),
        "success_rate": round(len(latencies) / attempts, 6),
        "status_counts": statuses,
        "latency_ms": {
            "mean": round(statistics.mean(latencies), 3) if latencies else None,
            "p95": percentile(latencies, 0.95),
            "maximum": round(max(latencies), 3) if latencies else None,
        },
        "errors": errors,
    }


def probe_pi_inference(attempts: int) -> dict[str, Any]:
    url = "http://192.168.50.90:8000/api/score"
    payload = {
        "device_id": "system-benchmark",
        "device_type": "medical_aiot",
        "operating_state": "idle",
        "criticality": "high",
        "features": {
            "flow_duration": 1.0,
            "packet_rate": 10.0,
            "byte_rate": 10000.0,
            "syn_count": 4.0,
            "ack_count": 8.0,
            "connection_rate": 500.0,
            "mean_packet_size": 300.0,
            "iat_mean": 0.08,
        },
        "fuse": True,
    }
    latencies: list[float] = []
    statuses: dict[str, int] = {}
    with httpx.Client(timeout=15.0) as client:
        for _ in range(attempts):
            started = time.perf_counter()
            response = client.post(url, json=payload)
            statuses[str(response.status_code)] = statuses.get(str(response.status_code), 0) + 1
            if response.is_success:
                latencies.append((time.perf_counter() - started) * 1000.0)
    total_seconds = sum(latencies) / 1000.0
    return {
        "url": url,
        "attempts": attempts,
        "successes": len(latencies),
        "success_rate": round(len(latencies) / attempts, 6),
        "status_counts": statuses,
        "latency_ms": {
            "mean": round(statistics.mean(latencies), 3) if latencies else None,
            "p95": percentile(latencies, 0.95),
            "maximum": round(max(latencies), 3) if latencies else None,
        },
        "throughput_requests_per_second": (
            round(len(latencies) / total_seconds, 3) if total_seconds else None
        ),
        "note": "sequential single-request HTTP benchmark; includes API and evidence-store overhead",
    }


def probe_tcp(host: str, port: int, attempts: int) -> dict[str, Any]:
    latencies: list[float] = []
    errors: list[str] = []
    for _ in range(attempts):
        started = time.perf_counter()
        try:
            with socket.create_connection((host, port), timeout=3.0):
                latencies.append((time.perf_counter() - started) * 1000.0)
        except Exception as exc:
            errors.append(type(exc).__name__)
    return {
        "endpoint": f"{host}:{port}",
        "attempts": attempts,
        "successes": len(latencies),
        "success_rate": round(len(latencies) / attempts, 6),
        "latency_ms": {
            "mean": round(statistics.mean(latencies), 3) if latencies else None,
            "p95": percentile(latencies, 0.95),
        },
        "errors": errors,
    }


def probe_mqtt(host: str, port: int, count: int) -> dict[str, Any]:
    topic = f"sensel/lab/benchmark/{uuid.uuid4().hex}"
    received: set[int] = set()
    connected = threading.Event()

    def on_connect(client: mqtt.Client, _userdata: object, _flags: object, reason: object, _properties: object) -> None:
        if not bool(getattr(reason, "is_failure", False)):
            client.subscribe(topic, qos=1)
            connected.set()

    def on_message(_client: mqtt.Client, _userdata: object, message: mqtt.MQTTMessage) -> None:
        try:
            received.add(int(message.payload.decode("ascii")))
        except ValueError:
            pass

    client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id=f"lab-benchmark-{uuid.uuid4().hex[:8]}")
    client.on_connect = on_connect
    client.on_message = on_message
    started = time.perf_counter()
    client.connect(host, port, keepalive=20)
    client.loop_start()
    if not connected.wait(5):
        client.loop_stop()
        client.disconnect()
        return {"messages": count, "received": 0, "success_rate": 0.0, "error": "connect_timeout"}
    for index in range(count):
        info = client.publish(topic, str(index).encode("ascii"), qos=1, retain=False)
        info.wait_for_publish(timeout=5)
    deadline = time.monotonic() + 10
    while len(received) < count and time.monotonic() < deadline:
        time.sleep(0.02)
    client.loop_stop()
    client.disconnect()
    return {
        "topic": topic,
        "qos": 1,
        "messages": count,
        "received": len(received),
        "success_rate": round(len(received) / count, 6),
        "wall_seconds": round(time.perf_counter() - started, 6),
    }


def docker_stats() -> list[dict[str, str]]:
    result = subprocess.run(
        [
            "docker",
            "stats",
            "--no-stream",
            "--format",
            "{{json .}}",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    rows: list[dict[str, str]] = []
    for line in result.stdout.splitlines():
        if line.strip():
            rows.append(json.loads(line))
    return rows


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--attempts", type=int, default=30)
    parser.add_argument("--mqtt-messages", type=int, default=50)
    parser.add_argument("--mqtt-port", type=int, default=2883)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    report = {
        "measured_at": datetime.now(timezone.utc).isoformat(),
        "scope": "short_functional_lab_benchmark_not_long_duration_soak",
        "control_plane_ready": probe_http("http://127.0.0.1:8088/ready", args.attempts),
        "console_health": probe_http("http://127.0.0.1:8089/health", args.attempts),
        "pi_edgemed_health": probe_http("http://192.168.50.90:8000/health", args.attempts),
        "pi_inference": probe_pi_inference(args.attempts),
        "mqtt_tcp": probe_tcp("192.168.50.134", args.mqtt_port, args.attempts),
        "mqtt_qos1_delivery": probe_mqtt("192.168.50.134", args.mqtt_port, args.mqtt_messages),
        "docker_stats_snapshot": docker_stats(),
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
