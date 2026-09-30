#!/usr/bin/env python3
"""Disrupt and verify recovery of MQTT and Control Plane lab services."""

from __future__ import annotations

import argparse
import json
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


def percentile(values: list[float], quantile: float) -> float | None:
    if not values:
        return None
    values = sorted(values)
    return round(values[min(round((len(values) - 1) * quantile), len(values) - 1)], 3)


def wait_http(url: str, timeout: float) -> dict[str, Any]:
    started = time.perf_counter()
    attempts = 0
    last_error = ""
    with httpx.Client(timeout=2.0) as client:
        while time.perf_counter() - started < timeout:
            attempts += 1
            try:
                response = client.get(url)
                if response.is_success:
                    return {
                        "recovered": True,
                        "seconds": round(time.perf_counter() - started, 6),
                        "attempts": attempts,
                        "status": response.status_code,
                    }
                last_error = f"HTTP {response.status_code}"
            except Exception as exc:
                last_error = f"{type(exc).__name__}: {exc}"
            time.sleep(0.5)
    return {
        "recovered": False,
        "seconds": round(time.perf_counter() - started, 6),
        "attempts": attempts,
        "last_error": last_error,
    }


def latency_probe(url: str, attempts: int) -> dict[str, Any]:
    values: list[float] = []
    errors = 0
    with httpx.Client(timeout=5.0) as client:
        for _ in range(attempts):
            started = time.perf_counter()
            try:
                response = client.get(url)
                if response.is_success:
                    values.append((time.perf_counter() - started) * 1000)
                else:
                    errors += 1
            except Exception:
                errors += 1
    return {
        "attempts": attempts,
        "successes": len(values),
        "errors": errors,
        "mean_ms": round(statistics.mean(values), 3) if values else None,
        "p95_ms": percentile(values, 0.95),
        "p99_ms": percentile(values, 0.99),
        "maximum_ms": round(max(values), 3) if values else None,
    }


def mqtt_recovery(container: str, host: str, port: int) -> dict[str, Any]:
    topic = f"sensel/lab/recovery/{uuid.uuid4().hex}"
    connected = threading.Event()
    disconnected = threading.Event()
    messages: list[str] = []
    connect_times: list[float] = []
    restart_started = [0.0]

    def on_connect(client: mqtt.Client, _userdata: object, _flags: object, reason: object, _properties: object) -> None:
        if not bool(getattr(reason, "is_failure", False)):
            client.subscribe(topic, qos=1)
            if restart_started[0]:
                connect_times.append(time.perf_counter() - restart_started[0])
            connected.set()

    def on_disconnect(_client: mqtt.Client, _userdata: object, _flags: object, _reason: object, _properties: object) -> None:
        disconnected.set()
        connected.clear()

    def on_message(_client: mqtt.Client, _userdata: object, message: mqtt.MQTTMessage) -> None:
        messages.append(message.payload.decode("utf-8", "replace"))

    client = mqtt.Client(
        mqtt.CallbackAPIVersion.VERSION2,
        client_id=f"recovery-{uuid.uuid4().hex[:8]}",
    )
    client.on_connect = on_connect
    client.on_disconnect = on_disconnect
    client.on_message = on_message
    client.reconnect_delay_set(min_delay=1, max_delay=3)
    client.connect(host, port, keepalive=10)
    client.loop_start()
    if not connected.wait(10):
        raise RuntimeError("MQTT did not connect before disruption")
    client.publish(topic, "before-restart", qos=1).wait_for_publish(timeout=5)
    deadline = time.monotonic() + 5
    while "before-restart" not in messages and time.monotonic() < deadline:
        time.sleep(0.05)

    restart_started[0] = time.perf_counter()
    result = subprocess.run(
        ["docker", "restart", container],
        capture_output=True,
        text=True,
        check=False,
    )
    saw_disconnect = disconnected.wait(10)
    reconnected = connected.wait(60)
    if reconnected:
        client.publish(topic, "after-restart", qos=1).wait_for_publish(timeout=5)
    deadline = time.monotonic() + 10
    while "after-restart" not in messages and time.monotonic() < deadline:
        time.sleep(0.05)
    client.loop_stop()
    client.disconnect()
    return {
        "container": container,
        "restart_exit_code": result.returncode,
        "saw_disconnect": saw_disconnect,
        "reconnected": reconnected,
        "reconnect_seconds": round(connect_times[-1], 6) if connect_times else None,
        "before_message_received": "before-restart" in messages,
        "after_message_received": "after-restart" in messages,
        "passed": result.returncode == 0
        and saw_disconnect
        and reconnected
        and "before-restart" in messages
        and "after-restart" in messages,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--post-recovery-probes", type=int, default=100)
    args = parser.parse_args()
    if not args.execute:
        raise SystemExit("Refusing disruptive test without --execute")

    report: dict[str, Any] = {
        "tested_at": datetime.now(timezone.utc).isoformat(),
        "scope": "controlled lab restart and reconnect test",
        "mqtt": mqtt_recovery("layera-emqx", "192.168.50.134", 2883),
    }
    started = time.perf_counter()
    restart = subprocess.run(
        ["docker", "restart", "sensel-integration-control-plane-1"],
        capture_output=True,
        text=True,
        check=False,
    )
    report["control_plane_restart"] = {
        "restart_exit_code": restart.returncode,
        "restart_command_seconds": round(time.perf_counter() - started, 6),
        **wait_http("http://127.0.0.1:8088/ready", timeout=60),
    }
    report["post_recovery_latency"] = latency_probe(
        "http://127.0.0.1:8088/ready",
        args.post_recovery_probes,
    )
    report["passed"] = bool(
        report["mqtt"]["passed"]
        and report["control_plane_restart"]["recovered"]
        and report["post_recovery_latency"]["errors"] == 0
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
