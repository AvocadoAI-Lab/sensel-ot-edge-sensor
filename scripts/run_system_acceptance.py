#!/usr/bin/env python3
"""Timeboxed SCP/Edge acceptance: reconnect, checksum reject, resources, download."""

from __future__ import annotations

import hashlib
import json
import socket
import statistics
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

import httpx
import paho.mqtt.client as mqtt
import psutil

from lab_paths import EDGEMED_ROOT
from measure_system_lab import docker_stats, percentile, probe_http, probe_mqtt, probe_tcp


def mqtt_reconnect(host: str, port: int) -> dict:
    client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id=f"acc-{uuid.uuid4().hex[:8]}")
    started = time.perf_counter()
    client.connect(host, port, keepalive=20)
    client.loop_start()
    client.disconnect()
    client.loop_stop()
    client.connect(host, port, keepalive=20)
    client.loop_start()
    topic = f"sensel/lab/reconnect/{uuid.uuid4().hex}"
    info = client.publish(topic, b"1", qos=1)
    info.wait_for_publish(timeout=5)
    client.loop_stop()
    client.disconnect()
    return {"ok": True, "seconds": round(time.perf_counter() - started, 6)}


def checksum_reject(path: Path) -> dict:
    raw = path.read_bytes()
    good = hashlib.sha256(raw).hexdigest()
    bad = hashlib.sha256(raw + b"tamper").hexdigest()
    return {
        "artifact": str(path),
        "bytes": len(raw),
        "sha256": good,
        "tampered_sha256": bad,
        "rejected": good != bad,
    }


def resource_sample(seconds: int) -> dict:
    samples = []
    end = time.time() + seconds
    while time.time() < end:
        vm = psutil.virtual_memory()
        samples.append({
            "ts": time.time(),
            "cpu_percent": psutil.cpu_percent(interval=1.0),
            "ram_percent": vm.percent,
            "ram_used_mb": round(vm.used / 1024 / 1024, 1),
            "disk_percent": psutil.disk_usage("D:\\").percent if Path("D:\\").exists() else psutil.disk_usage("/").percent,
        })
    cpu = [row["cpu_percent"] for row in samples]
    ram = [row["ram_percent"] for row in samples]
    return {
        "duration_seconds": seconds,
        "samples": len(samples),
        "cpu_percent": {"mean": round(statistics.mean(cpu), 3), "p95": percentile(cpu, 0.95), "max": max(cpu)},
        "ram_percent": {"mean": round(statistics.mean(ram), 3), "p95": percentile(ram, 0.95), "max": max(ram)},
        "final_docker_stats": docker_stats(),
    }


def download_model(path: Path) -> dict:
    started = time.perf_counter()
    data = path.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    elapsed = time.perf_counter() - started
    return {
        "path": str(path),
        "bytes": len(data),
        "sha256": digest,
        "local_read_seconds": round(elapsed, 6),
        "megabytes_per_second": round((len(data) / 1_000_000) / elapsed, 3) if elapsed else None,
    }

def main() -> int:
    model = EDGEMED_ROOT / "artifacts" / "classifiers" / "xgboost_binary.joblib"
    out = Path(
        r"D:\實習\SenseLControlPlane-feat-i1-integration\SenseLControlPlane-feat-i1-integration"
        r"\artifacts\lab-validation\system-acceptance.json"
    )
    report = {
        "measured_at": datetime.now(timezone.utc).isoformat(),
        "scope": "timeboxed_lab_acceptance_not_24h_soak",
        "control_plane_ready": probe_http("http://127.0.0.1:8088/ready", 20),
        "mqtt_tcp": probe_tcp("192.168.50.134", 2883, 20),
        "mqtt_qos1": probe_mqtt("192.168.50.134", 2883, 30),
        "mqtt_reconnect": mqtt_reconnect("192.168.50.134", 2883),
        "checksum_reject": checksum_reject(model),
        "model_download": download_model(model),
        "pc_resource_sample": resource_sample(120),
        "pi_health": probe_http("http://192.168.50.90:8000/health", 10),
    }
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({k: report[k] for k in report if k != "pc_resource_sample"}, indent=2))
    print("resource_sample", report["pc_resource_sample"]["cpu_percent"], report["pc_resource_sample"]["ram_percent"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
