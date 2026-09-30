#!/usr/bin/env python3
"""Lab: onboard a device type with no dedicated template and verify the Edge result.

The publisher resolves the device type through the Control Plane baseline catalog.
An unrecognised type must resolve to the statistics-free generic profile seeded
only with organisation-wide common rules, never to another device type's
profiling statistics.
"""
from __future__ import annotations

import json
import subprocess
import sys
import time
from pathlib import Path

PI_HOST = "192.168.50.90"
PI_USER = "fju"
PC_MQTT_HOST = "192.168.50.134"
REMOTE_PROFILE = "/home/fju/sensel-ot-edge-sensor/data/agent/baseline-profile.json"
from lab_paths import EDGEMED_ROOT

EXPECTED_PROFILE_ID = "generic-observe-only-v1"
BORROWED_STAT_KEYS = ("rate_p50_hint", "rate_p95_hint", "duration_p50_hint", "duration_p95_hint")


def ssh(command: str, *, password: str, timeout: int = 60) -> str:
    import paramiko

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(
        PI_HOST,
        username=PI_USER,
        password=password,
        timeout=20,
        look_for_keys=False,
        allow_agent=False,
    )
    _, stdout, stderr = client.exec_command(command, timeout=timeout)
    out = stdout.read().decode("utf-8", "replace")
    err = stderr.read().decode("utf-8", "replace")
    client.close()
    if err.strip():
        print(err.strip())
    return out


def _fail(message: str, document: dict | None = None) -> int:
    print(f"FAIL: {message}")
    if document is not None:
        print(json.dumps(document, ensure_ascii=False, indent=2)[:1200])
    return 1


def main() -> int:
    device_type = sys.argv[1] if len(sys.argv) > 1 else "unknown_medical_device"
    asset_id = sys.argv[2] if len(sys.argv) > 2 else "unknown-asset-01"
    pi_password = sys.argv[3] if len(sys.argv) > 3 else "0000"

    print(f"==> Publish baseline for unregistered device_type={device_type}")
    published = subprocess.run(
        [
            sys.executable,
            str(EDGEMED_ROOT / "scripts" / "publish_baseline_profile_mqtt.py"),
            "--device-type",
            device_type,
            "--asset-id",
            asset_id,
            "--mqtt-host",
            PC_MQTT_HOST,
        ],
        cwd=str(EDGEMED_ROOT),
        check=False,
    )
    if published.returncode != 0:
        return _fail(f"publish exited {published.returncode}")

    time.sleep(3)
    print("==> Read Pi baseline-profile.json")
    raw = ssh(f"cat {REMOTE_PROFILE} 2>/dev/null || echo '{{}}'", password=pi_password)
    try:
        document = json.loads(raw)
    except json.JSONDecodeError:
        print(raw[:500])
        return _fail("Pi baseline-profile.json is not valid JSON")

    profile_id = str(document.get("profile_id") or "")
    if profile_id != EXPECTED_PROFILE_ID:
        return _fail(f"expected profile_id={EXPECTED_PROFILE_ID}, got {profile_id!r}", document)

    observed = document.get("observed") if isinstance(document.get("observed"), dict) else {}
    provenance = observed.get("provenance") if isinstance(observed.get("provenance"), dict) else {}
    if provenance.get("resolution") != "generic_fallback":
        return _fail(f"expected generic_fallback resolution, got {provenance.get('resolution')!r}", document)
    if provenance.get("requested_device_type") != device_type:
        return _fail(f"provenance lost requested device_type {device_type!r}", document)
    if not provenance.get("requires_local_learning"):
        return _fail("generic fallback must require local learning", document)

    thresholds = observed.get("thresholds") if isinstance(observed.get("thresholds"), dict) else {}
    borrowed = [key for key in BORROWED_STAT_KEYS if key in thresholds]
    if borrowed:
        return _fail(f"generic fallback carries borrowed statistics: {borrowed}", document)
    if thresholds.get("assert_rate_thresholds") is not False:
        return _fail("generic fallback must disable rate assertions", document)
    if "cic_profiling_stats" in observed:
        return _fail("generic fallback must not carry CIC profiling statistics", document)

    iomt = observed.get("iomt") if isinstance(observed.get("iomt"), dict) else {}
    forbidden = iomt.get("forbidden_patterns") or []
    categories = iomt.get("allowed_destination_categories") or []
    if not forbidden:
        return _fail("common-rule forbidden patterns missing", document)
    if not categories:
        return _fail("common-rule destination categories missing", document)
    if iomt.get("normal_destinations"):
        return _fail("generic fallback must not assert device-specific destinations", document)

    print(f"OK: Pi applied {profile_id} version={document.get('version')}")
    print(f"    resolution={provenance.get('resolution')} common_rules={provenance.get('common_rules_id')}")
    print(f"    stats_source={provenance.get('stats_source')} requires_local_learning=True")
    print(f"    forbidden_patterns={len(forbidden)} allowed_destination_categories={len(categories)}")
    print("    no borrowed rate/duration statistics present")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
