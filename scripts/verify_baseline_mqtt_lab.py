#!/usr/bin/env python3
"""Lab: publish baseline template via MQTT and verify Pi edge-agent applied it."""
from __future__ import annotations

import json
import subprocess
import sys
import time
from pathlib import Path

PI_HOST = "192.168.50.90"
PI_USER = "fju"
PI_PW = "0000"
PC_MQTT_HOST = "192.168.50.134"
REMOTE_PROFILE = "/home/fju/sensel-ot-edge-sensor/data/agent/baseline-profile.json"
from lab_paths import EDGEMED_ROOT

EDGE_REPO = Path(__file__).resolve().parents[1]


def ssh(cmd: str, timeout: int = 60) -> str:
    import paramiko

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(PI_HOST, username=PI_USER, password=PI_PW, timeout=20, look_for_keys=False, allow_agent=False)
    _, stdout, stderr = client.exec_command(cmd, timeout=timeout)
    out = stdout.read().decode("utf-8", "replace")
    err = stderr.read().decode("utf-8", "replace")
    client.close()
    if err.strip():
        print(err.strip())
    return out


def main() -> int:
    profile_id = sys.argv[1] if len(sys.argv) > 1 else "cic-template-medical-camera-v1"
    asset_id = sys.argv[2] if len(sys.argv) > 2 else "blink-camera-01"

    print(f"==> Deploy edge-agent config to Pi")
    deploy = subprocess.run(
        [sys.executable, str(EDGE_REPO / "scripts" / "_pi_deploy_mqtt_edge_agent.py")],
        cwd=str(EDGE_REPO),
        check=False,
    )
    if deploy.returncode != 0:
        print("WARN: deploy script non-zero; continuing if agent already running")

    try:
        import paho.mqtt  # noqa: F401
    except ImportError:
        subprocess.run([sys.executable, "-m", "pip", "install", "paho-mqtt"], check=True)

    print(f"==> Publish {profile_id} via MQTT")
    pub = subprocess.run(
        [
            sys.executable,
            str(EDGEMED_ROOT / "scripts" / "publish_baseline_profile_mqtt.py"),
            "--profile-id",
            profile_id,
            "--asset-id",
            asset_id,
            "--mqtt-host",
            PC_MQTT_HOST,
        ],
        cwd=str(EDGEMED_ROOT),
        check=True,
    )
    if pub.returncode != 0:
        return pub.returncode

    time.sleep(3)
    print("==> Read Pi baseline-profile.json")
    raw = ssh(f"cat {REMOTE_PROFILE} 2>/dev/null || echo '{{}}'")
    try:
        doc = json.loads(raw)
    except json.JSONDecodeError:
        print("FAIL: Pi baseline-profile.json is not valid JSON")
        print(raw[:500])
        return 1
    got = str(doc.get("profile_id") or "")
    if got != profile_id:
        print(f"FAIL: expected profile_id={profile_id}, got {got!r}")
        print(json.dumps(doc, ensure_ascii=False, indent=2)[:800])
        return 1
    print(f"OK: Pi applied profile_id={got} version={doc.get('version')} stats_source={doc.get('stats_source')}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
