#!/usr/bin/env python3
"""Verify Pi edge-agent + PC mqtt-bridge end-to-end."""
from __future__ import annotations

import json
import subprocess
import sys
import time

import paramiko

HOST, USER, PW = "192.168.50.90", "fju", "0000"
PC_MQTT = "192.168.50.134"


def pi_run(cmd: str) -> str:
    c = paramiko.SSHClient()
    c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    c.connect(HOST, username=USER, password=PW, timeout=20, look_for_keys=False, allow_agent=False)
    _, o, e = c.exec_command(cmd, timeout=60)
    out = o.read().decode("utf-8", "replace")
    err = e.read().decode("utf-8", "replace")
    c.close()
    return out + err


def main() -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")

    print("==> Pi edge-agent process")
    print(pi_run("pgrep -af 'sensel-edge-agent/.venv' || pgrep -af 'edge-agent'"))

    print("==> Pi MQTT log lines")
    print(pi_run("grep -i mqtt /tmp/sensel-edge-agent.log | tail -n 15"))

    print("==> Sample real TrustEpisode line")
    sample = pi_run(
        "tail -n 5 /home/fju/sensel-ot-edge-sensor/data/assets/trust-episodes.jsonl | head -n 1"
    ).strip()
    print(sample[:500])

    print("==> Direct MQTT publish test from Pi")
    pub = pi_run(
        f"""python3 - <<'PY'
import json, time
import paho.mqtt.publish as pub
topic = "ot-edge/default/factory-lab-pi/ot-edge-pi4/episodes/v1"
payload = {{
  "schema": "trust_episode_envelope.v1",
  "tenant_id": "default",
  "site_id": "factory-lab-pi",
  "sensor_id": "ot-edge-pi4",
  "observed_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
  "payload": {{
    "episode_id": "mqtt-direct-test",
    "asset_id": "asset-pi-lab-001",
    "decision": "observe",
    "trust_score": 0.5,
    "summary": "direct-mqtt-verify"
  }}
}}
pub.single(topic, json.dumps(payload), hostname="{PC_MQTT}", port=1883)
print("published", topic)
PY"""
    )
    print(pub)

    time.sleep(3)
    print("==> PC mqtt-bridge logs (recent ot-edge)")
    r = subprocess.run(
        ["docker", "logs", "layera-mqtt-bridge", "--tail", "50"],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    for line in r.stdout.splitlines() + r.stderr.splitlines():
        if "ot-edge" in line.lower() or "ot_episode" in line.lower() or "published" in line.lower():
            print(line)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
