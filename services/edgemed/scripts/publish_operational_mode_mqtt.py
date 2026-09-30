"""Publish sensel.operational_mode.v1 artifacts to Edge via MQTT."""

from __future__ import annotations

import argparse
import json
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _topic(tenant_id: str, sensor_id: str) -> str:
    return f"sensel/{tenant_id}/cmd/{sensor_id}/operational"


def publish(
    artifact: dict,
    *,
    host: str,
    port: int,
    tenant_id: str,
    sensor_id: str,
    username: str = "",
    password: str = "",
    qos: int = 0,
) -> None:
    try:
        import paho.mqtt.client as mqtt
    except ImportError as exc:
        raise SystemExit("paho-mqtt required: pip install paho-mqtt") from exc

    payload = json.dumps(artifact, ensure_ascii=False).encode("utf-8")
    topic = _topic(tenant_id, sensor_id)
    client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id=f"opmode-pub-{uuid.uuid4().hex[:8]}")
    if username:
        client.username_pw_set(username, password or None)
    client.connect(host, port, keepalive=30)
    client.loop_start()
    time.sleep(0.5)
    client.publish(topic, payload=payload, qos=qos, retain=True)
    time.sleep(2.0)
    client.loop_stop()
    client.disconnect()
    print(f"Published retain=1 topic={topic} mode={artifact.get('mode')} bytes={len(payload)}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", required=True, choices=["listen", "learning", "detect", "idle"])
    parser.add_argument("--sensor-id", default="ot-edge-pi4")
    parser.add_argument("--site-id", default="factory-lab-pi")
    parser.add_argument("--tenant-id", default="default")
    parser.add_argument("--session-id", default="")
    parser.add_argument("--baseline-profile-id", default="")
    parser.add_argument("--baseline-profile-version", default="")
    parser.add_argument("--capture-interface", default="eth0")
    parser.add_argument("--mqtt-host", default="192.168.50.134")
    parser.add_argument("--mqtt-port", type=int, default=1883)
    parser.add_argument("--mqtt-username", default="")
    parser.add_argument("--mqtt-password", default="")
    args = parser.parse_args()

    session_id = args.session_id.strip()
    if args.mode in {"listen", "learning"} and not session_id:
        session_id = f"lab-{args.mode}-{uuid.uuid4().hex[:8]}"

    artifact = {
        "schema": "sensel.operational_mode.v1",
        "schema_version": "sensel.operational_mode.v1",
        "tenant_id": args.tenant_id,
        "sensor_id": args.sensor_id,
        "site_id": args.site_id,
        "mode": args.mode,
        "session_id": session_id or None,
        "baseline_profile_id": args.baseline_profile_id or None,
        "baseline_profile_version": args.baseline_profile_version or None,
        "capture": {"interface": args.capture_interface, "bpf_filter": ""},
        "version": _utc_now(),
        "updated_at": _utc_now(),
    }
    publish(
        artifact,
        host=args.mqtt_host,
        port=args.mqtt_port,
        tenant_id=args.tenant_id,
        sensor_id=args.sensor_id,
        username=args.mqtt_username,
        password=args.mqtt_password,
    )
    if session_id:
        print(f"session_id={session_id}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
