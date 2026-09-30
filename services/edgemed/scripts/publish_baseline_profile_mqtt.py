"""Publish sensel.baseline.profile.v1 artifacts to Control Plane EMQX for edge-agent sync."""

from __future__ import annotations

import argparse
import json
import sys
import time
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from app.baseline_templates import (
    bind_asset,
    list_templates,
    load_common_rules,
    load_template,
    resolve_profile_for_device_type,
)


def _topic(tenant_id: str, profile_id: str) -> str:
    return f"sensel/{tenant_id}/baseline/{profile_id}"


def publish(
    artifact: dict,
    *,
    host: str,
    port: int,
    tenant_id: str,
    profile_id: str,
    username: str = "",
    password: str = "",
    qos: int = 0,
) -> None:
    try:
        import paho.mqtt.client as mqtt
    except ImportError as exc:
        raise SystemExit("paho-mqtt required: pip install paho-mqtt") from exc

    payload = json.dumps(artifact, ensure_ascii=False).encode("utf-8")
    topic = _topic(tenant_id, profile_id)
    client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id=f"baseline-pub-{uuid.uuid4().hex[:8]}")
    if username:
        client.username_pw_set(username, password or None)

    try:
        client.connect(host, port, keepalive=30)
    except Exception as exc:
        raise RuntimeError(
            f"MQTT connect failed host={host} port={port}: {exc}. "
            "Is EMQX running on the Control Plane PC?"
        ) from exc
    client.loop_start()
    time.sleep(0.5)
    result = client.publish(topic, payload=payload, qos=qos, retain=True)
    time.sleep(2.0 if qos == 0 else 5.0)
    if qos > 0 and not result.is_published():
        if not result.wait_for_publish(timeout=20):
            raise RuntimeError(f"MQTT publish timed out topic={topic}")
    client.loop_stop()
    client.disconnect()
    print(f"Published retain=1 topic={topic} bytes={len(payload)} qos={qos}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--profile-id",
        action="append",
        dest="profile_ids",
        help="Template profile_id (repeatable; default: all catalog templates)",
    )
    parser.add_argument(
        "--device-type",
        default="",
        help="Resolve by device_type instead of profile_id; unknown types fall back to the generic observe-only profile",
    )
    parser.add_argument("--asset-id", default="", help="Optional asset binding (e.g. blink-camera-01)")
    parser.add_argument("--sensor-id", default="ot-edge-pi4")
    parser.add_argument("--site-id", default="factory-lab-pi")
    parser.add_argument("--tenant-id", default="default")
    parser.add_argument("--mqtt-host", default="192.168.50.134")
    parser.add_argument("--mqtt-port", type=int, default=1883)
    parser.add_argument("--mqtt-username", default="")
    parser.add_argument("--mqtt-password", default="")
    parser.add_argument("--qos", type=int, default=0, help="MQTT QoS (lab default 0)")
    args = parser.parse_args()

    if args.device_type.strip():
        common_rules = load_common_rules()
        template, resolution = resolve_profile_for_device_type(args.device_type.strip())
        profile_id = str(template.get("profile_id"))
        artifact = bind_asset(
            template,
            asset_id=args.asset_id.strip() or args.device_type.strip(),
            sensor_id=args.sensor_id,
            site_id=args.site_id,
            tenant_id=args.tenant_id,
            device_type=args.device_type.strip(),
            resolution=resolution,
            common_rules_id=str(common_rules.get("rules_id") or ""),
        )
        print(f"Resolved device_type={args.device_type.strip()} -> {profile_id} ({resolution})")
        publish(
            artifact,
            host=args.mqtt_host,
            port=args.mqtt_port,
            tenant_id=args.tenant_id,
            profile_id=profile_id,
            username=args.mqtt_username,
            password=args.mqtt_password,
            qos=args.qos,
        )
        return 0

    profile_ids = args.profile_ids or [str(item.get("profile_id")) for item in list_templates()]
    for profile_id in profile_ids:
        template = load_template(profile_id)
        if args.asset_id.strip():
            artifact = bind_asset(
                template,
                asset_id=args.asset_id.strip(),
                sensor_id=args.sensor_id,
                site_id=args.site_id,
                tenant_id=args.tenant_id,
            )
        else:
            artifact = dict(template)
            artifact.setdefault("tenant_id", args.tenant_id)
            artifact.setdefault("sensor_id", args.sensor_id)
            artifact.setdefault("site_id", args.site_id)
        publish(
            artifact,
            host=args.mqtt_host,
            port=args.mqtt_port,
            tenant_id=args.tenant_id,
            profile_id=profile_id,
            username=args.mqtt_username,
            password=args.mqtt_password,
            qos=args.qos,
        )
        time.sleep(0.2)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
