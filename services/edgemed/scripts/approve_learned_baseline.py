"""Approve a live-learned candidate and publish it as the active Edge baseline."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from app.baseline_learning import build_learned_profile, synthesize_lab_live_candidate


def _load_candidate(path: Path | None) -> dict:
    if path is None:
        return synthesize_lab_live_candidate()
    raw = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError("candidate must be a JSON object")
    return raw


def _publish_profile(profile: dict, *, host: str, port: int, tenant_id: str) -> None:
    try:
        import paho.mqtt.client as mqtt
    except ImportError as exc:
        raise SystemExit("paho-mqtt required: pip install paho-mqtt") from exc

    payload = json.dumps(profile, ensure_ascii=False).encode("utf-8")
    topic = f"sensel/{tenant_id}/baseline/{profile['profile_id']}"
    client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id=f"learned-pub-{uuid.uuid4().hex[:8]}")
    client.connect(host, port, keepalive=30)
    client.loop_start()
    time.sleep(0.5)
    client.publish(topic, payload=payload, qos=0, retain=True)
    time.sleep(2.0)
    client.loop_stop()
    client.disconnect()
    print(f"Published retain=1 topic={topic} bytes={len(payload)}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--candidate", type=Path, default=None, help="live-observed / candidate JSON; default: lab synthetic")
    parser.add_argument("--device-type", default="unknown_medical_device")
    parser.add_argument("--asset-id", default="unknown-asset-01")
    parser.add_argument("--sensor-id", default="ot-edge-pi4")
    parser.add_argument("--site-id", default="factory-lab-pi")
    parser.add_argument("--tenant-id", default="default")
    parser.add_argument("--profile-id", default="")
    parser.add_argument("--mqtt-host", default="192.168.50.134")
    parser.add_argument("--mqtt-port", type=int, default=1883)
    parser.add_argument("--skip-detect", action="store_true", help="Publish profile only; do not switch mode to detect")
    parser.add_argument(
        "--out",
        type=Path,
        default=ROOT / "artifacts" / "baseline-candidates" / "approved-learned-profile.json",
    )
    args = parser.parse_args()

    candidate = _load_candidate(args.candidate)
    profile = build_learned_profile(
        candidate,
        device_type=args.device_type,
        asset_id=args.asset_id,
        sensor_id=args.sensor_id,
        site_id=args.site_id,
        tenant_id=args.tenant_id,
        profile_id=args.profile_id,
    )
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(profile, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"Wrote approved profile {args.out}")
    _publish_profile(profile, host=args.mqtt_host, port=args.mqtt_port, tenant_id=args.tenant_id)

    if not args.skip_detect:
        time.sleep(1.0)
        result = subprocess.run(
            [
                sys.executable,
                str(ROOT / "scripts" / "publish_operational_mode_mqtt.py"),
                "--mode",
                "detect",
                "--sensor-id",
                args.sensor_id,
                "--site-id",
                args.site_id,
                "--tenant-id",
                args.tenant_id,
                "--baseline-profile-id",
                str(profile["profile_id"]),
                "--baseline-profile-version",
                str(profile["version"]),
                "--mqtt-host",
                args.mqtt_host,
                "--mqtt-port",
                str(args.mqtt_port),
            ],
            cwd=str(ROOT),
            check=False,
        )
        if result.returncode != 0:
            return result.returncode
        print(
            f"Approved live learning for device_type={args.device_type} "
            f"profile_id={profile['profile_id']} mode=detect"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
