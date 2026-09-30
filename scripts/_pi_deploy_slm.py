#!/usr/bin/env python3
"""Deploy SLM investigate bridge to Pi and restart stack."""
from __future__ import annotations

import io
import json
import stat
import sys
import tarfile
import time
from pathlib import Path

import httpx
import paramiko

HOST, USER, PW = "192.168.50.90", "fju", "0000"
REMOTE_ROOT = "/home/fju/sensel-ot-edge-sensor"
LOCAL_REPO = Path(__file__).resolve().parents[1]
REMOTE_TGZ = "/home/fju/sensel-ot-edge-sensor-slm.tgz"


def connect() -> paramiko.SSHClient:
    c = paramiko.SSHClient()
    c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    c.connect(HOST, username=USER, password=PW, timeout=25, look_for_keys=False, allow_agent=False)
    return c


def run_script(c: paramiko.SSHClient, script: str, timeout: int = 300) -> str:
    remote = "/tmp/sensel_slm_deploy.sh"
    sftp = c.open_sftp()
    with sftp.file(remote, "w") as handle:
        handle.write(script)
    sftp.chmod(remote, stat.S_IRWXU)
    sftp.close()
    _, o, e = c.exec_command(f"bash {remote}", timeout=timeout)
    return o.read().decode("utf-8", "replace") + e.read().decode("utf-8", "replace")


def build_tarball() -> bytes:
    entries = [
        "config/sensor.pi-edgemed.yaml",
        "config/model/edgemed-feature-mapping.ot-window-pi-lab-v1.json",
        "config/model/feature-contract.ot-window-pi-lab-v1.json",
        "deploy/pi4/start-native-edgemed.sh",
    ]
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as tar:
        for rel in entries:
            path = LOCAL_REPO / rel
            tar.add(path, arcname=rel)
        src_root = LOCAL_REPO / "services/packet-sensor/src"
        for path in src_root.rglob("*"):
            if path.is_dir() or "__pycache__" in path.parts or path.suffix == ".pyc":
                continue
            rel = path.relative_to(LOCAL_REPO / "services/packet-sensor")
            tar.add(path, arcname=str(Path("services/packet-sensor") / rel))
    return buffer.getvalue()


def main() -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")

    payload = build_tarball()
    print(f"bundle={len(payload)/1024:.1f}KB", flush=True)

    c = connect()
    sftp = c.open_sftp()
    with sftp.file(REMOTE_TGZ, "wb") as remote:
        remote.write(payload)
    sftp.close()

    print(run_script(
        c,
        f"""
set -e
mkdir -p {REMOTE_ROOT}
tar -xzf {REMOTE_TGZ} -C {REMOTE_ROOT}
chmod +x {REMOTE_ROOT}/deploy/pi4/start-native-edgemed.sh
echo '{PW}' | sudo -S bash {REMOTE_ROOT}/deploy/pi4/start-native-edgemed.sh
""",
        timeout=180,
    ), flush=True)
    c.close()

    for i in range(30):
        try:
            health = httpx.get(f"http://{HOST}:8000/health", timeout=10).json()
            slm = health.get("components", {}).get("slm", {})
            print(f"health {i}: status={health.get('status')} slm={slm}", flush=True)
            break
        except Exception as exc:
            print(f"health {i}: {exc}", flush=True)
            time.sleep(3)

    # Manual investigate smoke test
    body = {
        "device_id": "ot-edge-pi4",
        "device_type": "medical_aiot",
        "operating_state": "idle",
        "criticality": "high",
        "features": {
            "flow_duration": 1.0,
            "packet_rate": 84.0,
            "byte_rate": 25000.0,
            "syn_count": 2.0,
            "ack_count": 8.0,
            "connection_rate": 6.0,
            "mean_packet_size": 320.0,
            "iat_mean": 0.08,
        },
    }
    scored = httpx.post(f"http://{HOST}:8000/api/score", json={**body, "fuse": True}, timeout=60).json()
    inv = httpx.post(
        f"http://{HOST}:8000/api/investigate",
        json={"event_id": scored["event_id"]},
        timeout=120,
    ).json()
    event = inv["event"]
    assessment = event.get("assessment") or {}
    print(
        "investigate:",
        json.dumps(
            {
                "event_id": event.get("event_id"),
                "generation_status": assessment.get("generation_status"),
                "summary": (assessment.get("summary") or "")[:160],
                "slm": inv.get("slm"),
            },
            ensure_ascii=False,
        ),
        flush=True,
    )

    print("waiting 70s for packet-sensor feature window...", flush=True)
    time.sleep(70)
    c = connect()
    out = run_script(
        c,
        f"""
echo 0000 | sudo -S tail -n 1 {REMOTE_ROOT}/data/assets/trust-episodes.jsonl 2>/dev/null || true
echo ---
echo 0000 | sudo -S tail -n 8 /tmp/packet-sensor.log 2>/dev/null || true
""",
        timeout=60,
    )
    print(out, flush=True)
    c.close()
    print("PI_SLM_DEPLOY_OK", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
