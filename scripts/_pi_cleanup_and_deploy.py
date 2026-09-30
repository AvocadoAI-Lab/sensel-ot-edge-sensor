#!/usr/bin/env python3
"""Clean redundant Pi data and deploy native SenseL packet-sensor + EdgeMed bridge."""

from __future__ import annotations

import io
import stat
import sys
import tarfile
import time
from pathlib import Path

import httpx
import paramiko

HOST, USER, PW = "192.168.50.90", "fju", "0000"
REMOTE_ROOT = "/home/fju/sensel-ot-edge-sensor"
REMOTE_TGZ = "/home/fju/sensel-ot-edge-sensor-deploy.tgz"
LOCAL_REPO = Path(__file__).resolve().parents[1]


def connect() -> paramiko.SSHClient:
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(
        HOST,
        username=USER,
        password=PW,
        timeout=25,
        look_for_keys=False,
        allow_agent=False,
        banner_timeout=40,
    )
    transport = client.get_transport()
    if transport:
        transport.set_keepalive(20)
    return client


def run(client: paramiko.SSHClient, cmd: str, *, timeout: int = 600) -> str:
    _, stdout, stderr = client.exec_command(cmd, timeout=timeout)
    out = stdout.read().decode("utf-8", "replace")
    err = stderr.read().decode("utf-8", "replace")
    if err.strip():
        out += f"\n[stderr]\n{err}"
    return out


def run_script(client: paramiko.SSHClient, script: str, *, timeout: int = 900) -> str:
    remote = "/tmp/sensel_deploy_step.sh"
    sftp = client.open_sftp()
    with sftp.file(remote, "w") as handle:
        handle.write(script)
    sftp.chmod(remote, stat.S_IRWXU)
    sftp.close()
    return run(client, f"bash {remote}", timeout=timeout)


def cleanup(client: paramiko.SSHClient) -> None:
    print("==> Cleaning redundant Pi data", flush=True)
    print(
        run_script(
            client,
            """
set -e
echo BEFORE:
du -sh /home/fju/* 2>/dev/null | sort -hr | head -15 || true
rm -rf /home/fju/dataset
rm -f /home/fju/ciciomt_test_full.tgz /home/fju/edgemed-pi-deploy.tgz
rm -f /home/fju/sensel-ot-edge-sensor/services/edgemed/artifacts/eval/full_eval_stream.log
rm -f /home/fju/sensel-ot-edge-sensor/services/edgemed/artifacts/eval/full_eval_stream.pid
rm -f /home/fju/sensel-ot-edge-sensor/services/edgemed/artifacts/eval/full_eval_stream.done
find /home/fju/sensel-ot-edge-sensor/services/edgemed -type d -name __pycache__ -prune -exec rm -rf {{}} + 2>/dev/null || true
echo AFTER:
du -sh /home/fju/* 2>/dev/null | sort -hr | head -15 || true
df -h /home/fju
""",
        ),
        flush=True,
    )


def build_tarball() -> bytes:
    entries: list[tuple[str, Path]] = [
        ("config/policy/baseline.example.json", LOCAL_REPO / "config" / "policy" / "baseline.example.json"),
        ("config/sensor.pi-edgemed.yaml", LOCAL_REPO / "config" / "sensor.pi-edgemed.yaml"),
        ("services/packet-sensor/requirements.txt", LOCAL_REPO / "services" / "packet-sensor" / "requirements.txt"),
        ("deploy/pi4/start-native-edgemed.sh", LOCAL_REPO / "deploy" / "pi4" / "start-native-edgemed.sh"),
    ]
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as tar:
        model_dir = LOCAL_REPO / "config" / "model"
        for path in model_dir.rglob("*"):
            if path.is_dir():
                continue
            arcname = str(Path("config/model") / path.relative_to(model_dir))
            tar.add(path, arcname=arcname)
        for arcname, path in entries:
            if not path.is_file():
                raise FileNotFoundError(path)
            tar.add(path, arcname=arcname)
        src_root = LOCAL_REPO / "services" / "packet-sensor" / "src"
        for path in src_root.rglob("*"):
            if path.is_dir():
                continue
            if "__pycache__" in path.parts or path.suffix == ".pyc":
                continue
            rel = path.relative_to(LOCAL_REPO / "services" / "packet-sensor")
            tar.add(path, arcname=str(Path("services/packet-sensor") / rel))
    return buffer.getvalue()


def upload_and_install(client: paramiko.SSHClient, payload: bytes) -> None:
    print("==> Uploading deployment bundle", flush=True)
    sftp = client.open_sftp()
    with sftp.file(REMOTE_TGZ, "wb") as remote:
        remote.write(payload)
    sftp.close()

    print(
        run_script(
            client,
            f"""
set -e
rm -rf {REMOTE_ROOT}
mkdir -p {REMOTE_ROOT}
tar -xzf {REMOTE_TGZ} -C {REMOTE_ROOT}
chmod +x {REMOTE_ROOT}/deploy/pi4/start-native-edgemed.sh
mkdir -p {REMOTE_ROOT}/data/assets {REMOTE_ROOT}/data/agent {REMOTE_ROOT}/data/pcap
cp {REMOTE_ROOT}/config/policy/baseline.example.json {REMOTE_ROOT}/config/policy/baseline.json
cd {REMOTE_ROOT}/services/packet-sensor
python3 -m venv .venv
. .venv/bin/activate
pip install -U pip wheel
pip install -r requirements.txt
""",
            timeout=900,
        ),
        flush=True,
    )


def start_stack(client: paramiko.SSHClient) -> None:
    print("==> Starting EdgeMed + packet-sensor", flush=True)
    print(
        run_script(
            client,
            f"""
set -e
echo '{PW}' | sudo -S bash {REMOTE_ROOT}/deploy/pi4/start-native-edgemed.sh
""",
            timeout=120,
        ),
        flush=True,
    )


def verify() -> None:
    print("==> Verifying from PC", flush=True)
    for attempt in range(20):
        try:
            health = httpx.get(f"http://{HOST}:8000/health", timeout=8).json()
            print(f"EdgeMed health: {health.get('status')} degraded={health.get('degraded_components')}", flush=True)
            break
        except Exception as exc:
            print(f"health attempt {attempt}: {exc}", flush=True)
            time.sleep(3)
    else:
        raise RuntimeError("EdgeMed health check failed")

    client = connect()
    out = run(
        client,
        "bash -lc 'sleep 5; pgrep -af uvicorn; pgrep -af src.main; "
        "tail -n 20 /tmp/packet-sensor.log 2>/dev/null || true; "
        "tail -n 10 /tmp/edgemed-uvicorn.log 2>/dev/null || true; "
        "ls -la /home/fju/sensel-ot-edge-sensor/data/assets/model-runtime.json 2>/dev/null || true'",
        timeout=60,
    )
    print(out, flush=True)
    client.close()


def main() -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    payload = build_tarball()
    print(f"Bundle size: {len(payload)/1024/1024:.2f} MB", flush=True)
    client = connect()
    try:
        cleanup(client)
        upload_and_install(client, payload)
        start_stack(client)
    finally:
        client.close()
    verify()
    print("PI_DEPLOY_OK", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
