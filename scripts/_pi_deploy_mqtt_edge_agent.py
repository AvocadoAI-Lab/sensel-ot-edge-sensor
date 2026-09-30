#!/usr/bin/env python3
"""Deploy edge-agent source on Pi, fix data permissions, verify MQTT to PC."""
from __future__ import annotations

import io
import json
import pathlib
import sys
import tarfile
import time

import paramiko

HOST, USER, PW = "192.168.50.90", "fju", "0000"
PC_MQTT_HOST = "192.168.50.134"
REMOTE_ROOT = "/home/fju/sensel-ot-edge-sensor"
AGENT_REMOTE = f"{REMOTE_ROOT}/services/sensel-edge-agent"


def connect() -> paramiko.SSHClient:
    c = paramiko.SSHClient()
    c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    c.connect(HOST, username=USER, password=PW, timeout=20, look_for_keys=False, allow_agent=False)
    return c


def run(cmd: str, timeout: int = 180) -> tuple[str, str]:
    c = connect()
    _, o, e = c.exec_command(cmd, timeout=timeout)
    out = o.read().decode("utf-8", "replace")
    err = e.read().decode("utf-8", "replace")
    c.close()
    return out, err


def upload_bytes(remote_path: str, data: bytes, mode: int = 0o644) -> None:
    c = connect()
    sftp = c.open_sftp()
    with sftp.file(remote_path, "wb") as f:
        f.write(data)
    sftp.chmod(remote_path, mode)
    sftp.close()
    c.close()


def upload_agent_source(repo: pathlib.Path) -> None:
    agent = repo / "services" / "sensel-edge-agent"
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for name in ("src", "sensel", "requirements.txt"):
            path = agent / name
            if path.exists():
                tar.add(path, arcname=name)
    upload_bytes("/tmp/sensel-edge-agent.tgz", buf.getvalue(), mode=0o644)
    out, err = run(
        f"rm -rf {AGENT_REMOTE}/src {AGENT_REMOTE}/sensel {AGENT_REMOTE}/requirements.txt; "
        f"mkdir -p {AGENT_REMOTE}; "
        f"tar -xzf /tmp/sensel-edge-agent.tgz -C {AGENT_REMOTE}",
        timeout=60,
    )
    print(out)
    if err.strip():
        print(err)


def main() -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")

    repo = pathlib.Path(__file__).resolve().parents[1]
    agent_cfg = (repo / "config" / "sensor.pi-edge-agent.yaml").read_text(encoding="utf-8")
    start_sh = (repo / "deploy" / "pi4" / "start-edge-agent.sh").read_text(encoding="utf-8")

    c = connect()
    sftp = c.open_sftp()
    for remote, content, mode in (
        (f"{REMOTE_ROOT}/config/sensor.pi-edge-agent.yaml", agent_cfg, 0o644),
        (f"{REMOTE_ROOT}/deploy/pi4/start-edge-agent.sh", start_sh, 0o755),
    ):
        with sftp.file(remote, "w") as f:
            f.write(content)
        sftp.chmod(remote, mode)
    sftp.close()
    c.close()

    print("==> Upload edge-agent source")
    upload_agent_source(repo)

    print("==> Fix data file permissions (packet-sensor runs as root)")
    out, _ = run(
        f"echo '{PW}' | sudo -S chown -R fju:fju {REMOTE_ROOT}/data/assets {REMOTE_ROOT}/data/agent 2>/dev/null; "
        f"echo '{PW}' | sudo -S chmod -R u+rwX {REMOTE_ROOT}/data/assets {REMOTE_ROOT}/data/agent 2>/dev/null; "
        f"ls -la {REMOTE_ROOT}/data/assets/trust-episodes.jsonl",
        timeout=30,
    )
    print(out)

    print("==> MQTT TCP test Pi -> PC")
    out, _ = run(
        f"python3 - <<'PY'\nimport socket\ns=socket.socket(); s.settimeout(5)\n"
        f"try:\n s.connect(('{PC_MQTT_HOST}', 1883)); print('TCP_OK')\n"
        f"except Exception as e:\n print('TCP_FAIL', e)\n"
        f"finally:\n s.close()\nPY"
    )
    print(out.strip())
    if "TCP_OK" not in out:
        return 1

    print("==> Start edge-agent")
    out, err = run(
        f"CONTROL_PLANE_MQTT_HOST={PC_MQTT_HOST} bash {REMOTE_ROOT}/deploy/pi4/start-edge-agent.sh",
        timeout=300,
    )
    print(out)
    if err.strip():
        print(err)

    print("==> Inject test TrustEpisode")
    test_ep = {
        "schema": "trust_episode.v1",
        "episode_id": f"mqtt-lab-test-{int(time.time())}",
        "sensor_id": "ot-edge-pi4",
        "site_id": "factory-lab-pi",
        "tenant_id": "default",
        "decision": "observe",
        "trust_score": 0.42,
        "summary": "mqtt-lab-inject",
        "observed_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    line = json.dumps(test_ep, ensure_ascii=False)
    out, _ = run(
        f"python3 - <<'PY'\n"
        f"from pathlib import Path\n"
        f"p=Path('{REMOTE_ROOT}/data/assets/trust-episodes.jsonl')\n"
        f"p.parent.mkdir(parents=True, exist_ok=True)\n"
        f"with p.open('a', encoding='utf-8') as f:\n"
        f"    f.write({line!r} + '\\n')\n"
        f"print('injected', {line!r})\n"
        f"PY\n"
        f"sleep 10\n"
        f"tail -n 40 /tmp/sensel-edge-agent.log",
        timeout=60,
    )
    print(out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
