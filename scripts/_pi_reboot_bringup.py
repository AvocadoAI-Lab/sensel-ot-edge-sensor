#!/usr/bin/env python3
"""After PC reboot: start Pi edge-agent against host MQTT on port 2883."""

from __future__ import annotations

import sys
from pathlib import Path

import paramiko

HOST, USER, PW = "192.168.50.90", "fju", "0000"
PC, PORT = "192.168.50.134", 2883
ROOT = "/home/fju/sensel-ot-edge-sensor"
LOCAL_ROOT = Path(__file__).resolve().parents[1]


def connect() -> paramiko.SSHClient:
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(
        HOST,
        username=USER,
        password=PW,
        timeout=20,
        look_for_keys=False,
        allow_agent=False,
    )
    return client


def run(cmd: str, timeout: int = 180) -> tuple[str, str]:
    client = connect()
    _, stdout, stderr = client.exec_command(cmd, timeout=timeout)
    out = stdout.read().decode("utf-8", "replace")
    err = stderr.read().decode("utf-8", "replace")
    client.close()
    return out, err


def main() -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")

    print("==> Pi uname")
    out, _ = run("uname -a; hostname")
    print(out)

    print("==> Upload parameterized edge-agent start script")
    client = connect()
    sftp = client.open_sftp()
    sftp.put(
        str(LOCAL_ROOT / "deploy" / "pi4" / "start-edge-agent.sh"),
        f"{ROOT}/deploy/pi4/start-edge-agent.sh",
    )
    sftp.chmod(f"{ROOT}/deploy/pi4/start-edge-agent.sh", 0o755)
    sftp.close()
    client.close()

    print("==> TCP Pi -> PC:2883")
    out, _ = run(
        "python3 - <<'PY'\n"
        "import socket\n"
        "s=socket.socket(); s.settimeout(5)\n"
        "try:\n"
        f"    s.connect(('{PC}', {PORT})); print('TCP_OK')\n"
        "except Exception as e:\n"
        "    print('TCP_FAIL', e)\n"
        "finally:\n"
        "    s.close()\n"
        "PY"
    )
    print(out.strip())
    if "TCP_OK" not in out:
        return 1

    print("==> Start edge-agent")
    out, err = run(
        f"CONTROL_PLANE_MQTT_HOST={PC} CONTROL_PLANE_MQTT_PORT={PORT} "
        f"bash {ROOT}/deploy/pi4/start-edge-agent.sh",
        timeout=300,
    )
    print(out)
    if err.strip():
        print(err)

    print("==> Start native EdgeMed if present")
    out, err = run(
        f"if [ -x {ROOT}/deploy/pi4/start-native-edgemed.sh ]; then "
        f"echo '{PW}' | sudo -S bash {ROOT}/deploy/pi4/start-native-edgemed.sh; "
        f"else echo NO_NATIVE_SCRIPT; fi",
        timeout=180,
    )
    print(out)
    if err.strip():
        print(err)

    print("==> Status")
    out, _ = run(
        "pgrep -af 'src.main|uvicorn app.main|packet-sensor' || true; "
        "echo ---LOG---; tail -n 20 /tmp/sensel-edge-agent.log 2>/dev/null; "
        "echo ---HEALTH---; curl -sf -m 5 http://127.0.0.1:8000/health || echo no_edgemed_health"
    )
    print(out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
