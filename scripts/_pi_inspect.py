#!/usr/bin/env python3
import paramiko

HOST, USER, PW = "192.168.50.90", "fju", "0000"

c = paramiko.SSHClient()
c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
c.connect(HOST, username=USER, password=PW, timeout=20, look_for_keys=False, allow_agent=False)
cmds = [
    "echo ===DISK===; df -h /home/fju",
    "echo ===MEM===; free -h",
    "echo ===HOME===; du -sh /home/fju/* 2>/dev/null | sort -hr | head -25",
    "echo ===PROCS===; pgrep -af uvicorn; pgrep -af docker; pgrep -af llama || true",
    "echo ===DOCKER===; docker ps -a 2>/dev/null || echo no-docker",
    "echo ===EDGEMED===; ls -la /home/fju/sensel-ot-edge-sensor/services/edgemed/artifacts/eval 2>/dev/null; ls /tmp/edgemed* 2>/dev/null || true",
    "echo ===SENSEL===; ls -d /home/fju/sensel* /home/fju/*sensel* 2>/dev/null || echo no-sensel-dir",
]
for cmd in cmds:
    _, o, e = c.exec_command(cmd, timeout=90)
    print(o.read().decode("utf-8", "replace"))
    err = e.read().decode("utf-8", "replace")
    if err.strip():
        print("ERR:", err)
c.close()
