#!/usr/bin/env python3
import paramiko
c=paramiko.SSHClient(); c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
c.connect('192.168.50.90', username='fju', password='0000', timeout=20, look_for_keys=False, allow_agent=False)
_,o,_=c.exec_command(
    "ps aux | grep -E 'llama-server|uvicorn|packet-sensor|edge-agent' | grep -v grep; "
    "curl -sf http://127.0.0.1:8000/health | head -c 120; echo",
    timeout=30)
print(o.read().decode('utf-8','replace'))
c.close()
