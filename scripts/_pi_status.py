#!/usr/bin/env python3
import paramiko
c=paramiko.SSHClient()
c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
c.connect('192.168.50.90',username='fju',password='0000',timeout=20,look_for_keys=False,allow_agent=False)
cmds=[
 'ls -la /home/fju/sensel-ot-edge-sensor 2>/dev/null | head',
 'test -x /home/fju/sensel-ot-edge-sensor/services/packet-sensor/.venv/bin/python && echo venv_ok || echo venv_missing',
 'pgrep -af uvicorn; pgrep -af src.main || true',
]
for cmd in cmds:
 _,o,_=c.exec_command(cmd,timeout=30)
 print(o.read().decode('utf-8','replace'))
c.close()
