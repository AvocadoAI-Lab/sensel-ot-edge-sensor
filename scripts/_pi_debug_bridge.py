#!/usr/bin/env python3
import paramiko
c=paramiko.SSHClient()
c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
c.connect('192.168.50.90',username='fju',password='0000',timeout=20,look_for_keys=False,allow_agent=False)
cmd="""
echo ===PROCS===;
pgrep -af 'src.main|uvicorn' || true;
echo ===RUNTIME===;
cat /home/fju/sensel-ot-edge-sensor/data/assets/model-runtime.json 2>/dev/null || echo none;
echo ===EDGEMED LOG tail===;
tail -n 30 /tmp/edgemed-uvicorn.log 2>/dev/null;
echo ===PS LOG tail===;
tail -n 40 /tmp/packet-sensor.log 2>/dev/null;
"""
_,o,_=c.exec_command(cmd,timeout=30)
print(o.read().decode('utf-8','replace'))
c.close()
