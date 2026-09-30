#!/usr/bin/env python3
import time
import paramiko

time.sleep(65)
c=paramiko.SSHClient()
c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
c.connect('192.168.50.90',username='fju',password='0000',timeout=20,look_for_keys=False,allow_agent=False)
cmd="""
echo ===RUNTIME===;
cat /home/fju/sensel-ot-edge-sensor/data/assets/model-runtime.json 2>/dev/null || echo no-runtime;
echo ===EPISODES===;
wc -l /home/fju/sensel-ot-edge-sensor/data/assets/trust-episodes.jsonl 2>/dev/null || echo no-episodes;
tail -n 3 /home/fju/sensel-ot-edge-sensor/data/assets/trust-episodes.jsonl 2>/dev/null || true;
echo ===PSLOG===;
tail -n 15 /tmp/packet-sensor.log 2>/dev/null || true;
"""
_,o,_=c.exec_command(cmd,timeout=30)
print(o.read().decode('utf-8','replace'))
c.close()
