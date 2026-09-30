#!/usr/bin/env python3
import paramiko
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
c=paramiko.SSHClient()
c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
c.connect('192.168.50.90',username='fju',password='0000',timeout=20,look_for_keys=False,allow_agent=False)
sftp=c.open_sftp()
sftp.put(str(ROOT/'deploy/pi4/start-native-edgemed.sh'), '/home/fju/sensel-ot-edge-sensor/deploy/pi4/start-native-edgemed.sh')
sftp.close()
_,o,_=c.exec_command("echo 0000 | sudo -S cat /home/fju/sensel-ot-edge-sensor/data/assets/model-runtime.json; echo ---; wc -l /home/fju/sensel-ot-edge-sensor/data/assets/trust-episodes.jsonl; df -h /",timeout=20)
print(o.read().decode('utf-8','replace'))
c.close()
