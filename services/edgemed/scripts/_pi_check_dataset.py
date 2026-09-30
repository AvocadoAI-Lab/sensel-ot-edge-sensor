#!/usr/bin/env python3
import paramiko
c=paramiko.SSHClient(); c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
c.connect('192.168.50.90',username='fju',password='0000',timeout=20,look_for_keys=False,allow_agent=False)
cmds=[
 'uname -a; cat /proc/cpuinfo | grep -E "model name|Hardware|Revision" | head -n 5; free -h; df -h /home/fju | tail -n 1',
 'ls -la /home/fju/資料集 2>/dev/null || ls -la /home/fju/dataset 2>/dev/null || ls -la /home/fju/*CIC* 2>/dev/null || ls -la /home/fju/*IoMT* 2>/dev/null || echo NO_DATASET_DIR',
 'find /home/fju -maxdepth 3 -type d -iname "*mqtt*" 2>/dev/null | head; find /home/fju -maxdepth 3 -name "*test*.csv" 2>/dev/null | head',
]
for cmd in cmds:
  print('>>>', cmd[:90])
  _,o,_=c.exec_command(cmd, timeout=60)
  print(o.read().decode('utf-8','replace')[:2000])
c.close()
