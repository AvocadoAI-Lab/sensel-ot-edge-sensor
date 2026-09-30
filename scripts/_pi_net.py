#!/usr/bin/env python3
import paramiko
c=paramiko.SSHClient()
c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
c.connect('192.168.50.90',username='fju',password='0000',timeout=20,look_for_keys=False,allow_agent=False)
_,o,_=c.exec_command('ip -br link; ip -br addr; python3 --version; which docker || true')
print(o.read().decode())
c.close()
