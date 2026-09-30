#!/usr/bin/env python3
import paramiko, json
c=paramiko.SSHClient()
c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
c.connect('192.168.50.90',username='fju',password='0000',timeout=20,look_for_keys=False,allow_agent=False)
payload=json.dumps({
  "device_id":"ot-edge-pi4",
  "device_type":"medical_aiot",
  "operating_state":"idle",
  "criticality":"high",
  "features":{
    "flow_duration":1.0,
    "packet_rate":10.0,
    "byte_rate":10000.0,
    "syn_count":4.0,
    "ack_count":8.0,
    "connection_rate":500.0,
    "mean_packet_size":300.0,
    "iat_mean":0.08
  },
  "fuse":True
})
cmd=f"curl -s -X POST http://127.0.0.1:8000/api/score -H 'Content-Type: application/json' -d '{payload}' | python3 -m json.tool | head -n 80"
_,o,e=c.exec_command(cmd,timeout=60)
print(o.read().decode('utf-8','replace'))
print(e.read().decode('utf-8','replace'))
_,o2,_=c.exec_command("echo 0000 | sudo -S ls -la /home/fju/sensel-ot-edge-sensor/data/assets/ 2>/dev/null",timeout=20)
print(o2.read().decode())
c.close()
