import sys
import time
import uuid

import paho.mqtt.client as mqtt

host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
qos = int(sys.argv[2]) if len(sys.argv) > 2 else 0
client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id=f"probe-{uuid.uuid4().hex[:6]}")
client.connect(host, 1883, 60)
client.loop_start()
time.sleep(0.5)
result = client.publish("sensel/default/baseline/test-probe", b'{"probe": true}', qos=qos, retain=True)
time.sleep(2)
print(f"host={host} qos={qos} rc={result.rc} published={result.is_published()}")
client.loop_stop()
client.disconnect()
