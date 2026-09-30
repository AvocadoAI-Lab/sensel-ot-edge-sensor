#!/usr/bin/env bash
# Inject minimal lab traffic on Pi to trigger Suricata local.rules (sid 1000001/1000002).
# Run on the Pi (traffic egress via eth0 toward the PC / lab subnet).
set -euo pipefail

TARGET="${SURICATA_LAB_TARGET:-192.168.50.134}"
COUNT="${SURICATA_LAB_COUNT:-5}"

echo "==> Suricata lab traffic inject target=${TARGET} count=${COUNT}"

if command -v hping3 >/dev/null 2>&1; then
  echo "-> SYN probes (sid 1000002 OT port probe)"
  for port in 502 102 44818; do
    hping3 -S -p "${port}" -c "${COUNT}" -q "${TARGET}" 2>/dev/null || true
  done
fi

echo "-> TCP connects to Modbus 502 (sid 1000001)"
python3 - <<PY
import socket
target = "${TARGET}"
for _ in range(${COUNT}):
    for port in (502, 445, 3389, 22):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.8)
        try:
            s.connect((target, port))
        except OSError:
            pass
        finally:
            s.close()
PY

if command -v curl >/dev/null 2>&1; then
  echo "-> HTTP curl user-agent probe"
  curl -sf --max-time 2 -A curl "http://${TARGET}/" >/dev/null 2>&1 || true
fi

echo "==> Done. Wait ~5s then check:"
echo "   wc -c ~/sensel-ot-edge-sensor/data/suricata/eve.json"
echo "   tail -1 ~/sensel-ot-edge-sensor/data/assets/suricata-events.jsonl"
