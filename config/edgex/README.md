# EdgeX device & profile configs
#
# Default `devices/` + `profiles/` mount into device-modbus and device-mqtt.
#
# ## IEC 61850 lab (Pi / mirror lab) — recommended
#
# Use overlay `docker-compose.lab-61850.yml`:
#
# - **Only** `config/edgex/lab-61850/` → `device-mqtt` (`packet-sensor-features`)
# - `device-modbus` + `modbus-simulator` → profile **`modbus-lab`** (off by default)
# - OPC UA / S7 → profile **`phase2`** (off by default)
# - Apply / repair: `./scripts/apply-lab-61850-edgex.sh [user@pi]`
#
# ## Lab Modbus (S1-02, optional)
#
# - `docker compose --profile modbus-lab up -d device-modbus modbus-simulator`
# - Copy `devices/modbus-relay.example.yaml` → `devices/modbus-relay.yaml` (must include `serviceName: device-modbus`)
# - Verify: `make verify-modbus`
#
# ## Field deploy
#
# Edit `devices/modbus-relay.yaml`:
# - `Address`: relay IP/hostname
# - `Port`: `502`
# Disable `modbus-simulator` in compose or scale to 0.
#
# ## Feature summary MQTT bridge (S1-03)
#
# - Packet Sensor → `incoming/data/packet-sensor-features/FeatureSummary` on `local-mqtt`
# - `devices/mqtt-feature-summary.yaml` → `packet-sensor-features`
# - Verify: `make verify-mqtt`
#
# ## Phase 2 — OPC UA & S7
#
# - Profiles: `profiles/opcua-sample.yaml`, `profiles/s7-sample.yaml`
# - Examples: `devices/opcua-sample.example.yaml`, `devices/s7-sample.example.yaml`
# - Compose: `docker compose --profile phase2 up -d device-opc-ua device-s7`
# - Edge Console「設備與協定」：新增設備、連線診斷、啟用 Phase 2
