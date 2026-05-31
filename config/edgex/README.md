# EdgeX device & profile configs
#
# Mounted into device-modbus and device-mqtt at /custom-config/{devices,profiles}
#
# ## Lab Modbus (S1-02)
#
# - `modbus-simulator` container (`iotechsys/modbus-sim`) listens on **1502**
# - `devices/modbus-relay.yaml` → `relay-01` with 10s autoEvents
# - Verify: `make verify-modbus` (stack must be running)
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
