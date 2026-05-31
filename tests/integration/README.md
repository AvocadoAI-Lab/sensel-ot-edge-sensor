# Integration Tests

## 已實作（Sprint 1）

- Edge Agent → SenseL mock server 註冊與健康
- Health 離線緩衝 enqueue
- Modbus lab 設定單元測試（profile / device YAML）

## 待實作

- Packet Sensor → synthetic pcap replay
- MQTT feature summary → EdgeX device-mqtt（需 EdgeX test compose）

## Modbus 遙測驗證（需 Docker stack 運行中）

```bash
make up
make verify-modbus
```

執行：

```bash
make test
# 或
pip install -r tests/requirements.txt -r services/sensel-edge-agent/requirements.txt
PYTHONPATH=services/sensel-edge-agent:services/packet-sensor pytest tests -v
```
