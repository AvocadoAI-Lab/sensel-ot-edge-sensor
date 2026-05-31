# EdgeX Foundry Integration

EdgeX 4.0 non-secure stack，已合併至根目錄 `docker-compose.yml`（`include: edgex/docker-compose.edgex.yml`）。

## MVP 服務

| 服務 | 容器 | 用途 |
|------|------|------|
| `database` | edgex-postgres | 持久化（PostgreSQL） |
| `mqtt-broker` | edgex-mqtt-broker | EdgeX 內部 Message Bus |
| `core-keeper` | edgex-core-keeper | 設定/registry |
| `core-metadata` | edgex-core-metadata | 設備 metadata |
| `core-data` | edgex-core-data | 事件/讀數 |
| `device-modbus` | edgex-device-modbus | Modbus TCP 遙測 |
| `modbus-simulator` | edgex-modbus-simulator | Lab Modbus TCP 模擬器（port 1502） |
| `device-mqtt` | edgex-device-mqtt | 訂閱 local-mqtt 特徵摘要 |

Lab UI（可選）：`make up-ui` → http://127.0.0.1:4000

## 啟動

```bash
docker compose up -d
# 含 EdgeX UI
docker compose --profile lab-ui up -d
```

## 資料流

```
OT Device → device-modbus → Core Data → (Sprint 3) sensel-exporter → SenseL
Packet Sensor → local-mqtt → device-mqtt → Core Data → SenseL
```

## 設定

| 路徑 | 說明 |
|------|------|
| `config/edgex/devices/` | 設備定義（Modbus / MQTT） |
| `config/edgex/profiles/` | Device Profile YAML |
| `edgex/common-non-security.env` | 非安全模式環境變數 |

`device-mqtt` 的 `MQTTBROKERINFO_HOST` 指向 `local-mqtt`（非 EdgeX 內部 broker），對應 Packet Sensor 特徵摘要橋接。

## 版本

- EdgeX **4.0.0**（Odessa）
- 基於 [edgex-compose v4.0.0](https://github.com/edgexfoundry/edgex-compose) 精簡

## App Service（Sprint 3）

`sensel-exporter` — 將 Core Data 轉發至 SenseL Telemetry API，見 `app-services/sensel-exporter/`。
