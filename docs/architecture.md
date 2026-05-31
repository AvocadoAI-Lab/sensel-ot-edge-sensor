# 架構說明

## 設計原則

> 原始鏡像流量不直接進入 EdgeX。  
> EdgeX 負責遙測正規化與設備資料整合。  
> 被動鏡像流量由 Packet Sensor Agent 專責處理。  
> 僅將解析後的遙測、特徵摘要、異常事件與證據 metadata 送入 EdgeX 或 SenseL。

## 雙路徑資料流

### 主動遙測（EdgeX）

```
OT Device → Device Service → Core Data → App Service → SenseL Telemetry API
```

### 被動鏡像（Packet Sensor）

```
SPAN/TAP → Capture → L2-L7 Parser → Detection → Security Event / Feature Summary
                                              → PCAP Ring Buffer (local)
```

### 特徵摘要橋接

```
Packet Sensor → Local MQTT → EdgeX device-mqtt → Core Data → SenseL
```

## 部署拓撲（Ubuntu / Pi4）

| 介面 | 用途 |
|------|------|
| Management NIC | SenseL 上傳、管理、EdgeX |
| Mirror NIC | SPAN/TAP 唯讀擷取（promiscuous） |

## 元件對照 PRD

| PRD 元件 | 專案路徑 |
|----------|----------|
| EdgeX Stack | `edgex/` |
| Packet Sensor Agent | `services/packet-sensor/` |
| SenseL Edge Agent | `services/sensel-edge-agent/` |
| Local MQTT | `services/mqtt-broker/` |
| 政策 / Baseline | `config/policy/` |
| API Schema | `schemas/` |

## SenseL 平台（另庫擴充）

本 repo 為邊緣感測器；SenseL 平台需新增模組見 PRD §14（OT Dashboard、Asset Inventory 等），建議在 `senseL` 主專案中實作 ingestion API 與 UI。
