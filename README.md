# SenseL OT Edge Sensor

> 產品代號：SenseL RelayGuard  
> 邊緣部署的 OT 資安與遙測閘道器，整合 EdgeX 主動遙測與被動鏡像流量監控。

## 架構概覽

```
OT 設備 ──► EdgeX Device Services ──► SenseL Exporter ──► SenseL Platform
     │
     └── SPAN/TAP ──► Packet Sensor Agent ──► 本地偵測（OT 規則 + 選用 Snort/Suricata）──► SenseL Platform
```

**設計原則**：原始鏡像流量不直接進入 EdgeX；被動流量由 Packet Sensor 處理，僅上傳解析後的特徵摘要、安全事件與證據參考。

## 專案結構

| 目錄 | 說明 |
|------|------|
| `edgex/` | EdgeX Foundry 堆疊與 Device/App Services |
| `services/packet-sensor/` | 被動封包擷取、L2–L7 解析、本地異常偵測 |
| `services/packet-sensor/src/detection/external_engine/` | Snort/Suricata 告警橋接（選用） |
| `services/sensel-edge-agent/` | 與 SenseL 平台通訊、政策同步、健康回報 |
| `services/edge-console/` | 本機接入精靈 + 狀態主控台（含引擎/憑證落地狀態） |
| `services/mqtt-broker/` | 本地 MQTT（特徵摘要 → EdgeX device-mqtt） |
| `config/` | 感測器、擷取、政策與 EdgeX 設定 |
| `schemas/` | Telemetry / Security Event / Health JSON Schema |
| `deploy/` | Ubuntu 與 Pi4 部署腳本與網路設定範本 |
| `docs/` | 架構、部署與 API 文件 |

## 快速開始（Ubuntu）

```bash
# 1. 複製環境變數
cp .env.example .env
# 編輯 SENSEL_API_URL、API_KEY、SITE_ID、SENSOR_ID 等

# 2. 複製感測器設定
cp config/sensor.yaml.example config/sensor.yaml

# 3. 啟動完整堆疊
docker compose up -d

# 4. 健康檢查
./scripts/health-check.sh
```

詳見 [docs/deployment-ubuntu.md](docs/deployment-ubuntu.md)。

## 部署目標

| 階段 | 平台 | 說明 |
|------|------|------|
| MVP / Lab | Ubuntu Server 22.04/24.04 | 開發與 PoC 驗證 |
| Field | Raspberry Pi 4 (8GB) | 客戶現場部署 |
| NDR Edge | OpenWrt（x86_64 / ARM64） | 軟體 NDR sensor（FR-001） |

Pi4 部署見 [docs/deployment-pi4.md](docs/deployment-pi4.md)；OpenWrt 部署見 [docs/deployment-openwrt.md](docs/deployment-openwrt.md)。

## NDR 偵測引擎（Snort / Suricata，opt-in）

除內建 OT 規則偵測（OT-001~019）外，可選擇性疊加外部 IDS 引擎作為 sidecar。
兩者皆為**檔案解耦**：sidecar 輸出告警 → packet-sensor 橋接成 SecurityEvent →
與內建事件走同一條北向 / sighting 路徑。未啟用時對既有流程零影響。

| 引擎 | 鏡像 | 架構支援 | 建議硬體 |
|------|------|----------|----------|
| Snort 3 | `ciscotalos/snort3:latest` | **僅 amd64** | x86 ≥ 4GB（Tier 2） |
| Suricata | `jasonish/suricata:latest` | multi-arch（amd64 + **arm64**） | x86 或 ARM（含 Pi4） |

> ⚠️ **ARM / Pi4 注意**：Snort 官方鏡像目前只有 amd64，無法在 Pi4（ARM64）原生執行；
> 在 ARM 上請改用 **Suricata**，或維持內建 OT 偵測。引擎為重量級 sidecar，
> 建議僅在 x86 ≥ 4GB 開啟。

```bash
# Snort（x86）
SNORT_INTERFACE=eth1 \
docker compose -f docker-compose.yml -f docker-compose.snort.yml up -d

# Suricata（x86 或 ARM / Pi4）
SURICATA_INTERFACE=eth1 \
docker compose -f docker-compose.yml -f docker-compose.suricata.yml up -d
```

引擎狀態（運行中 / 規則版本 / 啟用規則數 / 最後更新時間）與已下發的 MQTT 憑證落地狀態，
會顯示在 **Edge Console 接入精靈的「落地狀態」面板**，並回報至 SenseL DMS engine 健康（FR-008）。
CTI-origin sighting 細節見 `docker-compose.snort.yml` / `docker-compose.suricata.yml` 標頭。

## MVP 功能範圍

- [x] 專案骨架與目錄配置
- [x] EdgeX Core + device-mqtt + device-modbus（compose 已合併；Modbus：`make verify-modbus`；MQTT feature summary：`make verify-mqtt`）
- [x] Packet Sensor：Sprint 1 擷取迴圈 + L2/L3 + MVP 規則 OT-001~010（`make verify-mvp`）
- [x] 本地規則偵測（OT-001 ~ OT-010）+ IEC 61850（OT-011~018）
- [x] PCAP ring buffer（記憶體 ring + `evidence_ref`）
- [x] SenseL 健康上傳 + 安全事件上傳（Edge Agent tail JSONL → mock/平台）
- [x] Pi lab Events Viewer（`http://<pi-ip>:8080`，方案 B）
- [x] NDR 引擎橋接：Snort 3 alert_json + Suricata EVE JSON（opt-in sidecar）
- [x] CTI-origin sighting（Snort/Suricata SID 落在 CTI 範圍時上報）
- [x] Control Plane MQTT 憑證自動下發與落地（registration → 持久化 → 重連）
- [x] Edge Console 顯示引擎狀態 / 規則版本 / 憑證落地
- [ ] SenseL 平台 OT Dashboard 整合

## 相關文件

- [架構說明](docs/architecture.md)
- [API 契約](docs/api-contracts.md)
- [偵測規則](docs/detection-rules.md)
- [PRD 摘要](docs/PRD.md)
- [Sprint 規劃](docs/sprint-plan.md)
- [S1-02b IEC 61850 被動 backlog](docs/sprint-s1-02b-iec61850.md)
- [版本發布說明](RELEASE_NOTES.md)

## 授權

Proprietary — SenseL / 內部使用
