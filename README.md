# SenseL OT Edge Sensor

> 產品代號：SenseL RelayGuard  
> 邊緣部署的 OT 資安與遙測閘道器，整合 EdgeX 主動遙測與被動鏡像流量監控。

## 這個分支：`first-principles-redesign` — 為什麼、差在哪、優勢

> 本分支**包含 `hardening-v1` 的全部修補**（偵測已修到可信，見 [hardening-v1.md](docs/hardening-v1.md)），再從第一性原理解決兩個更深的問題。

**為什麼存在**：就算偵測修好了，baseline 仍是「手寫 JSON 的猜測」、偵測狀態全在記憶體（**重啟即告警風暴**）；而且實務上你在拿到設備/SCD 前**根本還沒有 baseline**。本分支讓感測器**沒有 baseline 也能安全上線**，並把 baseline 來源換成工程真相。

**與 `hardening-v1` 的差異**

| 面向 | `hardening-v1` | `first-principles-redesign` |
|------|----------------|-----------------------------|
| baseline 來源 | 手寫 JSON（猜測） | 從工程 **SCD/SCL 自動推導**，或從**觀測學習** |
| 沒有 baseline 時 | 只能空跑 / 誤報 | **learning 模式**：安靜觀測、不告警 |
| 重啟 | 盤點失憶 → 告警風暴 | **狀態持久化（SQLite）**，不再風暴 |
| 兩套 baseline | — | SCD 與觀測**同一 schema**，可 **reconcile** |

**優勢**：**沒 baseline 也能立刻安全部署**（commissioning 學習）；重啟不失憶；baseline **對照工程真相**而非猜測；等真實 SCD 到了能 diff 出「觀測 ≠ 工程」的異常。

📽 **完整模擬流程（真實終端輸出）見 [docs/walkthrough.md](docs/walkthrough.md)**。

## 架構概覽

```
OT 設備 ──► EdgeX Device Services ──► SenseL Exporter ──► SenseL Platform
     │
     └── SPAN/TAP ──► Packet Sensor Agent ──► 本地偵測 ──► SenseL Platform
```

![dual-path architecture](docs/diagrams/architecture.png)

**設計原則**：原始鏡像流量不直接進入 EdgeX；被動流量由 Packet Sensor 處理，僅上傳解析後的特徵摘要、安全事件與證據參考。詳見 [hardening-v1 設計文件](docs/hardening-v1.md)。

## 偵測流程

每個封包先進 PCAP ring buffer（證據保全），再逐層解析、逐條規則評估；速率/離線/靜默類規則掛在每 60s 的 feature window（綠色為 hardening-v1 強化/修正處）：

![detection pipeline](docs/diagrams/detection-pipeline.png)

## Baseline 生命週期

工程的 SCD 與「觀測（學習模式）」兩條源頭，產出**同一個 policy schema**；還沒有 baseline 時可先用 commissioning 學習，等真實 SCD 到了再 reconcile。詳見 [first-principles-redesign 設計文件](docs/first-principles-redesign.md)。

![baseline lifecycle](docs/diagrams/baseline-lifecycle.png)

## 專案結構

| 目錄 | 說明 |
|------|------|
| `edgex/` | EdgeX Foundry 堆疊與 Device/App Services |
| `services/packet-sensor/` | 被動封包擷取、L2–L7 解析、本地異常偵測 |
| `services/sensel-edge-agent/` | 與 SenseL 平台通訊、政策同步、健康回報 |
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

Pi4 部署見 [docs/deployment-pi4.md](docs/deployment-pi4.md)。

## MVP 功能範圍

- [x] 專案骨架與目錄配置
- [x] EdgeX Core + device-mqtt + device-modbus（compose 已合併；Modbus：`make verify-modbus`；MQTT feature summary：`make verify-mqtt`）
- [x] Packet Sensor：Sprint 1 擷取迴圈 + L2/L3 + MVP 規則 OT-001~010（`make verify-mvp`）
- [x] 本地規則偵測（OT-001 ~ OT-010）+ IEC 61850（OT-011~018）
- [x] PCAP ring buffer（記憶體 ring + `evidence_ref`）
- [x] SenseL 健康上傳 + 安全事件上傳（Edge Agent tail JSONL → mock/平台）
- [x] Pi lab Events Viewer（`http://<pi-ip>:8080`，方案 B）
- [ ] SenseL 平台 OT Dashboard 整合

## 相關文件

- [架構說明](docs/architecture.md)
- [API 契約](docs/api-contracts.md)
- [偵測規則](docs/detection-rules.md)
- [PRD 摘要](docs/PRD.md)
- [Sprint 規劃](docs/sprint-plan.md)
- [S1-02b IEC 61850 被動 backlog](docs/sprint-s1-02b-iec61850.md)
- [**hardening-v1 設計文件**（偵測強化、攻擊 lab、含流程圖）](docs/hardening-v1.md)
- [**first-principles-redesign 設計文件**（SCD 攝取、commissioning、含流程圖）](docs/first-principles-redesign.md)

## 授權

Proprietary — SenseL / 內部使用
