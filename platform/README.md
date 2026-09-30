# SenseL Platform Extensions（參考）

邊緣感測器上傳的資料由 **SenseL 主平台**（`/Users/ericmao/senseL` 或獨立 backend）消費。

## PRD §14 待實作模組

| 模組 | 說明 |
|------|------|
| OT Edge Sensor Management | 感測器註冊、清單、政策版本 |
| OT Asset Inventory | MAC/IP/協定/風險 |
| OT Network Behavior Baseline | 行為基線 |
| OT Security Events | 事件時間軸 |
| OT Telemetry Timeline | 遙測與特徵摘要 |
| OT Evidence Viewer | PCAP 按需下載 |
| Edge Policy Management | Allowlist 下發 |
| AI Incident Summary | 事件關聯解釋 |

## Ingestion API

實作於 SenseL backend，契約見 `schemas/` 與 `docs/api-contracts.md`。

本 repo **不包含** 平台 UI/backend 程式碼，避免與邊緣部署耦合。
