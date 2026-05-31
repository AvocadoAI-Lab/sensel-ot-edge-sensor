# API 契約（Edge ↔ SenseL）

JSON Schema 定義於 `schemas/`。

## 端點摘要

| 方法 | 路徑 | 用途 |
|------|------|------|
| POST | `/api/v1/edge-sensors/register` | 感測器註冊 |
| POST | `/api/v1/ot/telemetry` | 遙測與設備讀數 |
| POST | `/api/v1/ot/security-events` | 安全事件 |
| POST | `/api/v1/edge-sensors/health` | 健康狀態 |

## 認證

- TLS 必填（NFR-1）
- Header: `Authorization: Bearer <API_KEY>` 或站點憑證

## 上傳路徑

1. **EdgeX App Service** → Telemetry API（主動遙測）
2. **SenseL Edge Agent** → Events / Health / 離線緩衝重試
3. **MQTT over TLS**（可選，大量特徵摘要）

## 證據上傳

- 預設僅上傳 `evidence_ref`（如 `local-ringbuffer://...`）
- 完整 PCAP 需平台/policy 明確觸發 on-demand upload

## 範例

見 PRD §16 與 `tests/fixtures/`。
