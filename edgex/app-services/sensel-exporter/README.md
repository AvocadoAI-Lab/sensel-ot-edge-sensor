# EdgeX App Service — SenseL Exporter

將 EdgeX 標準化讀數推送至 SenseL Telemetry API。

## 輸出

`POST /api/v1/ot/telemetry`

## 實作選項（Sprint 1）

1. EdgeX Application Functions SDK (Go)
2. 可配置 App Service + HTTP export function

## 設定

見 `config/edgex/sensel-exporter.yaml.example`
