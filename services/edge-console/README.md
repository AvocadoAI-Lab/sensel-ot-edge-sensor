# SenseL Edge Console (OT-C1)

本地 Web 管理介面：設定精靈、SenseL 企業邀請碼、註冊測試、連線狀態與事件總覽。

## URL

```text
http://<pi-ip>:8090
```

Lab 範例：`http://192.168.1.123:8090`

## 功能

| 分頁 | 說明 |
|------|------|
| **總覽** | SenseL / 註冊 / MQTT / 擷取 狀態卡 |
| **設定精靈** | Sensor ID、Site、SenseL URL、API Key、**企業邀請碼**、MQTT → 儲存並註冊 |
| **事件** | 最近 OT 安全事件（本地 JSONL） |
| **進階** | MQTT port、TLS 等 |

設定寫入 `data/agent/platform.json`（權限 600），Edge Agent 啟動時自動 overlay 覆蓋 env。

## 首次設定流程

1. 瀏覽器開啟 Edge Console
2. **設定精靈** → 填 Avocado AI **企業邀請碼**
3. SenseL URL：`http://192.168.1.108:8081`
4. **儲存並註冊** → 成功後顯示 `tenant_id`
5. Agent 可自動重啟（需掛載 docker.sock）

## 環境變數

| 變數 | 說明 |
|------|------|
| `EDGE_CONSOLE_PASSWORD` | 非空時需登入（Lab 可留空） |
| `EDGE_CONSOLE_DOCKER_RESTART` | `true` 允許 UI 重啟 agent |
| `EDGE_CONSOLE_AUTO_RESTART_AGENT` | 註冊成功後自動重啟 agent |
| `DEFAULT_SENSEL_API_KEY` | 首次載入預設 API key |

## 安全

- Lab 預設 **無密碼**；正式部署請設 `EDGE_CONSOLE_PASSWORD`
- 僅暴露於 management VLAN / LAN
- 邀請碼不寫入 log；API 回傳遮罩 preview

## 開發

```bash
cd services/edge-console
pip install -r requirements.txt
PLATFORM_CONFIG_PATH=/tmp/platform.json ASSETS_DIR=../../data/assets \
  uvicorn src.main:app --reload --port 8090
```

## Compose

隨主 stack 啟動（`docker-compose.yml` 內 `edge-console` 服務）。
