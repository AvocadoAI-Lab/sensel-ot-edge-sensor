# SenseL EdgeX Console

本地 Web 管理介面：**SenseL EdgeX** 品牌 UI、設定精靈、EdgeX 設備管理、即時流量與安全事件。

## URL

```text
http://<pi-ip>:8090
```

Lab：`http://192.168.1.123:8090`

## 分頁

| 分頁 | 說明 |
|------|------|
| **總覽** | 狀態卡 · **Telemetry Flow** 趨勢 · **Policy Status** 環形 gauge |
| **EdgeX 平台** | 服務健康、Message Bus、重啟 device 服務 |
| **設備與協定** | 協定矩陣 · **被動發現** · 新增設備精靈 · EdgeX 設備表 |
| **設定精靈** | 感測器身分、SenseL 註冊、企業邀請碼 |
| **安全事件** | 本地 JSONL · **來源 IP / 關聯 EdgeX 設備** |
| **偵測政策** | **唯讀** — 目前套用的 `rules_enabled`、MMS 白名單（來自 Portal MQTT） |
| **即時流量** | Mirror 鏡像每秒更新 |
| **進階** | 北向、擷取、Console 密碼、**審計 log** |

## 首次設定

1. 開啟 Console → **設定精靈**
2. 填 SenseL URL、API Key、**企業邀請碼**
3. **儲存並註冊** → 記下 `tenant_id`
4. **總覽** 確認 Policy / Telemetry 正常
5. **設備與協定** → 檢視被動發現、必要時 **＋ 新增設備**

## Phase 2（OPC UA / S7）

```bash
docker compose ... --profile phase2 up -d device-opc-ua device-s7
```

或在 Console **設備與協定** 點 **啟用 Phase 2 服務**。

## 環境變數

| 變數 | 說明 |
|------|------|
| `EDGE_CONSOLE_PASSWORD` | 非空時需登入（**正式部署必填**） |
| `EDGE_CONSOLE_PASSWORD_FILE` | 密碼檔路徑（預設 `/data/agent/console.password`） |
| `EDGE_CONSOLE_AUDIT_LOG` | 審計 JSONL（預設 `/data/agent/console-audit.jsonl`） |
| `EDGE_CONSOLE_DOCKER_RESTART` | 允許 UI 重啟容器 |
| `EDGEX_CORE_DATA_URL` / `EDGEX_CORE_METADATA_URL` | EdgeX 代理 |
| `EDGEX_DEVICES_DIR` | 設備 YAML 目錄（可寫入） |

## 正式部署（production overlay）

```bash
export EDGE_CONSOLE_PASSWORD='your-strong-password-min-8-chars'
docker compose -f docker-compose.yml -f docker-compose.pi4.yml \
  -f docker-compose.pi-production.yml up -d
```

`docker-compose.pi-production.yml` 會強制要求設定 `EDGE_CONSOLE_PASSWORD`。

## 安全

- Lab 可無密碼；**正式環境務必設密碼**
- 審計記錄：登入/登出、改密、設備 CRUD、容器重啟、Phase2 啟用
- 僅暴露於 management VLAN
- 邀請碼與 API key 不回傳明文

## API（摘錄）

| 路徑 | 說明 |
|------|------|
| `GET /api/status` | 總覽（含 `policy_gauge`、`telemetry`、`northbound` agent 快照） |
| `GET /api/detection-policy/applied` | 唯讀：目前套用的 OT 偵測政策（`detection-policy.json`） |
| `GET /api/edgex/discovery` | Mirror + EdgeX 資產合併 |
| `GET /api/events/recent` | 事件（含 `matched_device`） |
| `GET /api/audit/recent` | 審計記錄 |
| `POST /api/edgex/config/devices` | 新增設備 YAML |

## 開發

```bash
cd services/edge-console
pip install -r requirements.txt
PLATFORM_CONFIG_PATH=/tmp/platform.json ASSETS_DIR=../../data/assets \
  uvicorn src.main:app --reload --port 8090
```

## 驗證

```bash
EDGE_CONSOLE_URL=http://192.168.1.123:8090 ./scripts/verify-edge-console-edgex.sh
EDGE_CONSOLE_URL=http://192.168.1.123:8090 ./scripts/verify-edge-console-traffic.sh
EDGE_CONSOLE_URL=http://192.168.1.123:8090 ./scripts/verify-edge-console-detection-policy.sh
```

## Lab 流量控制（草案）

UI 控制本機 GOOSE/MMS publisher 與擷取 start/stop：見 [docs/edge-console-lab-traffic-control.md](../../docs/edge-console-lab-traffic-control.md)。

```bash
EDGE_CONSOLE_URL=http://192.168.1.123:8090 ./scripts/verify-edge-console-lab-traffic.sh
```

