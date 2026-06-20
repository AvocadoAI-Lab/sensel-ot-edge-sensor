<<<<<<< Updated upstream
# SenseL Edge Agent

邊緣與 SenseL 平台的通訊代理。

## 職責

| 模組 | 職責 |
|------|------|
| `api/` | 註冊、事件、遙測、健康 API 客戶端 |
| `policy/` | CTI blacklist HTTP 同步 → `ioc-cache.json`（Track B-S1） |
| `sighting/` | OT-019 → SMB sightings ingest + 離線佇列（Track B-S3） |
| `health/` | Pi 資源、擷取統計、服務狀態 |
| `upload/` | 離線緩衝與重試上傳（NFR-3） |

## 連線韌性（S5 / 階段 2）

- **註冊重試**：未成功 `register` 前，每 `REGISTER_RETRY_SEC`（預設 60，或 `sensel.retry.backoff_sec`）重試；成功後更新 MQTT `tenant_id` 並發布 `state`。
- **北向 MQTT**：斷線或 publish 失敗時指數退避重連（2s～60s）；`on_disconnect` 觸發重建連線。
- **Policy MQTT**（可選）：`reconnect_delay_set` + 主迴圈 `ensure_connected()`。

## API 端點

- `POST /api/v1/edge-sensors/register`
- `POST /api/v1/ot/security-events`
- `POST /api/v1/ot/telemetry`
- `POST /api/v1/edge-sensors/health`

## 執行

```bash
python -m src.main
```

## CTI Policy Sync（Track B-S1）

每 `POLICY_SYNC_INTERVAL_SEC`（預設 60s）自 108 拉取：

`GET {SENSEL_API_URL}/api/v1/feed/{tenant_id}/blacklist.json`

Header：`X-API-Key: {SMB_INTEL_API_KEY}`（Portal 情資 API Key）

輸出：

- `/app/data/ioc-cache.json` — 本地 IoC 索引（ipv4 / domain / hash）
- `/app/data/ioc-cache.stamp` — 供 packet-sensor 偵測重載（B-S2）

環境變數見 repo 根目錄 `.env.example`；亦可於 Edge Console `platform.json` 設定 `smb_intel_api_key`。

## CTI Sighting Report（Track B-S3）

監看 `security-events.jsonl` 中的 **OT-019 / `CTI_IOC_OBSERVED`**，POST 至：

`POST {SENSEL_API_URL}/api/v1/smb/sightings/ingest`

Header：`X-API-Key: {SMB_INTEL_API_KEY}`（與 B-S1 相同，與 ingest secret 分開）

| 項目 | 說明 |
|------|------|
| 觸發 | `CTI_IOC_OBSERVED`（OT-019） |
| 佇列 | `/app/data/sighting-queue.jsonl`（失敗重試，最多 10 次） |
| 偏移 | `/app/data/sighting-events.offset`（獨立於 MQTT 上傳 offset） |
| 週期 | 每 10s drain queue；主迴圈同步處理新事件 |

環境變數：`SIGHTING_REPORT_ENABLED`、`SIGHTING_REPORT_INTERVAL_SEC`、`SMB_INTEL_API_KEY`。

## CTI Policy MQTT（Track B-S5）

訂閱 Control Plane 發佈的黑名單 topic（預設與 northbound 同 broker）：

`sensel/{tenant_id}/policy/blacklist`

| 項目 | 說明 |
|------|------|
| 觸發 | 收到 MQTT JSON artifact（同 HTTP feed） |
| 行為 | 全量替換 `ioc-cache.json` + touch stamp |
| 備援 | HTTP pull 仍每 60s 執行（etag 去重） |
| QoS | 預設 1 |

環境變數：`POLICY_SYNC_MQTT_ENABLED=true`、`POLICY_SYNC_MQTT_HOST`（預設 `CONTROL_PLANE_MQTT_HOST`）、`POLICY_SYNC_MQTT_TOPIC`。

Lab 驗證：`./scripts/publish-track-b-lab-blacklist-mqtt.sh`（需 108 feed 或 inline payload + EMQX 203）。
=======
# SenseL Edge Agent

邊緣與 SenseL 平台的通訊代理。

## 職責

| 模組 | 職責 |
|------|------|
| `api/` | 註冊、事件、遙測、健康 API 客戶端 |
| `policy/` | CTI blacklist HTTP 同步 → `ioc-cache.json`（Track B-S1） |
| `sighting/` | OT-019 → SMB sightings ingest + 離線佇列（Track B-S3） |
| `health/` | Pi 資源、擷取統計、服務狀態 |
| `upload/` | 離線緩衝與重試上傳（NFR-3） |

## 連線韌性（S5 / 階段 2）

- **註冊重試**：未成功 `register` 前，每 `REGISTER_RETRY_SEC`（預設 60，或 `sensel.retry.backoff_sec`）重試；成功後更新 MQTT `tenant_id` 並發布 `state`。
- **北向 MQTT**：斷線或 publish 失敗時指數退避重連（2s～60s）；`on_disconnect` 觸發重建連線。
- **Policy MQTT**（可選）：`reconnect_delay_set` + 主迴圈 `ensure_connected()`。

## API 端點

- `POST /api/v1/edge-sensors/register`
- `POST /api/v1/ot/security-events`
- `POST /api/v1/ot/telemetry`
- `POST /api/v1/edge-sensors/health`

## 執行

```bash
python -m src.main
```

## CTI Policy Sync（Track B-S1）

每 `POLICY_SYNC_INTERVAL_SEC`（預設 60s）自 108 拉取：

`GET {SENSEL_API_URL}/api/v1/feed/{tenant_id}/blacklist.json`

Header：`X-API-Key: {SMB_INTEL_API_KEY}`（Portal 情資 API Key）

輸出：

- `/app/data/ioc-cache.json` — 本地 IoC 索引（ipv4 / domain / hash）
- `/app/data/ioc-cache.stamp` — 供 packet-sensor 偵測重載（B-S2）

環境變數見 repo 根目錄 `.env.example`；亦可於 Edge Console `platform.json` 設定 `smb_intel_api_key`。

## CTI Sighting Report（Track B-S3）

監看 `security-events.jsonl` 中的 **OT-019 / `CTI_IOC_OBSERVED`**，POST 至：

`POST {SENSEL_API_URL}/api/v1/smb/sightings/ingest`

Header：`X-API-Key: {SMB_INTEL_API_KEY}`（與 B-S1 相同，與 ingest secret 分開）

| 項目 | 說明 |
|------|------|
| 觸發 | `CTI_IOC_OBSERVED`（OT-019） |
| 佇列 | `/app/data/sighting-queue.jsonl`（失敗重試，最多 10 次） |
| 偏移 | `/app/data/sighting-events.offset`（獨立於 MQTT 上傳 offset） |
| 週期 | 每 10s drain queue；主迴圈同步處理新事件 |

環境變數：`SIGHTING_REPORT_ENABLED`、`SIGHTING_REPORT_INTERVAL_SEC`、`SMB_INTEL_API_KEY`。

## CTI Policy MQTT（Track B-S5）

訂閱 Control Plane 發佈的黑名單 topic（預設與 northbound 同 broker）：

`sensel/{tenant_id}/policy/blacklist`

| 項目 | 說明 |
|------|------|
| 觸發 | 收到 MQTT JSON artifact（同 HTTP feed） |
| 行為 | 全量替換 `ioc-cache.json` + touch stamp |
| 備援 | HTTP pull 仍每 60s 執行（etag 去重） |
| QoS | 預設 1 |

環境變數：`POLICY_SYNC_MQTT_ENABLED=true`、`POLICY_SYNC_MQTT_HOST`（預設 `CONTROL_PLANE_MQTT_HOST`）、`POLICY_SYNC_MQTT_TOPIC`。

Lab 驗證：`./scripts/publish-track-b-lab-blacklist-mqtt.sh`（需 108 feed 或 inline payload + EMQX 203）。
>>>>>>> Stashed changes
