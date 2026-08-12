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
| `edgex/` | Core Metadata inventory、desired-state reconciliation、observed outbox |

## EdgeX device management（P2-A）

EdgeX Core Metadata 是 site 內的 device registry，Edge Agent 是 Control Plane desired state 寫入 EdgeX 的唯一 writer。packet-sensor 的鏡像封包分析不經 EdgeX，所以 metadata 暫時不可用不會中斷 OT 偵測。

| 方向 | MQTT 5 topic | Protobuf message | 行為 |
|------|--------------|------------------|------|
| Edge → Tier 3 | `sensel/{tenant}/{site}/{sensor}/inventory/v1` | `InventorySnapshot` | EdgeX device/profile + manual/probe/passive evidence；內容 revision 去重 |
| Tier 3 → Edge | `sensel/{tenant}/{site}/{sensor}/device/desired/v1` | `DesiredDeviceStateCommand` | QoS 1 retained；驗 route、expiry、revision 與 sampling allowlist |
| Edge → Tier 3 | `sensel/{tenant}/{site}/{sensor}/device/observed/v1` | `ObservedDeviceStateReport` | durable SQLite outbox；回報 applied/no-change/rejected/failed |

Reconciler 只允許修改 `adminState` 與既有 `autoEvents.interval`；不修改 protocol endpoint、device profile，也不發 OT read/write command。`QUARANTINED` 與 `RETIRED` 一律映射為 `LOCKED`。

主要環境變數：`EDGEX_DEVICE_MANAGEMENT_ENABLED`、`EDGEX_CORE_METADATA_URL`、`EDGEX_INVENTORY_INTERVAL_SEC`、`EDGEX_DESIRED_MQTT_ENABLED`。狀態可從 `/app/data/agent-runtime.json` 的 `edgex_device_management` 查看。

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

## OT 防護管理中心：IDS 規則派送（EPIC B 邊緣端）

接收工控安全防護管理中心下派的 **自訂 Snort/Suricata 規則檔**，採 MQTT manifest 通知 + HTTP 拉檔（大檔走 HTTP），套用前驗 HMAC 簽章、套用後 reload 健檢、失敗自動回滾（PRD D4 第 2 段）。

- MQTT：`sensel/{tenant_id}/policy/ids-rules-+`（由 topic 後綴解析 engine 觸發拉取）
- HTTP：`GET {SENSEL_API_URL}/api/v1/feed/{tenant_id}/ot-rules.rules?engine={engine}`（`X-API-Key` + `If-None-Match`/304）
- 簽章：驗 `X-Signature`（HMAC，金鑰由 `SENSEL_API_KEY` 派生，與平台共用），失敗即拒絕套用

| 項目 | 說明 |
|------|------|
| 寫入 | `{IDS_RULE_TARGET_DIR}/{engine}.rules`（原子寫入，先備份 `.bak`） |
| 健檢 | `IDS_RULE_RELOAD_CMD`（可選 no-op）→ **`IDS_RULE_HEALTHCHECK_CMD`（必填**，如 `suricata -T -S {path}`；`{engine}`/`{path}` 可代入） |
| 回滾 | reload 或健檢失敗時還原前一版並重載，狀態標記 `rolled_back` |
| 狀態 | `/app/data/ids-rule-status.json`（逐 engine 的 version/etag/ok/rolled_back/rejected_version） |
| 備援 | 每 `IDS_RULE_INTERVAL_SEC`（預設 300s）HTTP 重拉（etag 去重） |

環境變數：`IDS_RULE_ENABLED`（預設 true）、`IDS_RULE_ENGINES`（逗號分隔，預設 `suricata`）、`IDS_RULE_RELOAD_CMD`、`IDS_RULE_HEALTHCHECK_CMD`、`IDS_RULE_TARGET_DIR`、`IDS_RULE_CMD_TIMEOUT_SEC`、`OT_FEED_SIGNING_SECRET`（預設取 `SENSEL_API_KEY`）。

> reload 容器化範例：將 `config/suricata/rules` 掛入本容器並設 `IDS_RULE_TARGET_DIR=/etc/suricata/rules`、`IDS_RULE_RELOAD_CMD="suricatasc -c reload-rules"`、`IDS_RULE_HEALTHCHECK_CMD="suricata -T -c /etc/suricata/suricata.yaml"`。**未設 `IDS_RULE_HEALTHCHECK_CMD` 時套用會拒絕並 NACK**（G15）；`IDS_RULE_RELOAD_CMD` 可留空（no-op）。

### ACK/NACK 北向回報（閉合 D4 迴圈）

每次規則／名單套用後，將結果回報至北向 topic `ot-edge/{tenant}/{site}/{sensor}/policy/ack/v1`（QoS 1）：

| outcome | 觸發 |
|---------|------|
| `ack` / `applied` | 套用成功（reload + 健檢通過） |
| `nack` / `rolled_back` | reload 或健檢失敗，已還原前一版 |
| `nack` / `rejected` | 無前一版可還原，或 **簽章驗證失敗** |

冪等（304／內容未變）不回報。Control Plane 可據此把派送紀錄由「已送出」更新為「已套用／已回滾」。

**HTTP fallback**：MQTT 北向不可用（或停用）時，`PolicyAckReporter` 會直接 `POST {SENSEL_API_URL}{POLICY_ACK_INGEST_PATH}`（預設 `/api/v1/internal/ot-security/policy-ack`），帶 `X-Ot-Security-Ingest-Secret`，確保派送紀錄仍能收斂。MQTT 可用時優先走匯流排。

環境變數：`POLICY_ACK_HTTP_FALLBACK_ENABLED`（預設 true）、`POLICY_ACK_INGEST_PATH`、`OT_SECURITY_INGEST_SECRET`（未設時回退 `OT_EDGE_SENSOR_API_KEY` / `SENSEL_API_KEY`）。

## OT 防護管理中心：管理黑白名單派送（EPIC C 邊緣端）

接收後台管理的黑/白名單（`blacklist`=偵測、`whitelist`=排除），與 CTI `blacklist.json`（IoC）分開。

- MQTT：`sensel/{tenant_id}/policy/listfiles`
- HTTP：`GET {SENSEL_API_URL}/api/v1/feed/{tenant_id}/listfiles.json`（驗 `X-Signature`）
- 輸出：`/app/data/managed-listfiles.json`（`deny`/`allow` × ip/cidr/domain/hash）+ `.stamp`
- **消費端**：`ManagedListfileEnforcer` 在 packet-sensor 偵測（OT-019/MVP）與 edge-agent 北向上傳前排除白名單命中（G6）

環境變數：`LISTFILE_ENABLED`（預設 true）、`LISTFILE_INTERVAL_SEC`、`LISTFILE_CACHE_PATH`、`LISTFILE_MQTT_ENABLED`。
