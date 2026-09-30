# PRD — OT Baseline 基線生命週期機制

> 產品：SenseL OT Edge Sensor — Edge Console「偵測與政策 / Baseline Management」
> 文件版本：1.0　|　最後更新：2026-06-10　|　狀態：MVP-1 + MVP-2 已上線（Pi `192.168.1.123`）

**Cloud / Portal 延伸：** SMB Portal Live Learning、三模式（listen/learning/detect）、Baseline Profile 与中断 Rollback 见 guacamole-ai [`docs/PRD_OT_BASELINE_LIVE_LEARNING.md`](../../guacamole-ai/docs/PRD_OT_BASELINE_LIVE_LEARNING.md)。本文件保留 **Edge Console 本机** pcap 学习、drift、rollback 路径。

---

## 1. 背景與問題

SenseL OT Edge Sensor 以被動鏡像（mirror / SPAN）擷取 OT 網段流量，並針對 IEC 61850（GOOSE / MMS）、Modbus TCP 等協定做異常偵測。偵測規則需要一份「正常狀態」的基準（baseline）才能判斷偏離（deviation）。

**痛點：**

- 早期 baseline 是**靜態手寫**在 `detection-policy.json`，無法反映現場實際拓樸，導致誤報 / 漏報。
- 沒有「學習 → 審核 → 套用 → 回滾」的生命週期，現場工程師無法安全地建立或更新基線。
- 無法回答「現在線上的設備與當初核准的基線差在哪？」（drift）。

**目標：** 提供一套可被現場 OT 工程師操作、可稽核、可回滾的基線生命週期，且**學習過程絕不告警**、**套用過程不需重啟服務**。

---

## 2. 範圍

### In Scope（本版）

- 以 **pcap 離線學習**產生候選基線（candidate）。
- 候選基線**人工審核核准**後合併進偵測政策並熱重載。
- **Live 觀測**（持續被動擷取）與 **Active 基線**的 **drift 比對**。
- 接受目前 live 觀測為新基線（approve drift）。
- 版本**歷史與回滾**。
- Live 觀測的**滾動視窗 / 老化**（只保留近期仍在線的身分）。

### Out of Scope（本版不做）

- 自動（無人審核）套用基線。
- Modbus / OPC UA / S7 的 baseline 學習合併（collector 已蒐集 Modbus，但**核准只合併 IEC 61850 區塊**）。
- 機器學習 / 統計式異常分數（本版為 identity allowlist 式基線）。
- 跨多 sensor 的中央基線管理。

---

## 3. 使用者與情境

| 角色 | 情境 |
| --- | --- |
| OT 維運工程師 | 上傳一段乾淨時段的 pcap，學習並核准成基線 |
| 資安分析師 | 檢視 live 觀測 vs 基線的 drift，判斷是新設備上線還是異常 |
| 現場交接 / 稽核 | 查看基線版本歷史、必要時回滾到前一版本 |

**核心使用者故事**

1. 作為工程師，我要能上傳 pcap 並看到系統學到哪些 GOOSE publisher / MMS IED，再決定是否核准。
2. 作為分析師，我要能一眼看出目前線上與基線的差異（新增 / 移除 / 變更），並能展開看明細。
3. 作為維運，我要能在套錯基線時回滾到上一版，且不需重啟 sensor。

---

## 4. 名詞定義

- **Candidate（候選）**：由 pcap 學習產生、尚未套用的基線文件（`candidate.json`）。
- **Active（生效中）**：已合併進 `detection-policy.json` 的基線。
- **Live Observed（即時觀測）**：sensor 持續被動擷取、定期落地的目前線上身分快照（`live-observed.json`）。
- **Drift（漂移）**：Live Observed 與 Active 之間的差異。
- **身分（identity）**：用於 allowlist 的關鍵欄位。GOOSE 以 `publisher_mac | appid | gocb_ref` 為鍵；MMS 以 `ied_ip` 為鍵（含 `allowed_mms_clients`）。

---

## 5. 狀態機

```
                ┌─────────────┐
                │ not_loaded  │  尚無 active 基線
                └──────┬──────┘
              學習(pcap) │ 產生 candidate
                        ▼
                ┌─────────────┐
                │  learning   │  candidate 比 active 新，待審核
                └──────┬──────┘
            approve     │
                        ▼
                ┌─────────────┐   live 與 active 出現差異
                │   active    │ ───────────────┐
                └──────┬──────┘                │
            approve     ▲                       ▼
            -drift /     │              ┌─────────────┐
            rollback     └───────────── │    drift    │
                                        └─────────────┘
```

**狀態判定邏輯**（`baseline_service.get_state`）：

1. 有 candidate 且 `candidate.generated_at > active.applied_at` → `learning`。
2. 否則有 active 且 `drift.summary.total > 0` → `drift`。
3. 否則有 active → `active`。
4. 否則 → `not_loaded`。

---

## 6. 架構與資料流

**設計原則：sensor 端不開 HTTP API；console 透過「共享 Docker volume + `docker exec`」驅動 sensor。** sensor 擁有 scapy 與所有協定 parser，console 負責生命週期狀態與審核。

```
┌──────────────┐         共享 volume          ┌─────────────────┐
│ edge-console │  ── pcap 寫入 uploads ──▶     │  packet-sensor   │
│ (FastAPI)    │  ── docker exec learn ──▶     │  (scapy/parsers) │
│              │  ◀── 讀 candidate.json ──     │                  │
│              │  ◀── 讀 live-observed ──      │  live pipeline   │
│              │  ── 寫 detection-policy ─▶    │  熱重載 stamp     │
└──────────────┘                              └─────────────────┘
```

### 6.1 掛載與路徑

| 用途 | console（rw/ro） | sensor（rw/ro） |
| --- | --- | --- |
| agent 目錄 | `/data/agent`（rw） | `/app/data/agent`（ro） |
| assets 目錄 | `/data/assets`（ro） | `/app/data/assets`（rw） |
| docker socket | `/var/run/docker.sock`（rw） | — |

| 檔案 | 產生者 | 路徑（console 視角） |
| --- | --- | --- |
| 上傳 pcap | console | `<agent>/baseline/uploads/<ts>-<name>.pcap` |
| 候選基線 | sensor（learn.py） | `<assets>/baseline/candidate.json` |
| Live 觀測快照 | sensor（main 迴圈） | `<assets>/baseline/live-observed.json` |
| 生效基線 | console | `<agent>/detection-policy.json`（`baseline.iec61850`） |
| 版本歷史 | console | `<agent>/baseline/baseline-state.json` |
| 熱重載 stamp | console | `<agent>/detection-policy.stamp` |

### 6.2 熱重載

核准 / 回滾後，console 以原子寫入更新 `detection-policy.json`，並寫 `detection-policy.stamp`（第一行 epoch、第二行 version）。sensor 以 `DETECTION_POLICY_RELOAD_SEC`（預設 5s）輪詢 stamp，偵測變動即重載政策，**無需重啟容器**。

---

## 7. 功能需求

### FR-1　pcap 離線學習
- 接受 `.pcap / .pcapng / .cap`；檔名清洗避免路徑注入。
- **上傳採串流落地**（`request.stream()` 邊收邊寫檔），RAM 與檔案大小無關；超過上限（預設 100MB，`BASELINE_MAX_PCAP_MB`）即中止並刪除半寫檔回 413。
- **大檔自動套封包上限**：未指定 `limit` 且檔案 > `BASELINE_AUTO_LIMIT_MB`（預設 50MB）時，自動以 `BASELINE_AUTO_LIMIT_PACKETS`（預設 50 萬）為上限學習（OT 身分很早就出現），避免逼近逾時。
- console 將 pcap 落地後 `docker exec` 執行 `python -m src.baseline.learn`；逾時 `BASELINE_LEARN_TIMEOUT_SEC`（預設 600s）回 504。
- learner 以 `scapy.sniff(offline=…, store=False)` 串流餵入既有 parser，蒐集身分並原子寫出 `candidate.json`。
- **學習過程不得產生任何安全事件**（collector 與偵測引擎分離）。

> **硬體建議（Pi 4B / 4 核 / 3.7GB）**：baseline 學的是「有哪些設備在線」而非流量量；乾淨時段 **5–15 分鐘擷取（≤ 100MB）** 即可涵蓋所有 GOOSE/MMS 身分。建議值 ≤ 50MB、安全上限 ~100MB、硬上限 100MB（可調）。

### FR-2　候選審核與套用
- UI 顯示候選統計（GOOSE / MMS / comm pairs / packets）與「核准並套用」。
- 核准時**只合併 `observed.iec61850`**（`goose_publishers`、`mms_ieds`）進 `detection-policy.json`。
- 套用即產生新 `version`（`baseline-YYYYMMDD-HHMMSS`）、更新 `updated_at`、寫 stamp、記錄歷史。
- 候選不含可套用的 IEC 61850 觀測 → 422。

### FR-3　Live 觀測快照
- sensor live pipeline 持續餵 `feed_goose / feed_mms / feed_modbus / feed_endpoints`。
- 每個 feature window（約 60s）落地一份 `live-observed.json`，含 `window_sec` 與 `stats`。

### FR-4　Drift 比對
- 比對 **active vs live** 的 IEC 61850 身分：
  - GOOSE：以 `publisher_mac|appid|gocb_ref` 為鍵 → added / removed / changed（`production`、`conf_rev` 變更）。
  - MMS：以 `ied_ip` 為鍵 → added / removed，以及每 IED 的 `allowed_mms_clients` 新增 / 移除。
- 回傳 `summary{added, removed, changed, total}` 與各類明細。
- UI：`drift` 狀態顯示摘要、可開抽屜看明細、提供「核准目前觀測為新基線」。

### FR-5　接受 Drift 為新基線
- 將目前 live 觀測整份套用為新 active 基線（同 FR-2 的版本 / stamp / 歷史流程，`source=edge-console-drift`）。

### FR-6　版本歷史與回滾
- `baseline-state.json` 保留最近 **20** 版，每版含完整 `snapshot`（可回滾）。
- 回滾以該版 snapshot 重新套用，產生新 version（`source=edge-console-rollback`），保留稽核軌跡。

### FR-7　Live 觀測滾動視窗 / 老化
- 每個身分記錄 `last_seen`（monotonic）。
- Live 快照以 `LIVE_OBSERVE_WINDOW_SEC`（預設 **900s**）為視窗：超過視窗未再出現的 GOOSE publisher / MMS IED / 個別 MMS client / comm pair **自動老化移除**。
- **pcap 學習路徑不套用視窗**（`window_sec=None`，全收），確保離線學習完整。

---

## 8. API 規格（edge-console，皆需 session）

| Method | Path | 說明 |
| --- | --- | --- |
| GET | `/api/baseline` | 回傳狀態機結果（state / active / candidate / history / drift summary） |
| GET | `/api/baseline/candidate` | 目前候選基線全文 |
| POST | `/api/baseline/learn` | 上傳 pcap（≤200MB），觸發學習，回候選 |
| POST | `/api/baseline/approve` | 核准候選並套用 |
| GET | `/api/baseline/drift` | drift 明細報告（goose / mms 的 added/removed/changed） |
| POST | `/api/baseline/approve-drift` | 接受 live 觀測為新基線 |
| POST | `/api/baseline/rollback` | `{version}` 回滾至指定版本 |

所有變更類操作皆寫入稽核日誌（`console-audit.jsonl`）。

---

## 9. 資料模型

### candidate.json / live-observed.json
```json
{
  "schema": "sensel.baseline/1",
  "generated_at": "2026-06-09T22:52:41+00:00",
  "source": "pcap_import | live_observed",
  "source_ref": "capture.pcap",
  "window_sec": 900,
  "stats": { "packets": 0, "unique_macs": 2, "unique_ips": 2,
             "comm_pairs": 1, "goose_publishers": 1, "mms_ieds": 1, "modbus_servers": 0 },
  "observed": {
    "iec61850": {
      "goose_publishers": [
        { "asset_id": "learned-goose-01", "publisher_mac": "…", "appid": 1000,
          "gocb_ref": "…", "go_id": "…", "conf_rev": 1, "production": true,
          "max_silence_sec": 30, "observed_frames": 123 }
      ],
      "mms_ieds": [
        { "asset_id": "learned-ied-01", "ied_ip": "192.168.10.50",
          "allowed_mms_clients": ["192.168.10.10"], "observed_reads": 8, "observed_writes": 4 }
      ]
    },
    "modbus_servers": [],
    "comm_pairs": [{ "src": "…", "dst": "…" }],
    "mac_ip": [{ "mac": "…", "ip": "…" }]
  }
}
```

### baseline-state.json
```json
{
  "active_version": "baseline-20260609-225047",
  "versions": [
    { "version": "baseline-20260609-225047", "applied_at": "…", "source_ref": "drift:…",
      "active": true, "goose": 1, "mms": 1, "snapshot": { "goose_publishers": [], "mms_ieds": [] } }
  ]
}
```

---

## 10. 非功能需求

- **安全**：學習不告警；主動探測另以 flag 控管（不屬本機制）。檔名清洗、IP 驗證避免注入。
- **可靠**：所有檔案寫入採 `tempfile + os.replace` 原子寫入，避免半寫毀損。
- **可用性**：套用 / 回滾不需重啟；sensor 端解析錯誤計數但不中斷學習。
- **可稽核**：版本歷史保留 20 版含快照；每次變更寫稽核日誌。
- **效能**：pcap 學習逾時上限 600s；live 快照每 ~60s 一次。

---

## 11. 設定參數

| 變數 | 預設 | 說明 |
| --- | --- | --- |
| `LIVE_OBSERVE_WINDOW_SEC` | `900` | live 觀測滾動視窗秒數；`0`=自開機累積不老化 |
| `BASELINE_MAX_PCAP_MB` | `100` | pcap 上傳硬上限（MB） |
| `BASELINE_AUTO_LIMIT_MB` | `50` | 超過此大小自動套封包上限 |
| `BASELINE_AUTO_LIMIT_PACKETS` | `500000` | 自動封包上限數 |
| `BASELINE_LEARN_TIMEOUT_SEC` | `600` | learner `docker exec` 逾時 |
| `DETECTION_POLICY_RELOAD_SEC` | `5` | sensor 輪詢 stamp 的間隔 |
| `PACKET_SENSOR_CONTAINER` | `sensel-packet-sensor` | console `docker exec` 目標容器 |
| `DETECTION_POLICY_PATH` / `_STAMP_PATH` | `/data/agent/…` | 政策與 stamp 路徑 |
| `ASSETS_DIR` | `/data/assets` | 共享 assets 目錄 |

---

## 12. 驗收標準

- [x] 上傳乾淨 pcap → 產生候選，UI 顯示 GOOSE/MMS 統計。
- [x] 核准候選 → `detection-policy.json` 出現 `baseline.iec61850`，version 更新，sensor 在 ≤5s 內熱重載。
- [x] sensor 持續產生 `live-observed.json`，含 `window_sec=900`。
- [x] live 與 active 不同 → state=`drift`，摘要與明細正確。
- [x] approve-drift → state 回 `active`，新版本入歷史。
- [x] 回滾 → 套用指定版本快照並產生新版本。
- [x] 超過視窗未出現的身分從 live 快照老化移除；pcap 學習不老化。
- [x] 單元測試：collector 老化（GOOSE / MMS client）、drift 比對；皆綠。

---

## 13. 已知限制與後續

- **僅 IEC 61850 合併**：collector 已蒐集 Modbus servers，但核准只寫 `iec61850`；Modbus baseline 合併為後續。
- **drift 僅比身分集合**：GOOSE 僅比 `production` / `conf_rev`；未比 silence / 頻率等時序特徵。
- **單機**：未做跨 sensor 中央基線同步。
- **後續候選**：
  - Modbus / OPC UA / S7 baseline 合併與 drift。
  - 半自動建議（drift 連續穩定 N 視窗自動建議核准）。
  - 基線比對加入時序特徵（GOOSE 週期、MMS 讀寫頻率）。

---

## 14. 相關程式

| 元件 | 檔案 |
| --- | --- |
| 觀測蒐集 / 老化 | `services/packet-sensor/src/baseline/collector.py` |
| pcap 學習 CLI | `services/packet-sensor/src/baseline/learn.py` |
| live 快照落地 | `services/packet-sensor/src/baseline/snapshot.py`、`src/main.py` |
| live pipeline 串接 | `services/packet-sensor/src/pipeline/processor.py` |
| 生命週期服務 | `services/edge-console/src/baseline_service.py` |
| API | `services/edge-console/src/main.py`（`/api/baseline*`） |
| UI | `services/edge-console/static/pages/policy.js` |
