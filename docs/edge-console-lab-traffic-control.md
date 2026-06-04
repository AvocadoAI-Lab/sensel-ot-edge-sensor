# Edge Console — Lab 流量控制 API / UI 草案

> 狀態：**草案（未實作）**  
> 目標：在 `http://<pi>:8090` 以 UI 控制 **61850 lab 本機流量**（GOOSE/MMS publisher）與 **被動擷取**（packet-sensor），支援開始／暫停／停止；正式現場僅顯示鏡像狀態、不暴露 publisher 控制。

---

## 1. 背景與問題

| 現況 | 缺口 |
|------|------|
| `sensel-goose-publisher`、`sensel-mms-publisher` 隨 `docker-compose.lab-61850.yml` 常駐啟動 | Console **無法** start/stop |
| `packet-sensor` 被動擷取 `eth0`，寫入 `capture-live.json` | 進階頁僅 **重啟** sensor，無「暫停擷取」 |
| EdgeX 平台頁可 `docker restart` 部分 EdgeX 容器 | **不含** lab publisher 容器名 |

Lab 流量與真實 **外部 SPAN mirror** 需 UI 上區分，避免誤導現場操作人員。

---

## 2. 設計原則

1. **Lab 與 Production 分離**：僅在偵測到 lab profile（publisher 容器存在或 `LAB_TRAFFIC_CONTROL_ENABLED=1`）時顯示「Lab 流量模擬」區塊。
2. **白名單容器**：只允許操作固定容器名，禁止任意 `docker` 參數注入。
3. **審計**：所有 start/stop/pause 寫入 `console-audit.jsonl`（與現有 `docker.restart` 一致）。
4. **複用既有能力**：docker.sock + `EDGE_CONSOLE_DOCKER_RESTART`；與 `_restart_container()` 同模組。
5. **狀態可觀測**：`GET` 回傳 Docker 狀態 + `capture-live.json` 新鮮度 + 可選 publisher 環境摘要（不洩漏密碼）。

---

## 3. 控制對象與語意

### 3.1 Lab 流量產生器（模擬 OT 流量）

| 容器 | 角色 | UI 標籤 |
|------|------|---------|
| `sensel-goose-publisher` | 週期發送 GOOSE | GOOSE 模擬 |
| `sensel-mms-publisher` | 週期發送 MMS/TCP:102 | MMS 模擬 |

**動作語意：**

| 動作 | Docker 行為 | 說明 |
|------|-------------|------|
| **開始** | `docker start <name>`（若已存在且 stopped） | 恢復發包 |
| **暫停** | `docker stop <name>` | 停止發包；容器仍在，可再 start |
| **停止** | 同暫停（v1）或 `docker stop` + 可選 `docker rm`（v2，預設不 rm） | v1 與暫停相同，UI 合併為「停止發包」即可 |

建議 v1：**暫停 = 停止發包**（皆 `docker stop`），避免誤刪容器。若需「完全移除」另提供進階「移除 lab 服務」（不在首屏）。

### 3.2 被動擷取（Packet Sensor）

| 容器 | 角色 |
|------|------|
| `sensel-packet-sensor` | 鏡像擷取 + 偵測 + `capture-live.json` |

| 動作 | Docker 行為 | 對即時流量的影響 |
|------|-------------|------------------|
| **開始擷取** | `docker start sensel-packet-sensor` | 恢復 pkt/s、GOOSE/MMS 計數更新 |
| **暫停擷取** | `docker stop sensel-packet-sensor` | 圖表凍結；publisher 仍可發包（鏡像上仍看得到，若同網卡） |
| **重啟擷取** | 既有 `POST /api/capture/reload` | 套用新 BPF/介面後重啟 |

**組合建議（快捷）：**

| 快捷按鈕 | 效果 |
|----------|------|
| **僅 Lab 模擬** | start publishers，stop packet-sensor（只看 synthetic） |
| **僅 Mirror 擷取** | stop publishers，start packet-sensor（現場驗證用） |
| **全部開始** | start 三者 |
| **全部暫停** | stop publishers + packet-sensor |

---

## 4. API 草案

Base path：`/api/lab/traffic`（需 session，與 `/api/status` 相同 `require_session`）

### 4.1 `GET /api/lab/traffic/status`

回傳 lab 控制面板所需完整狀態。

**Response 200**

```json
{
  "enabled": true,
  "mode": "lab",
  "message": "Lab 61850 publishers detected",
  "capture": {
    "container": "sensel-packet-sensor",
    "status": "running",
    "health": "healthy",
    "interface": "eth0",
    "bpf_filter": "(ether proto 0x88b8) or (tcp port 102)",
    "live": true,
    "instant_rate": 1.96,
    "age_sec": 1.2
  },
  "publishers": [
    {
      "id": "goose",
      "container": "sensel-goose-publisher",
      "label": "GOOSE 模擬",
      "status": "running",
      "interface": "eth0",
      "summary": "APPID 1000"
    },
    {
      "id": "mms",
      "container": "sensel-mms-publisher",
      "label": "MMS 模擬",
      "status": "running",
      "interface": "eth0",
      "src_ip": "192.168.10.88",
      "dst_ip": "192.168.10.50",
      "interval_sec": 2
    }
  ],
  "presets": [
    {"id": "lab_only", "label": "僅 Lab 模擬（停擷取）"},
    {"id": "mirror_only", "label": "僅 Mirror 擷取（停模擬）"},
    {"id": "all_on", "label": "全部開始"},
    {"id": "all_off", "label": "全部暫停"}
  ],
  "docker_control_enabled": true
}
```

**`enabled: false` 時機：**

- 無 `sensel-goose-publisher` / `sensel-mms-publisher` 容器定義，且 `LAB_TRAFFIC_CONTROL_ENABLED` 未設。
- Production overlay 未部署 lab-61850。

**Errors**

- `503`：`EDGE_CONSOLE_DOCKER_RESTART=false` 或無 docker.sock。

---

### 4.2 `POST /api/lab/traffic/actions`

統一動作端點（避免多個 REST 資源版本漂移）。

**Request body**

```json
{
  "action": "start",
  "targets": ["goose", "mms", "capture"]
}
```

| `action` | 說明 |
|----------|------|
| `start` | 對每個 target 執行 `docker start`（已 running 則 no-op） |
| `stop` | 對每個 target 執行 `docker stop` |
| `restart` | 僅允許 `capture` → 等同 `POST /api/capture/reload` |

| `targets[]` | 對應 |
|-------------|------|
| `goose` | `sensel-goose-publisher` |
| `mms` | `sensel-mms-publisher` |
| `capture` | `sensel-packet-sensor` |

**Preset 快捷（可選擴充）**

```json
{
  "preset": "mirror_only"
}
```

後端展開為 `targets` + `action`，見 §3.2 表。

**Response 200**

```json
{
  "ok": true,
  "results": [
    {"target": "goose", "container": "sensel-goose-publisher", "ok": true, "message": "started"},
    {"target": "mms", "container": "sensel-mms-publisher", "ok": true, "message": "already running"},
    {"target": "capture", "container": "sensel-packet-sensor", "ok": true, "message": "stopped"}
  ]
}
```

**Errors**

- `400`：未知 `action` / `target` / 容器不在白名單。
- `503`：docker 操作失敗（附 `results[].message`）。

**Audit**

```json
{"action": "lab.traffic", "detail": {"action": "stop", "targets": ["goose", "mms"], "preset": null}}
```

---

### 4.3 既有 API（保留、文件化）

| 方法 | 路徑 | 說明 |
|------|------|------|
| GET | `/api/traffic/live` | 唯讀即時統計（不變） |
| POST | `/api/capture/reload` | 重啟 packet-sensor（進階頁保留） |
| PUT | `/api/config` | 更新 `capture_interface` / `capture_bpf` → `capture.env` |

建議：`PUT /api/config` 儲存後提示「是否重啟擷取？」，不自動 stop publisher。

---

## 5. 後端模組草案

```
services/edge-console/src/
  lab_traffic_service.py   # 新建：白名單、docker start/stop、狀態聚合
  docker_control.py        # 可選：從 main._restart_container 抽出 start/stop/inspect
```

**環境變數**

| 變數 | 預設 | 說明 |
|------|------|------|
| `LAB_TRAFFIC_CONTROL_ENABLED` | 自動偵測 | 強制顯示 lab 控制（無 publisher 時用於 UI 開發） |
| `LAB_GOOSE_CONTAINER` | `sensel-goose-publisher` | |
| `LAB_MMS_CONTAINER` | `sensel-mms-publisher` | |
| `EDGE_CONSOLE_DOCKER_RESTART` | `true` | 與現有一致；為 false 時 lab traffic API 503 |

**偵測 lab 模式**

```python
def lab_traffic_available() -> bool:
    if env_enabled(): return True
    return docker_container_exists("sensel-goose-publisher") or docker_container_exists("sensel-mms-publisher")
```

---

## 6. UI 草案

### 6.1 位置：「即時流量」分頁頂部（主場景）

在 `tab-traffic` 的 `traffic-header` 下方新增可摺疊卡片 **「Lab 流量模擬（僅開發／PoC）」**，production 無 publisher 時整塊 `hidden`。

```
┌─────────────────────────────────────────────────────────────┐
│ 即時流量                    ● 即時  1.9 pkt/s               │
├─────────────────────────────────────────────────────────────┤
│ ⚠ Lab 流量模擬（本機 publisher，非外部 SPAN）    [說明 ▾]   │
│                                                             │
│  ┌──────────────┐ ┌──────────────┐ ┌──────────────────────┐ │
│  │ GOOSE 模擬   │ │ MMS 模擬     │ │ 被動擷取             │ │
│  │ ● 運行中     │ │ ● 運行中     │ │ ● 運行中             │ │
│  │ eth0         │ │ 88→50 :102   │ │ eth0 · BPF …         │ │
│  │ [暫停]       │ │ [暫停]       │ │ [暫停] [重啟]        │ │
│  └──────────────┘ └──────────────┘ └──────────────────────┘ │
│                                                             │
│  快捷：[僅 Lab 模擬] [僅 Mirror] [全部開始] [全部暫停]        │
│                                                             │
│  介面 eth0 · 後端 scapy · BPF (ether proto 0x88b8) or …     │
│  （以下為現有 metrics / 圖表 / Top MAC / 最近封包）          │
└─────────────────────────────────────────────────────────────┘
```

**狀態點顏色（與總覽一致）**

- `running` + capture `live` → 綠
- `stopped` → 灰
- `exited` / 不存在 → 紅 + 提示「請 docker compose up goose-publisher」

**說明摺疊文案（繁中）**

> 目前流量來自本機 **GOOSE/MMS 模擬器**，打在擷取介面 `eth0` 上，再由 Packet Sensor 被動統計。  
> 接真實交換器 SPAN 時，請在「進階」改 `CAPTURE_INTERFACE` 為鏡像口，並用「僅 Mirror」停止模擬器。

### 6.2 進階頁（次要）

保留現有「擷取 (Packet Sensor)」+「重啟 Packet Sensor」；增加一行連結：「前往即時流量 → Lab 控制」。

### 6.3 前端行為

| 事件 | 行為 |
|------|------|
| 進入 `traffic` tab | `GET /api/lab/traffic/status` + 既有 `GET /api/traffic/live` |
| 點「暫停／開始」 | `POST /api/lab/traffic/actions` → toast → 刷新 status + live |
| 快捷 preset | `POST { "preset": "mirror_only" }` |
| 輪詢 | 與現有相同：live 5s；lab status 10s（或僅在 traffic tab 可見時） |

**`app.js` 新增函式（草案）**

```javascript
async function loadLabTrafficStatus() { ... }
async function labTrafficAction(action, targets) { ... }
async function labTrafficPreset(preset) { ... }
```

### 6.4 無 Lab 模式（Production）

- 不顯示 Lab 卡片。
- `GET /api/lab/traffic/status` → `{ "enabled": false }`。
- 即時流量頁 hint 改為：「Mirror 埠鏡像擷取 · 無 lab 模擬」。

---

## 7. 安全與權限

| 項目 | 措施 |
|------|------|
| 認證 | 沿用 `require_session`；production 強制 `EDGE_CONSOLE_PASSWORD` |
| 授權 | v1 不區分角色；v2 可僅 `admin` 可 stop publisher |
| 命令注入 | 僅白名單容器名；`subprocess` 使用 list argv，不用 shell |
| 審計 | `lab.traffic` / `lab.traffic.preset` 寫 audit log |
| 破壞性 | 不提供 `docker rm` / `compose down`（v1） |

---

## 8. 實作階段建議

| 階段 | 內容 | 驗收 |
|------|------|------|
| **P0** | `lab_traffic_service.py` + `GET status` + `POST actions` + UI 三卡 + 快捷 | 點「全部暫停」→ Console pkt/s≈0；Portal 仍可有舊事件 |
| **P1** | 單元測試 mock docker；`verify-edge-console-lab-traffic.sh` | CI / Pi smoke |
| **P2** | MMS/GOOSE 間隔只讀顯示；可選 `PUT` 調 interval（寫 env 需 restart publisher） | 文檔即可 |
| **P3** | 與 `capture.env` 聯動：mirror_only 時提示改 eth1 | 現場 PoC |

**不納入 v1**

- 從 UI `docker compose up` 新 publisher（維持 deploy 腳本）。
- 暫停單一協定層（需改 publisher 程式支援 SIGUSR1）。

---

## 9. 與全鏈路驗收的關係

| 操作 | 203/108 影響 |
|------|----------------|
| 停止 publisher + 保持 sensor | 無新 MQTT 事件；既有 Portal 事件不變 |
| 停止 sensor | Console 無 live；agent 仍可發佈 buffered／MQTT 視佇列 |
| 全部暫停 | 適合「乾淨」驗證 108 ingest 來自單次注入 |

建議驗收腳本新增（可選）：

```bash
EDGE_CONSOLE_URL=http://192.168.1.123:8090 ./scripts/verify-edge-console-lab-traffic.sh
```

---

## 10. 開放問題

1. **暫停 vs 停止**：v1 是否合併為 `stop` 即可？  
2. **停止 publisher 後是否自動 stop sensor**：預設 **否**，由快捷「僅 Mirror」負責。  
3. **MMS 來源 IP 是否可在 UI 編輯**：P2 再考慮（需改 `data/agent/lab-mms.env` + restart）。  
4. **是否允許從 UI 啟動整條 compose profile**：建議否，避免與 `apply-lab-61850-edgex` 職責重疊。

---

## 11. 相關檔案（實作時）

| 檔案 | 變更 |
|------|------|
| `services/edge-console/src/lab_traffic_service.py` | 新增 |
| `services/edge-console/src/main.py` | 註冊路由 |
| `services/edge-console/static/index.html` | Lab 控制卡 HTML |
| `services/edge-console/static/app.js` | 事件與輪詢 |
| `services/edge-console/static/style.css` | 三欄卡片樣式 |
| `scripts/verify-edge-console-lab-traffic.sh` | 新增 smoke |
| `docs/runbook-ot-lab-deploy.md` | 連結本文 |

---

*草案版本：2026-06-05 · 對應 Edge Console v0.1.0 + lab-61850 overlay*
