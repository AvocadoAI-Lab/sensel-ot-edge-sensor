# Sprint 規劃（PRD MVP）

依 [`PRD.md`](PRD.md) MVP 範圍（Sprint 1–3）與 §18 驗收標準規劃。邊緣 repo 現況為 **v0.1.0 骨架**；本文件為執行用 backlog。

## 驗收北極星

- Lab 環境 **72 小時**穩定運行
- **新設備出現**與 **Modbus write** 事件可在 SenseL Dashboard 檢視

## Sprint 總覽

| Sprint | 週期 | 主題 | 退出條件 |
|--------|------|------|----------|
| **1 Foundation** | 1–2 週 | 可部署、可連線、可擷取 | `docker compose up` 後 agent 註冊 + health 上傳成功；packet-sensor 可從 mirror 介面抓到封包 |
| **2 Passive MVP** | 1–2 週 | 被動解析 + 偵測 + 證據 | OT-001~010 觸發事件並上傳 SenseL；PCAP ring buffer 可本地留存 |
| **3 Dashboard** | 1–2 週 | 端到端整合 + 政策 | 72h lab soak pass；Dashboard 可見資產、事件、遙測 |
| **4 Intelligence + UX** | 2 週 | Edge Console 工控 UI + Layer B AE + Layer C LLM/RAG | Portal 可讀 Layer C 摘要；203 gemma2:2b POC；behavior_score 上線 |
| **5 Productization** | 2 週 | Demo Ready + soak + deploy 硬化 | 見 [`sprint-5-productization.md`](sprint-5-productization.md) |

## PRD MVP 對照

| PRD 項目 | 主要 Sprint |
|----------|-------------|
| Docker Compose 部署 | 1 |
| EdgeX Core + device-mqtt + device-modbus | 1（core）/ 3（exporter 完整） |
| Packet Sensor L2/L3/L4 + Modbus TCP | 2 |
| OT-001 ~ OT-010 | 2 |
| PCAP ring buffer | 2 |
| SenseL 事件 / 遙測 / 健康上傳 | 1（health）/ 2（events）/ 3（telemetry） |
| SenseL OT Dashboard 基本整合 | 3（平台另庫，見 [`platform/README.md`](../platform/README.md)） |

---

## Sprint 1 — Foundation

**目標**：從骨架到最小可驗證資料流（註冊、health、封包擷取）。

### Epic 1.1 — Docker Compose 與 EdgeX

| ID | Story | 產出 | 狀態 |
|----|-------|------|------|
| S1-01 | 合併 EdgeX compose（core-data、metadata、device-mqtt、device-modbus） | `edgex/docker-compose.edgex.yml` | ✅ |
| S1-02 | device-modbus 連 lab Modbus relay / 模擬器 | 主動遙測進 Core Data | ✅ |
| **S1-02b** | **IEC 61850 被動（GOOSE + MMS）lab spike** | **[`sprint-s1-02b-iec61850.md`](sprint-s1-02b-iec61850.md)** | **✅** |
| S1-03 | device-mqtt 訂閱 local-mqtt feature summary | MQTT → Core Data E2E | ✅ |
| S1-04 | Pi4 overlay 實測 | `docker-compose.pi4.yml` | 部分 |

### Epic 1.2 — SenseL Edge Agent

| ID | Story | 產出 | 狀態 |
|----|-------|------|------|
| S1-05 | 設定載入（`.env` + `sensor.yaml`） | `src/config/` | ✅ |
| S1-06 | 感測器註冊 | `api/client.py` | ✅ |
| S1-07 | 週期性 health 上傳 | `health/collector.py` | ✅ |
| S1-08 | 離線緩衝骨架（health） | `upload/buffer.py` | ✅ |

### Epic 1.3 — Packet Sensor 擷取

| ID | Story | 產出 | 狀態 |
|----|-------|------|------|
| S1-09 | 介面 + promisc + BPF | `capture/interface.py` | ✅ |
| S1-10 | Scapy 擷取迴圈 + L2/L3 計數 | `main.py` | ✅ |
| S1-11 | 單網卡 lab 模式文件 | `deployment-ubuntu.md` | 待辦 |

### Epic 1.4 — 測試

| ID | Story | 產出 | 狀態 |
|----|-------|------|------|
| S1-12 | SenseL mock + integration test | `tests/integration/` | ✅ |
| S1-13 | Makefile `test` 修正 | `Makefile` | ✅ |

### Sprint 1 Done Checklist

- [ ] `docker compose up -d` 全堆疊 healthy
- [x] Edge Agent 完成註冊並週期 health 上傳（程式已實作，待 docker 驗證）
- [ ] Packet Sensor 持續計數封包 ≥ 1h 無 crash
- [ ] `./scripts/health-check.sh` 全綠
- [x] `make test` 通過 integration tests

---

## Sprint 2 — Passive MVP

**目標**：被動路徑產生可上傳的安全事件與證據。

### Epic 2.1 — 協定解析

| ID | Story | 模組 |
|----|-------|------|
| S2-01 | Ethernet / VLAN | `parser/l2/ethernet.py` |
| S2-02 | IPv4/IPv6、TCP/UDP 五元組 | `parser/l3/ip.py`, `parser/l4/transport.py` |
| S2-03 | Modbus TCP function code | `parser/l7/modbus/tcp.py` |
| S2-04 | 通訊 pair / port 統計 | `assets/inventory.py` |

### Epic 2.2 — 資產與規則

| ID | Story | 說明 |
|----|-------|------|
| S2-05 | 本地 asset inventory | MAC/IP/協定/port |
| S2-06 | baseline 載入與 diff | `config/policy/baseline.json` |
| S2-07 | OT-001 ~ OT-006 | 新 MAC/IP、mapping、pair、port、scan |
| S2-08 | OT-007 Modbus write | baseline allowlist |
| S2-09 | OT-008 流量速率 | 滑動窗口 |
| S2-10 | OT-009 relay offline | EdgeX + 被動雙源 |
| S2-11 | OT-010 未授權主機 | baseline + comm pair |

### Epic 2.3 — 證據與事件

| ID | Story | 模組 |
|----|-------|------|
| S2-12 | PCAP ring buffer | `evidence/ring_buffer.py` |
| S2-13 | 事件 + evidence_ref | `events/generator.py` |
| S2-14 | Security event 上傳 | Edge Agent |
| S2-15 | Feature summary → MQTT | local-mqtt |

### Epic 2.4 — 測試

| ID | Story | 產出 |
|----|-------|------|
| S2-16 | Synthetic pcap replay | integration |
| S2-17 | OT-001~010 各一觸發 fixture | 對照 `detection-rules.md` |

### Sprint 2 Done Checklist

- [x] 新 MAC/IP → OT-001/002 事件（`make verify-mvp` / `scripts/mvp-selftest.py`）
- [x] Modbus write 非 allowlist → OT-007
- [x] 事件含 `evidence_ref`，ring buffer 可查 PCAP ref
- [x] MQTT 發布 feature summary（S1-03）
- [x] Edge Agent 上傳 security-events.jsonl → SenseL API

---

## Sprint 3 — Dashboard & E2E

**目標**：主動 + 被動匯入 SenseL，通過 72h soak。

### Epic 3.1 — EdgeX → SenseL（邊緣 repo）

| ID | Story | 產出 |
|----|-------|------|
| S3-01 | sensel-exporter App Service | `edgex/app-services/sensel-exporter/` |
| S3-02 | device-mqtt profile 綁定 feature summary | device-profiles |
| S3-03 | Telemetry API 上傳 | `/api/v1/ot/telemetry` |

### Epic 3.2 — SenseL 平台（另庫）

| ID | 模組 |
|----|------|
| S3-04 | Ingestion API |
| S3-05 | OT Edge Sensor Management |
| S3-06 | OT Asset Inventory |
| S3-07 | OT Security Events 時間軸 |
| S3-08 | OT Telemetry Timeline |
| S3-09 | OT Evidence Viewer |

### Epic 3.3 — 政策與 AI

| ID | Story |
|----|-------|
| S3-10 | Edge Policy 下發（`policy/sync.py`） |
| S3-11 | AI Incident Summary 模板（平台） |

### Epic 3.4 — Soak

| ID | Story |
|----|-------|
| S3-12 | E2E：SPAN → 偵測 → Dashboard |
| S3-13 | E2E：Modbus write → OT-007 → Dashboard |
| S3-14 | 72 小時 lab soak 報告 |
| S3-15 | Pi4 field 部署驗證 |

### Sprint 3 Done Checklist

- [ ] 72h 穩定、新設備與 Modbus write 事件在 Dashboard 可見
- [ ] 主動/被動遙測分開呈現、可關聯同一資產
- [ ] 政策下發後 baseline 重載生效
- [ ] 離線 30min 恢復後 queue 重送成功

---

## 跨 Sprint

| 項目 | S1 | S2 | S3 |
|------|----|----|-----|
| JSON Schema 綁定 | health | security-event, feature-summary | telemetry |
| CI | 骨架 | 規則測試 | E2E gate |
| TLS / API Key | mock HTTP OK | staging TLS | 正式 TLS |

## 風險與緩解

| 風險 | 緩解 |
|------|------|
| EdgeX compose 複雜 | 先用官方 minimal compose |
| 無 SPAN / Modbus 設備 | pcap replay + pymodbus 模擬器 |
| IEC 61850 GOOSE 需 L2 lab | bridge + goose-publisher；見 S1-02b |
| 平台 API 未就緒 | Sprint 1 起維護 mock server |
| Pi4 資源不足 | compose 資源限制 + 可調取樣率 |

## Sprint 4 — Edge Console UX + OT Layer B/C 智慧加值

**詳細規格：** [`sprint-4-ot-intelligence-ui.md`](sprint-4-ot-intelligence-ui.md)

| Epic | 主題 | Repo |
|------|------|------|
| **A** | Edge Console 工控 UI（tokens、總覽四卡） | sensel-ot-edge-sensor |
| **B** | Layer B OT 行為 AE v0（feature + behavior_score） | Aristaconnector-Control-Plane |
| **C** | Layer C gemma2:2b + Agentic RAG（episode enrich） | Aristaconnector-Control-Plane |
| **D** | Portal Layer C 卡片化 | guacamole-ai |

**退出條件：** Edge Console 工控視覺上線；203 OT LLM enrich POC 合格；AE 寫入 entity_state；Portal 可讀摘要卡。

| 退出項 | 狀態 |
|--------|------|
| ① Edge Console tokens + 四卡 | ✅ 已上線（S4-A3 事件篩選 ✅） |
| ② LLM enrich POC | ✅ E2E `--expect-llm` PASS；10 episode 人工評分待辦 |
| ③ AE v0 → entity_state | ✅ model.joblib + warm-up；203 `OT_BEHAVIOR_AE_ENABLED=1` |
| ④ Portal Layer C 卡片 | ✅ 已 deploy；warm-up 提示已加 |

---

## 建議時程（2 週 / sprint）

| 週次 | 邊緣 repo | 平台 repo |
|------|-----------|-----------|
| W1–2 | Sprint 1 | Mock ingestion API |
| W3–4 | Sprint 2 | Events / Asset API |
| W5–6 | Sprint 3 + soak | Dashboard UI |
| W7–8 | Sprint 4 — Edge Console + spec | Layer B/C + Portal 卡片 |
