# Sprint 4 — Edge Console UX + OT Layer B/C 智慧加值

**前置：** Sprint 1–3 產品化（D1–D4、F2/F3、OT-C1/C2）完成；lab 72h soak 報告作為 baseline 參考。  
**週期建議：** 2 週（可拆 W1 / W2 milestone）。  
**Lab 拓撲：** 不變 — Pi `192.168.1.123` → 203 CP → 108 Portal（見 [`runbook-ot-lab-deploy.md`](runbook-ot-lab-deploy.md)）。

## 目標與退出條件

| 項目 | 說明 |
|------|------|
| **北極星** | 分析師在 Portal 看到**可讀的 Layer C 中文摘要與建議**；Edge Console 具工控視覺語言；Layer B 對 OT entity 產出**行為偏離分數**（非取代 Edge 規則） |
| **退出** | ① Edge Console design tokens + 總覽四卡上線；② 203 `gemma2:2b` OT enrich POC ≥10 episode 人工評分合格；③ Layer B AE v0 寫入 `entity_state`；④ Portal Layer C 卡片取代 raw JSON 預覽 |
| **非目標** | 完整 multimodal（PCAP 影像/波形）；LSTM 全序列模型；每 event 呼叫 LLM；取代 OT-001~018 規則 |

## 架構總覽

```
┌─────────────────────────────────────────────────────────────────────────────┐
│ Pi (Edge)                                                                    │
│  packet-sensor OT-001~018 ──► MQTT ot-edge/{tenant}/.../events/v1           │
└───────────────────────────────────┬─────────────────────────────────────────┘
                                    ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ 203 Control Plane                                                            │
│  mqtt-bridge ──► events.norm.ot_security.v1                                  │
│       │                                                                      │
│       ▼                                                                      │
│  Layer B: ot_security_adapter (rules) ──► episode + entity_state             │
│       │         + ot_behavior_scorer (AE v0, Sprint 4) ──► behavior_score    │
│       ▼                                                                      │
│  layerc-bridge ──► /analyze (OT profile)                                     │
│       │              ├─ rule fast path (現行)                                  │
│       │              └─ OT_LLM_ENRICH=1 → Agentic RAG + gemma2:2b            │
│       ▼                                                                      │
│  108 ingest ──► Portal 工控安全卡片                                           │
└─────────────────────────────────────────────────────────────────────────────┘
```

**設計原則**

1. **規則 = 高 precision 告警**（Edge + Layer B adapter）；ML = **drift / compound anomaly 分數**。
2. **LLM 僅 episode 級** enrich，絕不 per-event。
3. **OT profile 不走 Wazuh EvidenceOps**；使用 OT 專用輕量 RAG + tools。
4. **203 Mac mini 預設 2B**；9B 僅 high/critical escalation（可選）。

---

## Epic A — Edge Console UI/UX

**Repo：** `sensel-ot-edge-sensor/services/edge-console/`  
**現況：** 靜態 HTML/CSS/JS、`Inter` 字體、generic dark SaaS（`static/style.css`）。

### A.1 Design Tokens（工控語言）

| Token | 值 | 用途 |
|-------|-----|------|
| `--purdue-l0` ~ `--purdue-l5` | 層級色階（灰→琥珀→青綠→藍→紫→紅） | Purdue 標籤、資產層 |
| `--mono-id` | `"IBM Plex Mono", monospace` | sensor_id、MAC、rule_id |
| `--status-ok` | `#14b8a6` | 健康 / 已註冊 |
| `--status-warn` | `#f59e0b` | 離線 / baseline 學習中 |
| `--status-alarm` | `#ef4444` | 規則觸發 |
| `--surface-panel` | `#0f1419` + 1px `#2a3544` | 面板（低 glare） |

**Story S4-A1：** 新增 `static/tokens.css`，`style.css` import；保留現有 layout，只換視覺層。

### A.2 總覽四卡

| 卡片 | 資料來源 | 欄位 |
|------|----------|------|
| 感測器狀態 | `status_service` / health | 註冊、tenant、site、uptime |
| 擷取介面 | config + packet-sensor stats | iface、BPF、pps 近似 |
| 規則活動（24h） | 本地 events 計數或 API | top rule_id、severity 分布 |
| Baseline | `config/policy/baseline.json` | 資產數、comm pair 數、warm-up 狀態 |

**Story S4-A2：** `index.html` 總覽 tab 四卡；`app.js` 輪詢 `/api/status`（既有 endpoint 擴充若需）。

### A.3 事件列表強化

- 等寬 `rule_id`、Purdue badge、severity 色條
- 篩選：severity、rule_id 前綴（OT-01x / OT-01x）
- 不引入 React（Sprint 4 範圍外）

**Story S4-A3：** 事件 tab UX；驗證 Pi lab `:8090` 可讀。

### Epic A 驗收

- [ ] `:8090` 總覽四卡載入 < 2s（本地）
- [ ] rule_id / sensor_id 等寬顯示
- [ ] 現有 onboarding / BPF 設定流程不受影響

---

## Epic B — Layer B OT 行為異常（AE v0）

**Repo：** `Aristaconnector-Control-Plane/sensel-inferplane/` + `services/layer_b_inference/`  
**現況：** `b1_ingress/ot_security_adapter.py` 純規則，`source: ot_security_rules`，無 ET-BERT。

### B.1 混合管線

```
events.norm.ot_security.v1
    → ot_security_adapter (不變)
    → ot_behavior_feature_extractor (新)
    → ot_behavior_autoencoder.score() (新)
    → 併入 entity_state.trust_score / behavior_score
    → results.layerb.episode.v1 (context 帶 behavior_score)
```

**Story S4-B1：** feature extractor + sliding window（預設 5 min）。  
**Story S4-B2：** AE 推理（ONNX 或 sklearn joblib）；冷啟動 warm-up 標記。  
**Story S4-B3：** `entity_state` schema 擴充欄位（向下相容）。

### B.2 特徵向量（AE 輸入）

每 **entity_key**（優先 `ot-sensor:{sensor_id}`，次選 `device:{ip}`）每 window 一筆固定長度向量：

| 索引 | 特徵名 | 計算方式 |
|------|--------|----------|
| f0 | `event_count` | window 內 OT 事件總數 |
| f1–f10 | `count_rule_OT-001` … `count_rule_OT-010` | 各 rule 計數（MVP 規則） |
| f11–f18 | `count_rule_OT-011` … `count_rule_OT-018` | 61850 規則計數 |
| f19 | `unique_dst_ip` | 唯一 dst IP 數 |
| f20 | `unique_dst_port` | 唯一 dst port 數 |
| f21 | `mms_write_count` | OT-016 + OT-007 write 類計數 |
| f22 | `goose_event_count` | OT-011~013, OT-017 合計 |
| f23 | `high_severity_ratio` | high+critical / total |
| f24 | `inter_arrival_mean_ms` | 事件間隔均值 |
| f25 | `inter_arrival_std_ms` | 事件間隔標準差 |
| f26 | `new_pair_count` | OT-004 觸發次數 |
| f27 | `rate_anomaly_count` | OT-008 + OT-015 次數 |
| f28–f31 | reserved | 填 0，供 Sprint 5 擴充 |

**Window：** `OT_BEHAVIOR_WINDOW_SEC=300`（5 min），步進 `OT_BEHAVIOR_STEP_SEC=60`。  
**Normalization：** 訓練集 per-feature min-max；持久化 `models/ot_behavior_ae/v1/scaler.json`。

### B.3 AE 模型與輸出

| 項目 | 規格 |
|------|------|
| 結構 | FC encoder [32→16→8] → decoder 對稱；ReLU；MSE reconstruction loss |
| 訓練資料 | lab soak 72h + 人工標 normal 時段；排除已知 attack replay |
| 推理輸出 | `behavior_score` ∈ [0,1]（reconstruction error 映射）；`behavior_label`: `normal` \| `drift` \| `anomaly` |
| 閾值 | `drift` ≥ p95 train error；`anomaly` ≥ p99 |
| warm-up | 前 `OT_BEHAVIOR_WARMUP_WINDOWS=288`（24h @ 5min）僅累積不告警 |

**Story S4-B4：** 離線訓練腳本 `scripts/train_ot_behavior_ae.py` + lab fixture。  
**Story S4-B5：** layerb-worker 載入模型；feature flag `OT_BEHAVIOR_AE_ENABLED=0|1`。

### B.4 LSTM（Sprint 5 預留，Sprint 4 不實作）

有序序列 `[rule_id, protocol, src, dst, dt_ms]` 適用 **compound 序列異常**（如 write 前異常 read 模式）。需 labeled episodes；Sprint 4 只在 spec 預留 `OT_BEHAVIOR_MODEL=lstm` enum。

### B.5 與 Edge 規則分工

| 層級 | 職責 |
|------|------|
| Edge OT-016 等 | 已知 bad pattern，可解釋、可簽核 |
| Layer B AE | 跨 rule、跨時間 **漸進 drift**（commissioning vs 慢速攻擊） |
| trust_score | `trust_score = min(rule_trust, 1 - behavior_score * weight)`，`weight=0.3` 預設 |

### Epic B 驗收

- [ ] `OT_BEHAVIOR_AE_ENABLED=1` 時 entity_state 含 `behavior_score`
- [ ] warm-up 期 Portal 顯示「baseline 學習中」
- [ ] 單元測試：feature 向量 deterministic、AE smoke score
- [ ] 不改變 ot_security_adapter 既有 rule 輸出

---

## Epic C — Layer C LLM Enrich + Agentic RAG

**Repo：** `Aristaconnector-Control-Plane/src/pipeline/`、`services/layer_c_api/`、`services/layer_c_bridge/`  
**現況：** `ot_security_layer_c_run.py` → `run_analyze_by_rules`，`summary_zh` 為模板字串。

### C.1 雙路徑 Analyze

```
episode_is_ot_security?
    yes → run_ot_security_layer_c_pipeline
              ├─ [always] rule analyze (C2 fast path)
              └─ [if OT_LLM_ENRICH=1 && eligible] ot_llm_enrich_agent
                        ├─ retrieve OT KB
                        ├─ tools (history, behavior_score, rule meta)
                        └─ gemma2:2b → structured JSON
              → merge into layerc_ttp_reasoning
    no  → 既有 Wazuh / EvidenceOps 路徑（不變）
```

**Eligible 條件（預設）：**

- `malicious_count > 0` **或** `behavior_label == anomaly`
- severity ∈ `{high, critical}` **或** `behavior_score >= 0.85`
- 每 sensor 每小時 LLM 呼叫 ≤ `OT_LLM_MAX_PER_SENSOR_HOUR=12`

**Story S4-C1：** `ot_llm_enrich.py` + feature flag。  
**Story S4-C2：** rule path 失敗時 LLM 不執行（fail closed）。

### C.2 Ollama / 203 環境

| 變數 | Lab 預設 | 說明 |
|------|----------|------|
| `OT_LLM_MODEL` | `gemma2:2b` | OT enrich 專用 |
| `OT_LLM_BACKEND` | `ollama` | 同 `LLM_BACKEND` |
| `OT_LLM_OLLAMA_URL` | `http://host.docker.internal:11434` | 203 host Ollama |
| `OT_LLM_MAX_TOKENS` | `256` | 短輸出 |
| `OT_LLM_TIMEOUT_SEC` | `45` | Mac mini 保守值 |
| `OT_LLM_ESCALATION_MODEL` | `gemma2:9b` | 僅 `OT_LLM_ESCALATION=1` + critical |
| `OT_LLM_ENRICH` | `0` → POC 時 `1` | 總開關 |
| `OT_LLM_ONLY_ON` | `episode` | 固定 episode（不支援 event） |
| `LLM_MODEL` | `gemma2:9b` | 非 OT Wazuh 路徑保留 |

**203 部署步驟（POC）：**

```bash
ollama pull gemma2:2b
# docker-compose.layerc.yml 或 .env.layerc 覆寫 OT_LLM_* 
docker compose -f docker-compose.yml -f docker-compose.layerc.yml up -d --build layerc-api layerc-bridge
```

**Story S4-C3：** `docker-compose.layerc.yml` 註解與 `.env.example` 文件化 OT_LLM_*。

### C.3 Agentic RAG — OT 窄域 Agent

**不重用** Wazuh multimodal EvidenceOps；新建 **OT KB + tool registry**。

#### Retriever（KB v0 目錄）

```
Aristaconnector-Control-Plane/kb/ot_security/
├── rules/
│   ├── OT-001.md … OT-018.md      # 各 rule 中文說明、觸發條件、誤報情境
├── protocols/
│   ├── iec61850-mms-glossary.md
│   ├── goose-basics.md
│   └── modbus-tcp-write.md
├── runbooks/
│   ├── commissioning-vs-attack.md
│   ├── mms-write-response.md
│   └── purdue-segmentation.md
└── manifest.json                   # chunk id, tags, purdue_level
```

Embedding：本地 `nomic-embed-text` 或 BM25 fallback（無 GPU 時）。  
**Story S4-C4：** KB v0 至少 18 rule 檔 + 3 runbook；chunk + manifest。

#### Tools（episode 級）

| Tool | 輸入 | 輸出 |
|------|------|------|
| `get_rule_meta(rule_id)` | OT-016 | severity, purdue, mitre_ot_ref |
| `get_entity_history(entity_key, hours=24)` | entity | event counts by rule |
| `get_behavior_score(entity_key)` | entity | score, label, warm-up |
| `get_baseline_status(site_id)` | site | asset count, learning phase |
| `get_episode_evidence(episode_id)` | episode | 前 5 evidence snippets |

**Story S4-C5：** tool implementations；agent loop max 3 tool rounds。

#### LLM 輸出 Schema（`layerc_ttp_reasoning` 擴充）

```json
{
  "schema_version": "ot_security.v2",
  "category": "ot_security",
  "severity": "high",
  "rule_id": "OT-016",
  "sensor_id": "ot-edge-001",
  "site_id": "factory-lab-001",
  "purdue_level": "L2",
  "summary_zh": "非 baseline MMS client 對 IED 執行寫入操作，過去 24h 同 sensor 無類似行為。",
  "severity_rationale_zh": "MMS write 直接影響邏輯節點，且來源 IP 不在已知工程站清單。",
  "recommended_actions": [
    {"priority": 1, "action_zh": "隔離來源 IP 192.168.10.88 與 IED 間 MMS 連線", "category": "contain"},
    {"priority": 2, "action_zh": "比對 PCAP 證據與 baseline 工程站清單", "category": "investigate"}
  ],
  "behavior_score": 0.91,
  "behavior_label": "anomaly",
  "llm_model": "gemma2:2b",
  "llm_enriched": true,
  "kb_citations": ["OT-016", "runbook/mms-write-response"],
  "confidence": 0.82
}
```

**向下相容：** Portal 仍讀 `summary_zh`、`severity`；新欄位 optional。  
**Story S4-C6：** schema validator + e2e 擴充 `scripts/e2e-ot-layerc-analyze.py --expect-llm`。

### C.4 Multimodel 策略

| 層級 | 模型 | 觸發 |
|------|------|------|
| 預設 enrich | gemma2:2b | eligible episode |
| Escalation | gemma2:9b | `severity=critical` 且 `OT_LLM_ESCALATION=1` |
| 非 OT | gemma2:9b | 既有 Layer C |

**Multimodal（Phase 2+）：** PCAP 統計特徵（包長分布、port entropy）作為額外 tool 輸出，**不**將 raw bytes 送入 LLM。

### Epic C 驗收

- [ ] `OT_LLM_ENRICH=0` 行為與現行完全一致
- [ ] `OT_LLM_ENRICH=1` 時 10 個 lab episode 人工評分：summary 可讀、無明顯 hallucination
- [ ] P95 LLM 延遲 < 15s（2B，203 Mac mini）
- [ ] `evidenceops=false` 不變；E2E `e2e-ot-layerc-analyze.py` PASS

---

## Epic D — Portal Layer C 卡片化

**Repo：** `guacamole-ai/sensel_control_plane/`（OT 安全 UI + ingest）

### D.1 呈現

| 區塊 | 內容 |
|------|------|
| 摘要卡 | `summary_zh`、`severity` badge、Purdue、rule_id |
| 行為卡 | `behavior_score` 進度條、`behavior_label` |
| 建議動作 | `recommended_actions[]` 有序列表 |
| 引用 | `kb_citations` chips |
| 進階 | 折疊 raw `layerc_reasoning` JSON |

**Story S4-D1：** OT 事件詳情頁 Layer C section 元件。  
**Story S4-D2：** ingest 路徑確認 `_extract_layerc_summary` 讀取 v2 欄位。

### Epic D 驗收

- [ ] 108 Portal 開啟 OT 事件可見卡片（非僅 JSON）
- [ ] F2 告警 email 仍可用 `summary_zh`（`guacamole-ai/sensel_control_plane/services/ot_security/alert_dispatcher.py`）

---

## Story 總表

| ID | Epic | Story | Repo | 優先 |
|----|------|-------|------|------|
| S4-A1 | A | Design tokens | sensel-ot-edge-sensor | P0 |
| S4-A2 | A | 總覽四卡 | sensel-ot-edge-sensor | P0 |
| S4-A3 | A | 事件列表 UX | sensel-ot-edge-sensor | P1 |
| S4-B1 | B | Feature extractor | Aristaconnector-Control-Plane | P0 |
| S4-B2 | B | AE 推理整合 | Aristaconnector-Control-Plane | P0 |
| S4-B3 | B | entity_state schema | Aristaconnector-Control-Plane | P0 |
| S4-B4 | B | 訓練腳本 + model artifact | Aristaconnector-Control-Plane | P1 |
| S4-B5 | B | Feature flag worker | Aristaconnector-Control-Plane | P0 |
| S4-C1 | C | ot_llm_enrich pipeline | Aristaconnector-Control-Plane | P0 |
| S4-C2 | C | Fail-closed + eligibility | Aristaconnector-Control-Plane | P0 |
| S4-C3 | C | 203 env / compose 文件 | Aristaconnector-Control-Plane | P0 |
| S4-C4 | C | OT KB v0 | Aristaconnector-Control-Plane | P0 |
| S4-C5 | C | Agent tools | Aristaconnector-Control-Plane | P1 |
| S4-C6 | C | Schema + e2e | Aristaconnector-Control-Plane | P0 |
| S4-D1 | D | Portal 卡片 UI | guacamole-ai | P1 |
| S4-D2 | D | Ingest v2 欄位 | guacamole-ai | P1 |

---

## 建議時程（2 週）

| 天 | 邊緣 (A) | CP (B+C) | Portal (D) |
|----|----------|----------|------------|
| D1–2 | A1 tokens + A2 四卡 | B1 feature extractor | — |
| D3–4 | A3 事件列表 | B2–B3 AE + entity_state | D2 ingest |
| D5 | Pi deploy 驗證 | C4 KB v0 | — |
| D6–7 | — | C1–C3 LLM enrich POC | D1 卡片 |
| D8–9 | — | B4 訓練 + B5 flag | 整合測試 |
| D10 | 文件 | C6 e2e + 10 episode 評分 | E2E 108 |

---

## 測試計畫

| 測試 | 命令 / 方法 |
|------|-------------|
| Layer C OT E2E | `PYTHONPATH=. python3 scripts/e2e-ot-layerc-analyze.py --layerc-url http://192.168.1.203:8001` |
| LLM enrich E2E | 同上 + `--expect-llm`（Sprint 4 新增） |
| AE 單元 | `pytest sensel-inferplane/tests/test_ot_behavior_*.py` |
| Edge Console | 手動 Pi `:8090` + 既有 pytest |
| Portal | 108 開 episode 有 `summary_zh` + `recommended_actions` |
| 負載 | 203 上確認 LLM QPS < 0.01（episode 限流） |

---

## 風險與緩解

| 風險 | 緩解 |
|------|------|
| 2B 摘要品質不足 | escalation 9B；prompt + RAG citation 約束 |
| AE 冷啟動誤報 | warm-up 24h；drift 只降 trust 不單獨告警 |
| 203 Ollama OOM | 2B 預設；與 9B 錯峰；`OT_LLM_MAX_PER_SENSOR_HOUR` |
| LLM 幻覺 | 必須引用 KB rule_id；tool  grounding；temperature=0.2 |
| 三 repo 協調 | 本文件為單一 spec；各 repo PR 連結 Story ID |

---

## 環境變數速查（203 `.env.layerc` 建議）

```bash
# Layer C OT profile（既有）
LAYERC_OT_ANALYZE_PROFILE=1
LAYERC_BRIDGE_MODE=live
AGENT_MODE=rule

# Sprint 4 — LLM
OT_LLM_ENRICH=1
OT_LLM_MODEL=gemma2:2b
OT_LLM_MAX_TOKENS=256
OT_LLM_MAX_PER_SENSOR_HOUR=12
OT_LLM_ESCALATION=0
OT_LLM_ESCALATION_MODEL=gemma2:9b

# Sprint 4 — Layer B AE
OT_BEHAVIOR_AE_ENABLED=1
OT_BEHAVIOR_WINDOW_SEC=300
OT_BEHAVIOR_STEP_SEC=60
OT_BEHAVIOR_WARMUP_WINDOWS=288
OT_BEHAVIOR_MODEL=autoencoder
```

---

## 相關文件

- [`sprint-plan.md`](sprint-plan.md) — Sprint 總覽
- [`detection-rules.md`](detection-rules.md) — OT-001~018
- [`runbook-ot-lab-deploy.md`](runbook-ot-lab-deploy.md) — 三節點部署
- [`architecture.md`](architecture.md) — 邊緣雙路徑
- CP `Aristaconnector-Control-Plane/docs/architecture/LAYER_B_INFERENCE.md`
- CP `src/pipeline/ot_security_layer_c_run.py` — 現行 OT Layer C
- CP `sensel-inferplane/b1_ingress/ot_security_adapter.py` — 現行 OT Layer B

---

## Sprint 5 預留（不在 Sprint 4 範圍）

- LSTM / GRU 序列異常模型
- PCAP 統計 multimodal tool
- Edge Console React rewrite
- 9B 預設 escalation 策略與 A/B 評測框架
