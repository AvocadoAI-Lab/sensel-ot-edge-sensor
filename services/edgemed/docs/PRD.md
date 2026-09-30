# Avocdo EdgeMed Security v0.1 — Product Requirements Document

| 欄位 | 內容 |
|---|---|
| PRD 版本 | 0.2 Reviewed Draft |
| 產品版本 | Q3 Benchmark Alpha |
| 目標日期 | 2026-09-30 Q3 Alpha；W9–12 延伸為 Q4 testbed hardening |
| Product owner | Avocdo.ai |
| Release type | Research / Developer Preview |

## 1. Product vision

Avocdo EdgeMed Security 是一套可地端部署、被動監控、以證據為核心的醫療 AIoT／OT 威脅與異常偵測引擎。它以並行的 XGBoost 與 LSTM Autoencoder 產生 detector evidence，再由小型語言模型整理、deterministic RAG state machine 補充來源，協助資安人員理解異常網路行為，同時不影響設備可用性。

### One-line value proposition

> Detect known and unknown medical AIoT threats locally, then turn every alert into a source-grounded, reviewable investigation event.

## 2. 問題陳述

醫療 AIoT／OT 場域存在以下問題：

- 設備無法安裝一般 endpoint agent。
- 舊型系統與韌體無法快速更新。
- 臨床服務無法容忍錯誤阻斷。
- 傳統 IDS 告警缺少設備狀態與臨床脈絡。
- 未知攻擊無法完全依賴 signature。
- SOC 難以從大量 Flow 與日誌快速整理 evidence。
- 敏感流量不適合傳送至外部雲端 LLM。

## 3. 產品目標

### Q3 Alpha 目標

1. 證明公開 IoMT 資料上的已知攻擊與未知異常偵測可行。
2. 證明偵測模型可在 edge-class 硬體推論。
3. 建立可追溯、可驗證的 Security Event Schema。
4. 以 `HuggingFaceTB/SmolLM2-360M-Instruct` 證明英文、edge-first SLM 能忠實產生 evidence-grounded JSON 摘要、有限 taxonomy 與受控 retrieval intent，而不是取代 detector。
5. 證明 deterministic orchestrator／allowlisted state machine 能以 read-only 工具取得相關設備與威脅資訊；360M SLM 不直接執行 function call。
6. 建立進入虛擬醫院 testbed 前的技術基線。

### Non-goals

- 不取代醫院 SIEM／SOC。
- 不提供臨床決策。
- 不承諾辨識所有 zero-day。
- 不自動隔離醫療設備。
- 不提供自主攻擊 Agent。
- 不把 360M SLM 當成自由 tool-calling agent，也不讓任何生成模型產生 detector score、severity score 或設備／網路寫入。
- 不聲稱符合特定法規或醫療器材認證。

## 4. 目標使用者

### Persona A — Hospital SOC Analyst

需求：快速知道哪一台設備異常、為何異常、是否有相關事件，以及下一步查什麼。

痛點：告警太多、設備命名不一致、缺少醫療設備脈絡。

### Persona B — Hospital Network / Security Engineer

需求：被動監控 SPAN/TAP 流量，了解正常通訊關係並辨識異常目的地或頻率。

痛點：不能在設備上安裝 agent，也不能冒險主動掃描。

### Persona C — Clinical / Biomedical Engineer

需求：確認告警是否其實是正常開機、維護、互動或韌體更新。

痛點：一般資安工具不理解設備 lifecycle state。

### Persona D — Security Researcher / Testbed Operator

需求：以可重現 benchmark 評估防禦模型，並為虛擬醫院建立受控情境。

痛點：公開資料常有 leakage，研究結果難以轉移至場域。

## 5. 核心使用流程

### Flow A — 即時異常調查

```text
1. Sensor 接收 Flow metadata
2. XGBoost 輸出 known-attack probabilities
3. LSTM Autoencoder 輸出 anomaly score
4. Fusion layer 建立 evidence event
5. SmolLM2-360M 產生 evidence-grounded JSON 摘要、有限 taxonomy 與 retrieval intent enum
6. Deterministic orchestrator 驗證 intent，依固定 state machine 查 asset、threat、playbook、related events
7. Guardrails 驗證來源、schema 與 action
8. API / dashboard 顯示 advisory event
```

### Flow B — 模型或 RAG 失效

```text
Detector 正常、SLM 格式／grounding 失效或 RAG unavailable
→ 使用 template-based event
→ 保留兩個 detector 的原始 score、threshold、evidence 與 version
→ 標示 `generation_fallback`／`enrichment_unavailable`
```

單一 detector 失效時輸出 `partial_detection` 並保留另一 detector；兩者均失效時回傳 service error，不產生推測性 verdict。

### Flow C — Benchmark

```text
固定 dataset manifest
→ preprocessing
→ training
→ independent evaluation
→ artifact hash
→ report generation
```

## 6. 功能需求

### FR-1 資料輸入

系統應支援：

- CSV flow records。
- REST JSON flow records。
- 後續可擴充 Zeek／Suricata event adapter。

每筆事件應包含 numeric features；asset ID、device type、operating state 可選。缺失脈絡不得由模型自行猜測。

### FR-2 Preprocessing

- 依 versioned feature schema 驗證欄位。
- 處理 NaN、inf 與缺失值。
- 使用訓練時保存的 scaler／imputer。
- 不允許 label、attack name、capture ID 進入模型特徵。
- Schema mismatch 必須清楚報錯或進入 degraded mode。

### FR-3 XGBoost Known Threat Classifier

- 輸出 top class、per-class probability、model version。
- 支援至少 binary 與 category classification。
- 提供 top contributing features。
- 不將 probability 命名為真實世界的 certainty。

### FR-4 LSTM Autoencoder

- 依 device/session 建立 sequence，不得跨設備拼接。
- 主要模型以 benign-only data 訓練。
- 輸出 raw reconstruction error、normalized anomaly score、threshold 與 model version。
- 支援 device/state-specific threshold 的後續擴充。

### FR-5 Risk Fusion

- 保留 XGBoost 與 LSTM 原始輸出。
- 初版 severity 由 deterministic policy 決定。
- 支援 asset criticality 與 operating state；缺失時標示 unknown。
- 不允許 SLM 覆寫 detector score。

### FR-6 Fine-tuned SLM

- Q3 起始與 release 預設模型固定為 `HuggingFaceTB/SmolLM2-360M-Instruct`（英文、Apache-2.0、edge-first）；Apple M2 Pro 16GB 執行 LoRA／PEFT fine-tune，Raspberry Pi 5 8GB 以量化 GGUF／`llama.cpp` 推論。
- 輸入只能是 versioned fused evidence event，不直接輸入 raw PCAP、payload 或未治理自由文字。
- 輸出只能是指定 JSON：`summary_en`、allowlisted `taxonomy`、既有 `evidence_ids`、allowlisted `retrieval_intents` 與 `status`。
- SLM 可引用 evidence ID，但不能建立 evidence、數值、detector score、threshold、severity score 或工具參數；detector 與 policy-owned 欄位對 SLM 為 read-only。
- 不足以判斷時輸出 `insufficient_evidence`；輸出封鎖、停機、修改設備、網路寫入或攻擊操作內容時立即 fallback。

SFT dataset 使用 JSONL，每列包含 `record_id`、`split_group`、`input`、`target`、`metadata`。`input` 必須含 schema version、detector outputs、帶 ID 的 evidence 與最小 asset context；`target` 必須含英文摘要、taxonomy、evidence IDs、retrieval intent enum 與 status；`metadata` 記錄來源、reviewer、policy version。資料集必須包含 evidence insufficient、detector conflict、unknown taxonomy、instruction-like log text、empty retrieval 等 negative cases，並以 scenario/device group 隔離 train/validation/test。

Model selection exit criteria：360M 完成一輪基線及一輪 targeted fine-tune 後，若仍未達 frozen SLM test gate，或 Pi 5 實測無法符合記憶體／延遲門檻，才可評估 `HuggingFaceTB/SmolLM2-1.7B-Instruct` 或約 2B 級 Granite instruct model。升級候選必須通過授權／來源、M2 Pro 16GB fine-tune、Pi 5 runtime 及 frozen test 的實質改善審查；Q3 首選仍固定為 360M，升級不是 Alpha 必交付。

### FR-7 Agentic RAG

初版 Agentic RAG 由 deterministic orchestrator／allowlisted state machine 執行固定 investigation graph：

1. Asset lookup。
2. Behavior baseline lookup。
3. Threat knowledge lookup。
4. Related-event lookup。
5. Playbook lookup。
6. Compose source-grounded report。

360M SLM 只能輸出 retrieval intent enum，不能選擇任意工具名稱、建立參數或直接執行 function call。Orchestrator 依 policy、event fields 與 budget 決定是否呼叫既有工具；不得自由新增工具，每個工具均為 read-only，最多 5 次 retrieval，無遞迴或自我修改。

### FR-8 Safety Guardrails

- 輸入 schema validation。
- 文件內容與系統指令分離。
- Tool allowlist。
- Tool argument validation。
- 最大 5 次 deterministic retrieval steps。
- Timeout 與 token budget。
- Output schema validation。
- Claim-to-source validation。
- Prohibited action filter。
- Human approval indicator。
- 完整 audit trail。

### FR-9 Event API

最低 API：

- `GET /health`
- `GET /api/model`
- `POST /api/score`
- `POST /api/investigate`
- `GET /api/events/{event_id}`

### FR-10 Dashboard

Dashboard 應顯示：

- Device ID/type/state。
- Known attack prediction。
- Anomaly score 與 threshold。
- Top evidence。
- Retrieved sources。
- Severity 與 summary。
- Advisory actions。
- Detector、SLM、RAG 狀態。

### FR-11 Model lifecycle

- 所有 artifact 有版本與 hash。
- 支援上一版本 rollback。
- API event 保存各 detector/model version。
- 模型不可在 production-like runtime 自動線上學習。

### FR-12 Degraded mode 與 fallback

- SLM timeout、JSON invalid、未知 taxonomy、引用不存在 evidence 或 prohibited content：直接採 deterministic template，不把生成內容部分修補後發布。
- Retrieval intent invalid：降為 `none`；orchestrator 仍可依 policy 執行必要的 asset／playbook lookup。
- RAG timeout、空結果、index unavailable 或 citation mismatch：保留 detector／fusion event，標示 `enrichment_unavailable`，不得用模型常識補齊。
- 單一 detector unavailable：標示 `partial_detection`；兩 detector 均 unavailable：`POST /api/score` 回傳明確 service error，不呼叫 SLM/RAG。
- Dashboard 與 API 必須顯示實際 degraded state、fallback reason 與 component version。

## 7. Security Event Schema

```json
{
  "schema_version": "0.1",
  "event_id": "evt_...",
  "timestamp": "2026-09-15T08:30:00Z",
  "asset": {
    "device_id": "hashed-device-id",
    "device_type": "patient_monitor",
    "operating_state": "idle",
    "criticality": "high"
  },
  "detection": {
    "known_attack": {
      "category": "mqtt_publish_flood",
      "probability": 0.94,
      "model_version": "xgb-0.1.0"
    },
    "anomaly": {
      "score": 0.82,
      "threshold": 0.71,
      "model_version": "lstm-ae-0.1.0"
    }
  },
  "evidence": [
    {
      "evidence_id": "ev_1",
      "feature": "flow_packets_per_second",
      "observed": 840,
      "baseline": 76,
      "source": "detector:event-window-391"
    }
  ],
  "enrichment": {
    "status": "available",
    "retrieval_intents": ["asset_context", "playbook_lookup"],
    "sources": [
      {
        "source_id": "asset-profile:patient-monitor-a",
        "source_type": "asset"
      }
    ]
  },
  "assessment": {
    "verdict": "suspected_attack",
    "severity": "high",
    "severity_source": "fusion-policy-0.1",
    "summary": "Observed network behavior exceeded the recorded baseline and matched a known detector category.",
    "summary_source": "smollm2-360m-adapter-0.1",
    "evidence_ids": ["ev_1"],
    "taxonomy": "network_behavior_anomaly",
    "generation_status": "generated"
  },
  "response": {
    "mode": "advisory_only",
    "human_approval_required": true,
    "recommended_actions": ["verify_device_state"]
  }
}
```

## 8. RAG 知識模型

| Namespace | 內容 | Q3 資料來源 |
|---|---|---|
| Asset KB | 設備類型、協定、正常目的地 | 合成／公開範例 |
| Behavior KB | idle、active、interaction baseline | CICIoMT2024 衍生摘要 |
| Threat KB | CVE、CWE、ATT&CK/ICS 摘要 | 公開資料的受控快照 |
| Playbook KB | 調查步驟與 escalation | Avocdo 範例 playbooks |
| Evidence KB | Detector event 與歷史事件 | MVP runtime data |

Q3 不把公開資料與未來院內資料混在同一 namespace。文件只能作為 retrieval evidence，不得改寫 system policy 或工具權限。Retrieved document 全部視為 untrusted data；只有 state machine 能映射 intent → allowlisted tool → validated arguments。每個 enrichment claim 必須指向實際 retrieved source ID；查無來源即省略 claim 並標示 `insufficient_evidence`，不得由 SLM 以內建知識補齊。

Q3 RAG 邊界：只做本地、read-only、單事件 investigation；不做 web search、shell、程式執行、任意 URL fetch、網路／設備變更、開放式 agent loop、跨 namespace 自動合併或把 retrieved instructions 當命令。

## 9. 安全需求

### SR-1 被動模式

系統不得要求 inline deployment，不得向被監控設備發送封包。

### SR-2 Advisory only

所有處置均為建議；API 不提供 isolate、block、shutdown 或 firewall-write endpoint。

### SR-3 Data minimization

- 預設不保存 payload。
- 預設使用 hashed device identifier。
- 預設 local-only inference。
- 外部網路呼叫必須顯式設定並記錄。

### SR-4 Model supply chain

- 模型與依賴有 hash。
- Release 建立 SBOM。
- 僅載入 allowlisted model artifact。
- 模型更新失敗時保持現行版本。

### SR-5 RAG security

- 防止 retrieved document prompt injection。
- Knowledge data 與 instructions 分離。
- Retrieved claims 需附 source ID。
- 不允許 retrieval document 建立新工具或提高權限。

## 10. 非功能需求

### NFR-1 Availability

- Detector 不依賴外部 LLM 或網路。
- SLM／RAG 失效時可降級。
- Collector 故障不得影響被監控網路。

### NFR-2 Performance

- 固定在 Pi 5 8GB、主動散熱、量化 360M GGUF／`llama.cpp` 上完成實測；SLM 單事件最多生成 160 tokens，warm-run P95 ≤ 10 秒、服務 peak RSS ≤ 4GB、不得 OOM；detector 單事件 P95 ≤ 500ms。
- 未通過上述門檻可發布 benchmark artifact，但不得標示 Pi 5 ready。Flows/sec 只報告實測值，不由單事件 latency 推估。
- API 應分別記錄 detector latency 與 enrichment latency。
- Q3 報告 P50、P95、RAM、CPU、temperature 及 dropped events。
- 24 小時 soak 不得有 process crash、模型自動重載失敗或未揭露外部呼叫；dropped-event rate 依固定輸入負載報告，不預先承諾未知場域吞吐量。

### NFR-3 Reproducibility

- 固定 seed、manifest、environment lock、artifact hash。
- Benchmark 可由單一命令重現。

### NFR-4 Explainability

- 每個 detector verdict 都有 top evidence。
- 每個 RAG claim 都有 source。
- 每個事件都有模型與政策版本。

### NFR-5 Privacy

- 系統不需要病患身分資料即可運作。
- 除錯資料不得默認包含 payload 或 PHI。

## 11. Product metrics

### Detection metrics

- Binary ROC-AUC、PR-AUC、precision、recall 與 bootstrap 95% CI。
- Category macro-F1、per-class support 與 confusion matrix；random split 只作診斷。
- Session/device-aware holdout macro-F1；若 metadata 不足須揭露。
- Anomaly ROC-AUC、PR-AUC、TPR@5% FPR、實際 benign FPR 與 95% CI。
- LSTM AE 對 Isolation Forest 的主要 holdout PR-AUC 差值。

### SLM/RAG metrics

- Raw／post-guardrail JSON valid rate。
- Evidence-ID precision 與 exact-match。
- Unsupported factual claim rate 與 guardrail escape count。
- Retrieval precision@k。
- Claim citation coverage。
- `insufficient_evidence` precision／recall／F1。
- Taxonomy allowlist violation count 與 retrieval-intent exact-match。

### Edge metrics

- P50/P95 detector latency。
- P50/P95 investigation latency。
- Peak RAM。
- CPU utilization。
- Temperature／thermal throttling。
- Dropped-event rate。
- 24-hour stability。

### Product readiness metrics

- 可重現 benchmark 成功率。
- Model card／Data card 完成率。
- Guardrail test pass rate。
- API schema compatibility。

## 12. Release acceptance criteria

### 必須達成

- End-to-end flow 可由 CSV 產生 source-grounded event。
- XGBoost 與 anomaly detector 可分別啟用／停用。
- `HuggingFaceTB/SmolLM2-360M-Instruct` 在 M2 Pro 16GB 完成 LoRA／PEFT，交付 adapter、量化 GGUF、SFT schema/provenance、Model Card 與 frozen test report；Pi 5 以 `llama.cpp` 實測。
- SLM 不可產生／覆寫 detector score 或直接呼叫工具；RAG 只能由 deterministic、read-only state machine 執行。
- SLM／RAG／單一 detector／兩 detector 失效路徑通過 failure-injection 與 fallback tests。
- Safety guardrails 阻止 prohibited actions。
- 所有 output 通過 JSON schema。
- Benchmark、model card、data card 與 known limitations 完成。
- Pi 5 8GB 有 24 小時 soak、P50/P95、peak RSS、CPU、溫度、OOM／crash 與 dropped-event 實測報告。
- Frozen SLM test set至少 200 筆且至少 30% 為 negative／insufficient cases；若不足必須揭露，且不得用百分比外推。
- Raw JSON valid rate ≥ 95%；對外 post-guardrail JSON valid rate = 100%。
- Evidence-ID precision = 100%、evidence exact-match ≥ 95%、unsupported factual claim rate ≤ 3%、`insufficient_evidence` F1 ≥ 0.90；任何不存在 evidence、未知 taxonomy 或 prohibited content 均不得通過 guardrail。

### 目標但可帶限制發布

- XGBoost 在主要 group-aware holdout 的 category macro-F1 優於 Logistic Regression，或差距絕對值 ≤ 0.03 且 edge 效能更佳。
- LSTM AE 在可信 sequence split 的 PR-AUC 優於 Isolation Forest，或差距絕對值 ≤ 0.03 且提供 temporal evidence。
- Anomaly `TPR@5% FPR ≥ 0.60`。
- Retrieval precision@5 ≥ 0.80、最終 knowledge claim citation coverage = 100%。
- Pi 5 warm-run SLM P95 ≤ 10 秒、detector P95 ≤ 500ms、peak RSS ≤ 4GB、無 OOM。

未達「目標但可帶限制發布」可發布 Alpha，但必須在 Release Notes 與 Model Card 明確揭露，不得選擇性只公布最佳 split，也不得使用 Pi 5 ready、unknown-threat ready 等宣稱。未達「必須達成」則 No-Go。

### Definition of Done

- Data：frozen manifest、leakage audit、group-aware evaluation、preprocessing config／hash 可重現。
- Detection：XGBoost 與 LSTM AE 並行；detector、fusion、policy 欄位與 SLM 欄位權限隔離且有 schema tests。
- SLM：360M fine-tune、adapter、GGUF、frozen evaluation、provenance、Model Card 與 fallback template 完整。
- RAG／Safety：deterministic state machine、read-only allowlist、citation validation、prompt/log injection cases、audit trail 與所有 degraded paths 測試通過。
- Edge／Product：Pi 5 報告、24 小時 soak、API、dashboard、release／architecture／threat／privacy／known-limitations 文件完成。
- Positioning：所有介面與文件明示非臨床、advisory-only；沒有自動阻斷、設備寫入、攻擊操作、zero-day、法規或臨床效能宣稱。

## 13. User stories

### US-1

作為 SOC analyst，我希望看到 detector score 與 top evidence，以便在不相信生成式摘要時仍可獨立判斷。

驗收：關閉 SLM 後事件仍包含完整 detection 與 evidence。

### US-2

作為 network engineer，我希望系統完全被動，以避免監控產品影響醫療設備。

驗收：產品無任何必要的 network write path。

### US-3

作為 biomedical engineer，我希望告警顯示設備 operating state，以判斷它是否為正常臨床活動。

驗收：state 缺失時顯示 unknown，而非推測。

### US-4

作為 security researcher，我希望重現公開 benchmark，以驗證結果沒有來自資料洩漏。

驗收：提供 manifest、seed、config、hash 與一鍵執行方式。

### US-5

作為產品安全審查者，我希望每個 Agent 行動都有 audit log，以確認它沒有嘗試未授權操作。

驗收：記錄 tool、arguments、policy decision、result 與 timestamp。

## 14. 風險與緩解

| 風險 | 影響 | 緩解 |
|---|---|---|
| CICIoMT 過度擬合 | 實院失效 | Device/session/attack holdout |
| SLM 幻覺 | 錯誤調查建議 | Evidence-only generation + fallback |
| RAG prompt injection | 權限提升 | Instruction/data separation + allowlist |
| LSTM 無可信時間序列 | 結果無效 | 保留 Isolation Forest；揭露限制 |
| Pi 5 過熱或延遲 | 無法 edge 部署 | Active cooling、量化、分離 enrichment |
| 誤報過多 | SOC 拒用 | Threshold calibration、dedup、state context |
| 醫療設備被錯誤阻斷 | 病人安全風險 | Advisory-only、無 write API |
| 授權不清 | 無法商用 | Release 前完成模型與資料授權審查 |

## 15. 後續版本

### v0.5 — Virtual Hospital Preview

- 受控正常與攻擊情境。
- Red／blue test harness。
- 72 小時 soak test。
- Prompt/log injection red-team。

### v0.7 — Hospital Shadow Pilot

- 真實 SPAN/TAP metadata。
- 30 天 observe、30 天 shadow alert。
- 院方標註與 threshold calibration。

### v1.0 — GA candidate

- 至少兩個不同場域驗證。
- 工業級 edge hardware。
- Signed update、TPM、rollback、SBOM。
- SIEM integrations 與正式維運文件。
