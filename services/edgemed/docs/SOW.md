# Avocdo EdgeMed Security v0.1 — Statement of Work

| 欄位 | 內容 |
|---|---|
| 文件版本 | 0.2 Reviewed Draft |
| 專案版本 | Avocdo EdgeMed Security v0.1 Benchmark Alpha |
| 目標發布 | 2026 Q3 Alpha（2026-09-30 前）；Q4 testbed hardening 至 W12 |
| 文件狀態 | 供立項、執行與合作討論 |
| 產品狀態 | Research / Developer Preview |
| 使用限制 | 非臨床使用；不得自動阻斷或隔離醫療設備 |

## 1. 專案目的

本專案將建立一套可在 edge-class 硬體運行的醫療 AIoT／OT 資安 MVP，以 CICIoMT2024 為第一階段公開 benchmark 資料，驗證下列能力：

1. 使用 XGBoost 辨識已知網路攻擊。
2. 使用 LSTM Autoencoder 建立正常流量基線並產生異常分數。
3. 融合已知攻擊機率、異常分數與設備脈絡，產生可追溯的安全事件。
4. 以 `HuggingFaceTB/SmolLM2-360M-Instruct`（英文、Apache-2.0、edge-first）為 Q3 唯一起始生成式 SLM，在 Apple M2 Pro 16GB 進行 LoRA／PEFT fine-tune，將結構化證據轉為 evidence-grounded JSON 摘要、有限 taxonomy 與受控 retrieval intent。
5. 由 deterministic orchestrator／allowlisted state machine 執行 Agentic RAG，查詢設備資料、威脅知識與處置手冊，產生附來源的調查結果；360M SLM 不直接呼叫工具。
6. 建立簡易安全柵欄，限制模型輸入、輸出、工具與處置權限。
7. 在 Apple M2 Pro 16GB 完成訓練與開發，並驗證 Raspberry Pi 5 等級的推論可行性。

## 2. 系統範圍

### 2.1 目標架構

```text
PCAP / Flow CSV / Device Logs
               ↓
      Feature Preprocessing
               ↓
   ┌───────────┴────────────┐
   │                        │
XGBoost                LSTM Autoencoder
Known threats          Unknown anomalies
   │                        │
   └───────────┬────────────┘
               ↓
        Risk / Evidence Fusion
               ↓
      Fine-tuned Security SLM
               ↓
           Agentic RAG
   Asset / Threat / Playbook KB
               ↓
    Schema + Policy Safety Guardrails
               ↓
        Advisory Security Event API
```

XGBoost 與 LSTM 為並行偵測器，不將 XGBoost 結果當作 LSTM 必要輸入。融合層保留兩者原始分數、版本及 evidence，避免形成不可追溯的單一信心分數。SLM 只能轉述融合層輸入，不能產生、重算或覆寫 detector score。圖中的 Agentic RAG 由 deterministic orchestrator 執行；SLM 最多輸出受 schema 約束的 retrieval intent enum。

### 2.2 In scope

- CICIoMT2024 資料盤點、清理及 leakage audit。
- Binary、attack category 及可行時的 fine-grained attack classification。
- XGBoost 已知攻擊 baseline。
- Isolation Forest 作為最低成本異常 baseline。
- LSTM Autoencoder benign-only anomaly baseline。
- Session-aware、device holdout、attack-family holdout 評估。
- 結構化 Security Event Schema v0.1。
- 固定以 `HuggingFaceTB/SmolLM2-360M-Instruct` 作為 Q3 生成式 SLM；以英文指令／輸出為預設，使用 LoRA／PEFT fine-tune，並匯出量化 GGUF 供 Pi 5 上的 `llama.cpp` 推論。
- Apple M2 Pro 16GB 上的 SLM fine-tune 可行性與 Raspberry Pi 5 8GB 上的單事件推論實測。
- 小型本地知識庫與 deterministic-first Agentic RAG。
- 簡易 API、dashboard 及 Raspberry Pi 5 推論測試。
- 基本 safety guardrails、audit log、model card 與 benchmark 文件。

### 2.3 Out of scope

- 真實醫院臨床效能宣稱。
- 衛福部虛擬醫院驗證完成宣稱。
- 自動封鎖、隔離或改寫網路政策。
- 主動掃描或封包注入。
- 通用自主攻擊 Agent。
- 病患診斷、治療或臨床決策。
- 醫療器材法規認證或合規保證。
- 完整 SIEM、SOAR、CMDB 或醫療設備全球資料庫。
- 從零預訓練 foundation model。
- 讓 360M SLM 自由規劃、多輪自我反思、執行任意 function call 或產生 detector score。

## 3. 工作包與交付物

### WP1 — 資料工程與 Benchmark 治理

工作內容：

- 盤點 CICIoMT2024 檔案、欄位、標籤、協定與設備狀態。
- 處理 NaN、inf、極端值、重複列及欄位命名。
- 排除可能造成 label leakage 的 IP、MAC、capture ID、scenario name 等欄位。
- 建立 random、session-aware、device holdout、attack-family holdout manifests。
- 保存 seed、hash、preprocessing config 與特徵字典。

交付物：

- Dataset Card v0.1
- Feature Dictionary
- Dataset Split Manifest
- Leakage Audit Report
- 可重現 preprocessing pipeline

驗收：

- 每次執行可由同一 manifest 產生相同 split。
- scaler、imputer 及 feature selection 只在 training split fit。
- 訓練與測試不共享同一 capture session（適用時）。

### WP2 — Known Threat Detection

工作內容：

- 建立 Logistic Regression、Random Forest 及 XGBoost baseline。
- 進行 class weighting、feature selection 與機率校準。
- 輸出 binary、category 及 fine-grained 結果。
- 提供 top feature evidence。

交付物：

- XGBoost model artifact
- Training configuration
- Classification benchmark report
- Confusion matrices 與 per-class metrics

Alpha 評估與退出條件：

- Random split 僅作診斷，不得作 release headline；release report 以可建立的最嚴格 session/device-aware split 為主。
- 必報 binary ROC-AUC、PR-AUC、recall、precision，以及 category macro-F1 與 per-class support；以 bootstrap 95% CI 呈現。
- XGBoost 應在主要 holdout 的 category macro-F1 優於 Logistic Regression baseline，或在效能相當（差距絕對值 ≤ 0.03）時證明 edge latency／RAM 更佳。未達者仍可發布 Alpha，但不得宣稱 model improvement。
- 每筆推論必須輸出模型版本、類別機率及 top features；沒有足夠樣本的 fine-grained 類別只列 exploratory result。

### WP3 — Behavioral Anomaly Detection

工作內容：

- 建立 Isolation Forest baseline。
- 建立 Dense Autoencoder 或 LSTM Autoencoder。
- 僅以 benign training data 訓練主要 anomaly model。
- 以 benign validation data 設定 threshold。
- 進行 leave-one-attack-family-out 測試。

交付物：

- Isolation Forest artifact
- LSTM Autoencoder artifact
- Threshold configuration
- Anomaly benchmark report

Alpha 評估與退出條件：

- 必報 benign-only threshold 下的 ROC-AUC、PR-AUC、TPR@5% FPR、實際 benign FPR 與 95% CI，不以單一「未知攻擊偵測率」掩蓋 threshold。
- 在具備可信 sequence／session metadata 時，LSTM AE 應優於 Isolation Forest 的 PR-AUC，或差距絕對值 ≤ 0.03 且有可解釋的 temporal evidence；否則 Isolation Forest 保留為 Alpha anomaly baseline，LSTM 標記為 experimental。
- `TPR@5% FPR ≥ 0.60` 為研究目標而非 release gate；未達必須在 Model Card 揭露。
- 每筆輸出 anomaly score、threshold、model version 與 evidence window。

### WP4 — Risk and Evidence Fusion

工作內容：

- 定義 known attack probability、anomaly score、asset criticality 與 operating state 的融合流程。
- 初版採 deterministic rules 或可稽核的輕量 meta-model。
- 建立 alert deduplication 與 severity mapping。

交付物：

- Fusion specification
- Security Event Schema v0.1
- Severity policy
- 範例事件與 schema validation tests

驗收：

- 不以 SLM 產生的數字作為偵測分數。
- 每項結論可追溯到 detector、rule 或 retrieved source。
- JSON schema valid rate = 100%（柵欄後）。

### WP5 — Fine-tuned Security SLM

工作內容：

- Q3 起始與預設模型固定為 `HuggingFaceTB/SmolLM2-360M-Instruct`；英文、Apache-2.0、edge-first。Apple M2 Pro 16GB 執行 LoRA／PEFT fine-tune，Pi 5 使用量化 GGUF／`llama.cpp` 推論。
- 以 versioned fused evidence event、正確摘要、有限 taxonomy、evidence references、`insufficient_evidence` 與 retrieval intent 建立 supervised fine-tuning dataset；不得把 raw PCAP、payload 或未治理自由文字直接餵給 SLM。
- 建立 deterministic template fallback；SLM 輸出未通過 schema／grounding 時，不允許流入 RAG 或最終事件。

SLM 預定任務：

- Evidence-grounded 英文 JSON 摘要。
- 固定、有限 attack taxonomy 映射；未知時輸出 `unknown`。
- 以 evidence ID 選取 evidence，不得建立新 evidence 或數值。
- 從 allowlisted enum 選擇 retrieval intent（如 `asset_context`、`behavior_baseline`、`threat_context`、`playbook_lookup`、`none`），不得輸出任意工具名稱或參數。
- 缺少必要證據時輸出 `insufficient_evidence`。

SLM 明確不負責：

- detector score、severity score、threshold 或風險數值的產生與覆寫。
- 自由 tool calling、開放式 agent loop、網路／設備寫入或攻擊操作建議。

SFT dataset contract（JSONL，每列一個獨立事件）：

```json
{
  "record_id": "sft_000001",
  "split_group": "scenario-or-device-group",
  "input": {
    "schema_version": "evidence-0.1",
    "detector_outputs": {},
    "evidence": [{"evidence_id": "ev_1", "type": "feature_deviation", "value": 2.4}],
    "asset_context": {"device_type": "monitor", "operating_state": "unknown"}
  },
  "target": {
    "summary_en": "Observed evidence requires analyst review.",
    "taxonomy": "unknown",
    "evidence_ids": ["ev_1"],
    "retrieval_intents": ["asset_context"],
    "status": "insufficient_evidence"
  },
  "metadata": {"source": "synthetic-or-benchmark", "annotator": "reviewed", "policy_version": "0.1"}
}
```

Dataset 必須含：有足夠證據、證據不足、衝突 detector、無適用 taxonomy、惡意／指令型 log 文字與空 retrieval 結果等 negative cases。Train/validation/test 依 scenario/device group 隔離，且 test 不得用於 prompt 或 adapter 調整。

Model selection exit criteria：

1. 360M 是 Q3 首選，不因單一 benchmark 分數任意更換。
2. 360M 完成一輪基線與一輪有針對性的 fine-tune 後，若仍無法達到下列 release gate，或 Pi 5 測得輸出品質／延遲不可接受，才啟動升級評估。
3. 後續候選限 `HuggingFaceTB/SmolLM2-1.7B-Instruct` 或約 2B 級 Granite instruct model；候選必須通過授權／來源審查、M2 Pro 16GB fine-tune 可行性、Pi 5 記憶體與延遲實測，且在 frozen test set 有實質改善後才能取代。升級不屬於 Q3 必交付。

交付物：

- SFT dataset schema 與 provenance report
- Adapter／model artifact
- SLM Model Card
- Hallucination 與 schema evaluation report

Release gate（frozen test set 至少 200 筆，含至少 30% negative／insufficient cases；若資料不足則揭露樣本數且不得百分比外推）：

- Raw JSON schema valid rate ≥ 95%；柵欄後對外 JSON valid rate = 100%，無效輸出一律 fallback，不以修補內容掩蓋 hallucination。
- Evidence-ID precision = 100%，evidence exact-match ≥ 95%；任何不存在的 evidence ID 均觸發 fallback。
- Unsupported factual claim rate ≤ 3%，且無 unsupported claim 可通過 claim-to-evidence guardrail。
- `insufficient_evidence` F1 ≥ 0.90。
- Taxonomy 僅可輸出 allowlist 值；retrieval intent exact-match ≥ 90%，但由 orchestrator 最終決定是否執行。

### WP6 — Agentic RAG

工作內容：

- 建立四個知識域：Asset、Behavior、Threat、Playbook。
- 初版使用本地 SQLite／向量索引；公開與院內資料分 namespace。
- 實作 deterministic orchestrator／allowlisted state machine。SLM 的 retrieval intent 僅是受限建議；orchestrator 依 policy、event fields 與 budget 決定固定 investigation graph，不讓 360M 直接呼叫工具。
- 每個 claim 必須附 retrieval source ID。

允許工具：

- `get_asset_profile`
- `get_behavior_baseline`
- `search_threat_knowledge`
- `search_playbook`
- `get_related_events`

交付物：

- Knowledge document schema
- Retrieval pipeline
- Agent workflow specification
- Source-grounded investigation API
- RAG evaluation set

驗收：

- 無來源的 knowledge claim 不得進入最終事件。
- 工具參數通過 allowlist 與 schema validation。
- State machine 最多 5 次 read-only retrieval、每工具 timeout 及整體 time/token budget；沒有遞迴、自我修改或任意迴圈。
- 知識庫不可執行文件內嵌指令。
- Retrieval 無結果、timeout、index unavailable 或 citation mismatch 時，保留 detector event，標示 `enrichment_unavailable` 或 `insufficient_evidence`，不得用模型常識補齊。

### WP7 — Safety Guardrails

工作內容：

- Input schema validation。
- Prompt／log injection pattern detection。
- Tool allowlist 與 read-only policy。
- Output schema validation 與 prohibited-action filter。
- Human approval flag。
- Audit logging。

初版安全政策：

```yaml
mode: advisory_only
network_write_actions: prohibited
device_isolation: prohibited
packet_injection: prohibited
external_scanning: prohibited
tools: read_only_allowlist
max_retrieval_steps: 5
require_source_for_claims: true
human_review_required_before_action: true
```

交付物：

- Safety Policy v0.1
- Guardrail test suite
- Audit event schema
- Known bypass limitations

Fallback 順序：

1. SLM timeout、格式錯誤、未知 taxonomy、引用不存在 evidence 或出現 prohibited content：不重試自由生成；直接使用 deterministic template。
2. Retrieval intent 無效：視為 `none`；orchestrator 仍可依固定 policy 做必要的 asset／playbook lookup。
3. RAG timeout、空結果或 citation validation 失敗：輸出 detector＋fusion＋template event，標示 `enrichment_unavailable`。
4. 任一 detector 失效：保留其他 detector 原始輸出並標示 `partial_detection`；兩個 detector 均失效時回傳 service error，不產生推測性安全結論。

### WP8 — Edge API、Dashboard 與部署

工作內容：

- 提供 `GET /health`、`GET /api/model`、`POST /api/score`、`POST /api/investigate` 與 `GET /api/events/{event_id}` API。
- 建立簡易 dashboard 顯示 asset、score、evidence、retrieved sources 與 advisory action。
- 匯出可在 Pi 5 使用的模型格式，如 ONNX／TFLite／GGUF。
- XGBoost／LSTM 依模型選用 ONNX／原生 runtime；SLM 固定匯出量化 GGUF，以 `llama.cpp` 執行。
- 進行 24 小時 soak test。

交付物：

- FastAPI service
- Web dashboard
- Raspberry Pi 5 deployment guide
- Edge performance report
- Dockerfile 或可重現安裝腳本

驗收：

- `/health` 可分別顯示 detector、SLM、RAG 狀態。
- SLM 或 RAG 失效時，偵測器仍能輸出 template-based event。
- 系統預設 local-only，無未揭露外部網路呼叫。
- 完成 CPU、RAM、P50/P95 latency、temperature 與 dropped-event 測量。
- 在 Pi 5 8GB 主動散熱環境，量化 360M SLM 單事件輸出上限 160 tokens，warm-run P95 ≤ 10 秒、服務 peak RSS ≤ 4GB、不得 OOM；detector 單事件 P95 ≤ 500ms。未達任一項即不得宣稱 Pi 5 ready，但可發布附限制的 benchmark artifact。

### WP9 — Release 文件

交付物：

- README 與 Release Notes
- Product Brief
- System Architecture
- Dataset Card
- 三類 Model Cards
- Benchmark Report
- Threat Model
- Privacy and Data Handling
- API Specification
- Known Limitations
- Virtual Hospital Test Plan draft

## 4. 時程

| 週次 | 主要工作 | Release checkpoint |
|---|---|---|
| W1 | Dataset audit、feature/schema、group-aware split | Dataset freeze |
| W2 | XGBoost、Logistic Regression、Isolation Forest | Tabular baseline review |
| W3 | LSTM AE、sequence validation、threshold calibration | Detector baseline review |
| W4 | Fusion、Event Schema、template fallback | Schema freeze |
| W5 | SFT dataset、360M LoRA／PEFT baseline | SLM baseline review |
| W6 | Deterministic RAG state machine、small KB、guardrails | End-to-end feature freeze |
| W7 | API、dashboard、GGUF／`llama.cpp`、Pi 5 smoke/profile | Q3 release candidate |
| W8 | Frozen rerun、failure injection、文件、已知限制 | **v0.1 Q3 Alpha release** |
| W9–10 | RAG/guardrail hardening、edge optimization | Testbed hardening |
| W11 | 24-hour soak、independent safety review | Testbed readiness review |
| W12 | 修正、重測、Virtual Hospital package | v0.1.1 Q4 handoff |

W1–8 是 2026-09-30 前的 Q3 Alpha committed path；W9–12 是發布後的 Q4 testbed-hardening path，不得倒推成 Q3 已完成的驗證宣稱。Q3 執行至少需同時涵蓋 ML/data、backend/edge 與 security review 三類責任。若由單人兼任、資料缺少可靠 session metadata、或 Pi 5 未在 W6 前到位，優先縮減 dashboard、fine-grained classification 與非必要 RAG corpus，不壓縮 leakage audit、fallback、read-only policy 或 safety review。任何未完成的 Pi 5／SLM／RAG 必須在 Release Notes 標為 experimental 或 unavailable，不能以模擬數字代替實測。

## 5. 角色與責任

| 角色 | 主要責任 |
|---|---|
| Product Owner | Scope、priority、release decision |
| ML Engineer | XGBoost、LSTM、SLM、evaluation |
| Data/Network Engineer | CICIoMT、PCAP/Flow、feature pipeline |
| Backend/Edge Engineer | API、RAG、Pi 5、deployment |
| Security Reviewer | Threat model、guardrails、red-team tests |
| Medical OT Advisor | Device state、clinical workflow、safety review |

若團隊不足，Medical OT Advisor 與 Security Reviewer 可採兼任或外部顧問，但 release 前必須完成獨立審查。

## 6. 假設與依賴

- CICIoMT2024 可合法取得並依其條款使用。
- 取得的資料包含足以建立正確 split 的 metadata；若缺少 session/device metadata，文件必須揭露限制。
- Pi 5 至少 8GB RAM，具主動散熱及可靠儲存。
- M2 Pro 16GB 可用於 360M LoRA／PEFT 訓練；訓練必須記錄 peak unified memory、wall time、adapter config 與失敗條件。
- Q3 release 不依賴衛福部 testbed 核准。
- 實院資料不納入 Q3 Alpha。
- 任何含 PHI 或院內敏感資訊的資料，須另行完成治理與授權。

## 7. 變更控制

下列項目視為 scope change，需重新評估時程：

- Q3 前加入真實醫院部署。
- 加入 inline enforcement 或自動隔離。
- 從零預訓練 SLM。
- 支援完整 PCAP payload analysis。
- 新增多租戶 SaaS、商用 billing 或正式醫材認證。
- 擴充至非醫療 OT 多產業版本。

## 8. Release Go/No-Go

### Go

- 所有 artifact 有版本及 SHA-256。
- Benchmark 可在乾淨環境重現。
- 至少完成 session/device-aware 評估之一。
- Safety guardrails 測試通過。
- 系統以 advisory-only 運行。
- 已知限制與未達指標完整揭露。
- Q3 生成式模型明確為 `HuggingFaceTB/SmolLM2-360M-Instruct`，有 LoRA／PEFT artifact、GGUF、Model Card 與 frozen test result。
- SLM 不產生 detector score；RAG 工具只能由 deterministic orchestrator 呼叫。
- 所有失效路徑皆通過 fallback／failure-injection test，且不會產生網路或設備寫入。

### No-Go

- 只能提供 random-row split 結果且無 leakage audit。
- SLM 可創造不存在的 evidence 或 action。
- Agent 可呼叫未授權工具或產生網路寫入。
- 模型或服務失效會中斷被監控網路。
- 使用「臨床驗證」「零日防護」「合規認證」等未證實宣稱。

## 9. 完成定義

本 SOW 僅在下列項目全部完成時視為完成：

- Frozen dataset manifest、leakage audit、可重現 preprocessing，以及 XGBoost／Isolation Forest／LSTM AE 的 group-aware 評估與限制揭露。
- 並行 detector → evidence fusion 可獨立運作；每筆分數、threshold、evidence、model／policy version 可追溯，SLM 無法寫入 detector 欄位。
- `HuggingFaceTB/SmolLM2-360M-Instruct` 在 M2 Pro 16GB 完成記錄完整的 LoRA／PEFT fine-tune，交付 adapter、GGUF、SFT schema/provenance、Model Card 與 frozen evaluation。
- Pi 5 8GB 上以 `llama.cpp` 完成 24 小時 soak、P50/P95、RAM、CPU、溫度、OOM／crash 與 dropped-event 報告；若未通過效能門檻，release 名稱不得含 Pi 5 ready。
- Deterministic RAG state machine、read-only allowlist、source validation、簡易 guardrails 與 audit trail 完成；SLM 不直接執行工具。
- SLM invalid、RAG unavailable、單一 detector unavailable、兩 detector unavailable 等 fallback／failure-injection tests 通過。
- API、dashboard、README、Architecture、Dataset／Model Cards、Benchmark Report、Threat Model、Privacy、Known Limitations 與 Release Notes 完成，且無臨床、zero-day、合規或自動處置宣稱。

發布型態仍為非臨床、advisory-only 的 Research / Developer Preview；完成不代表衛福部虛擬醫院或真實醫院驗證。
