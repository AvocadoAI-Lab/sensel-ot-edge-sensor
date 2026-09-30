# Avocdo EdgeMed Security — 整體設計說明（師生報告用）

| 欄位 | 內容 |
|---|---|
| 文件用途 | 向指導老師報告系統整體設計與現況 |
| 產品 | Avocdo EdgeMed Security v0.1（Q3 Alpha research preview） |
| 對應文件 | `docs/PRD.md`、`docs/SOW.md`、`docs/BACKLOG.md`、`docs/RELEASE_NOTES.md` |
| 驗證報告 | `docs/VIRTUAL_SCENARIO_REPORT.md`（虛擬醫院行為情境 10/10） |
| 撰寫基準日 | 2026-08-04 |

---

## 1. 一句話說明

這套系統在**本地**看醫療 AIoT／OT 設備的網路流量特徵，用**兩層偵測**找出「怪不怪」與「像哪種已知攻擊」，再整理成**可審查的建議事件**給人看。  
系統**不會**自己隔離設備、擋封包或改防火牆。

> Detect known and unknown medical AIoT threats locally, then turn every alert into a source-grounded, reviewable investigation event.

---

## 2. 為什麼要這樣做

醫療場域常見限制：

- 設備難裝一般 endpoint agent，韌體也難快速更新  
- 臨床服務不能被錯誤阻斷  
- 只有簽名／規則不夠應付未知異常  
- 告警若沒有設備狀態與證據，SOC 很難調查  
- 敏感流量不適合丟到外部雲端大模型  

因此設計原則是：

1. **被動監控、地端優先**  
2. **偵測與解釋分離**：模型負責分數與證據；語言層只負責整理  
3. **只建議、要人核准**（advisory-only）  
4. **可追溯**：每筆事件有 schema、版本、證據 ID  

---

## 3. 與老師指導的對齊

老師指示重點：

1. **Feature extraction 之後**再送進模型（先變數字特徵，再分類／偵測）  
2. 分成兩層：  
   - **Anomaly detection**：用正常行為學「平常長怎樣」  
   - **Attack detection**：辨識／分類攻擊  

本專案落點：

| 老師說的 | 本系統做法 |
|---|---|
| 特徵抽出後再進模型 | 輸入為數值 flow features（CIC CSV 已抽好特徵；API 收 `features`） |
| 第一層 anomaly | Isolation Forest（即時）＋ Tick／LSTM AE（序列；線上並行） |
| 第二層 attack | XGBoost **攻擊類別**（優先）；特徵對不上時退回 binary |
| 先做攻擊類別 | CICIoMT 上已訓練／評估 category 模型並接到線上 |

補充：本 repo **沒有**自己從原始 PCAP 重做完整 feature extraction 引擎；Q3 以公開 CSV 特徵與 API 特徵物件為輸入。特徵抽出在資料管線更前端（資料集或感測端）。

---

## 4. 整體架構（現況 as-built）

```text
[原始流量 / PCAP]
        │
        ▼
【特徵抽出】← 資料集或感測端（本 Q3 多半已是 CSV／features）
        │
        ▼
┌───────────────────────┐
│  數值特徵 features    │
└───────────┬───────────┘
            │
   ┌────────┴────────┐
   ▼                 ▼
┌────────────┐   ┌─────────────────┐
│ Anomaly 層 │   │ Attack 層       │
│ IF（即時） │   │ XGBoost category│
│ LSTM（tick │   │ （必要時 binary）│
│  序列）    │   └────────┬────────┘
└─────┬──────┘            │
      └─────────┬─────────┘
                ▼
         【Fusion 融合】
      Security Event Schema v0.1
      （分數／證據不可被後面改寫）
                │
                ▼
         【SLM 格式化層】
      SmolLM2-360M 已鎖定；
      現況 runtime = template + fallback
                │
                ▼
      【Deterministic Agentic RAG】
      只讀 allowlist 工具，最多 5 步
                │
                ▼
         【Guardrails 護欄】
      輸入檢查／禁止動作／audit
                │
                ▼
      FastAPI ＋ Dashboard（advisory）
```

### 資料流一句話

特徵 →（異常層 IF＋LSTM ∥ 攻擊層 XGBoost）→ 融合事件 → SLM 整理 → RAG 補來源 → 護欄 → API／畫面。

---

## 5. 各層設計說明

### 5.1 資料基礎（M1）

- 資料集：CICIoMT2024（Wi‑Fi／MQTT CSV；使用者自行接受條款下載）  
- 治理：inventory、provenance、leakage denylist、官方 train／test 檔級 manifest  
- 規則：官方 test 檔不進入 train／validation；preprocessor 只在 train 上 fit  
- 限制：公開 CSV 常缺可信 `device_id`／`session_id`／時間戳 → LSTM 時序比較需合成時序或線上 tick 緩衝  

相關：`docs/data/DATASET_CARD.md`、`config/feature_dictionary.yaml`

### 5.2 兩層偵測（M2）

**Anomaly（找怪）**

| 元件 | 角色 | 訓練概念 |
|---|---|---|
| Isolation Forest | 單筆特徵即時異常分 | 偏正常／良性行為 |
| Tick（約 60s）＋ LSTM AE | 同一設備序列異常 | 只在 benign 序列上訓練；不跨 device／session 拼序列 |

線上：兩者可並行；LSTM 需累積足夠 tick，不足時標 `warming`。

**Attack（認攻擊）**

| 元件 | 角色 |
|---|---|
| Logistic Regression | 已知威脅 baseline（比較用） |
| XGBoost category | 主線：攻擊家族／類別機率 |
| XGBoost binary | 備援：Attack／Benign |

輸出進入 fusion 的 `known_attack`（含 `category`、`probability`、`task` 等）。

### 5.3 融合與事件契約（M3）

- Schema：`app/schemas/security_event_v0_1.json`  
- 嚴重度：`config/severity_policy.yaml`（政策決定，不由生成模型覆寫）  
- 狀態：`ok`／`partial_detection`；偵測器不一致會標 `disagreement`  
- 兩層都不可用時：**拒絕捏造 verdict**  
- 不變量：**detector-owned** 欄位（分數、證據）後續 SLM／RAG 不得改寫  

### 5.4 SLM（M4）

- 鎖定模型：`HuggingFaceTB/SmolLM2-360M-Instruct`  
- 任務：短英文摘要、有限 taxonomy、retrieval intent enum、只引用既有 evidence_id  
- **不做**：改分數、自由 tool call、設備／網路寫入  
- 現況 runtime：template formatter＋schema／grounding 驗證；失敗 → `template_fallback`  
- 已備：SFT 資料、LoRA 設定與訓練腳本  
- **未做（硬體門檻）**：M2 Pro 實訓 LoRA、GGUF、Pi 5 推理量測  

### 5.5 Deterministic Agentic RAG（M5）

- 本地小型 KB：asset／behavior／threat／playbook  
- 工具：read-only allowlist；SLM 的 intent 只是建議，不能任意選工具或組參數  
- 最多 5 次 retrieval；claim 需有 source_id  
- 失敗 → `enrichment_unavailable`，不捏造知識  

### 5.6 安全護欄與發布（M6）

- 輸入 schema 檢查、指令注入遮罩、禁止動作過濾（如 isolate／block）  
- 強制 `advisory_only`、`human_approval_required`  
- Failure injection：單一／雙偵測器失效、SLM／RAG 失效  
- Dashboard 顯示元件與 degraded 狀態  
- Release notes／已知限制已文件化  
- **未做**：Pi 5 真實 latency／RAM／溫度數字  

---

## 6. 產品邊界（對老師報告時請強調）

**會做**

- 本地偵測與調查事件整理  
- 證據可追溯、可人工覆核  

**不會做**

- 自動隔離／阻斷醫療設備  
- 主動掃描、封包注入、防火牆寫入  
- 臨床決策  
- 用 SLM 取代 detector  
- 宣稱已通過特定醫材／法規認證  

---

## 7. 驗證現況（軟體側）

| 項目 | 狀態 |
|---|---|
| 單元／API 測試 | 通過（含 fusion、guardrails、LSTM、RAG 等） |
| Failure injection | 通過 |
| 虛擬醫院行為情境 | `docs/VIRTUAL_SCENARIO_REPORT.md` **10/10 通過** |
| CIC 抽樣分類器指標 | 有 artifacts（例如 XGB binary ROC-AUC 高、category macro-F1 優於 LR） |
| Pi 5／LoRA 實測 | **未完成**（硬體門檻；禁止捏造數字） |

虛擬情境涵蓋（摘要）：

1. 正常監視器  
2. 閘道 DDoS（攻擊類別層）  
3. 輸液幫浦僅 anomaly  
4. 偵測器意見不一致  
5. LSTM warming → 可打分  
6. IF＋LSTM 並行融合  
7. SLM fallback  
8. RAG unavailable  
9. 護欄擋 isolate／注入  
10. 兩層皆無 → 拒絕捏造  

---

## 8. 里程碑對照（Backlog）

| 里程碑 | 內容 | 軟體狀態 |
|---|---|---|
| M0 | Repo／IF／API 垂直切片 | 完成 |
| M1 | CICIoMT 資料治理 | 完成 |
| M2 | 並行 detector（LR／XGB／LSTM／IF） | 完成（線上已接 category＋IF／LSTM） |
| M3 | Fusion＋Event schema | 完成 |
| M4 | Starting SLM | 管線／護欄完成；LoRA／GGUF／Pi 未做 |
| M5 | Deterministic RAG | 完成 |
| M6 | Safety＋release 文件 | 軟體完成；Pi 量測未做 |
| Q4 | Soak、獨立審查、完整虛擬醫院套件等 | 未完成（僅有行為情境報告） |

---

## 9. 已知限制（報告時建議主動說明）

1. CIC 官方 CSV 常缺時序／設備欄位 → LSTM 不能宣稱「全在官方 CSV 上時序驗證」。  
2. 分類器目前多為 per-file 抽樣訓練，非全 corpus 離線重訓。  
3. Sample flow（8 維）與 CIC XGBoost（約 45 維）特徵不一致 → demo 路徑可能只有 anomaly、沒有 category。  
4. SLM 現況是 template 路徑，不是已微調邊緣模型。  
5. RAG KB 是架構證明用小型知識，不是院內真實 CMDB。  
6. Dashboard 是研究預覽，不是正式 SOC 產品。  

---

## 10. 主要程式與設定對照

| 區塊 | 路徑 |
|---|---|
| API／Dashboard | `app/main.py`、`app/static/index.html` |
| IF | `app/detector.py` |
| Tick／LSTM | `app/ticks.py`、`app/lstm_ae.py`、`app/tick_buffer.py` |
| XGBoost／LR | `app/classifier.py`、`scripts/train_classifiers.py` |
| Fusion | `app/fusion.py`、`config/severity_policy.yaml` |
| SLM | `app/slm.py`、`config/slm.yaml` |
| RAG | `app/rag/`、`config/kb/` |
| 護欄 | `app/guardrails.py`、`config/security_policy.yaml` |
| 資料治理 | `app/data/`、`scripts/prepare_ciciomt.py` |

---

## 11. 建議報告口述結構（約 5–8 分鐘）

1. **問題**：醫療設備不能亂擋、又要抓已知攻擊與未知異常。  
2. **老師兩層**：特徵之後 → anomaly ＋ attack。  
3. **我們怎麼接**：IF／LSTM ∥ XGBoost category → fusion。  
4. **後面為什麼有 SLM／RAG**：只整理與補來源，不改分數。  
5. **安全底線**：advisory-only、護欄、失效 fallback。  
6. **證據**：單元測試＋虛擬情境 10/10；硬體項誠實說還沒做。  
7. **下一步**：LoRA／Pi 量測、Q4 虛擬醫院與 soak。  

---

## 12. 結語

本專案已把 Q3 Alpha **軟體架構與兩層偵測主線**落到可跑、可測、可報告的狀態，並以 advisory-only 與 detector／生成層權限分離符合安全研究定位。  
剩餘核心缺口集中在**硬體實測與模型微調產物**，以及 Q4 場域硬化，不應在報告中宣稱已完成。

如需更細規格，請併讀：

- 需求：`docs/PRD.md`  
- 工項：`docs/SOW.md`、`docs/BACKLOG.md`  
- 發布與限制：`docs/RELEASE_NOTES.md`  
- 情境驗證：`docs/VIRTUAL_SCENARIO_REPORT.md`
