# 電腦 vs 樹莓派 4 — 相同測試對比報告

- 產生時間（UTC）：`2026-08-10T06:27:05.429301+00:00`
- 電腦端：`http://127.0.0.1:8000`（Windows 11）
- 樹莓派端：`http://192.168.50.90:8000`（Raspberry Pi 4 Model B，4GB）
- 測試內容：兩邊送完全相同的示範請求（設備 `monitor-07`，README 範例特徵）

---

## 1. 總覽對照表

| 項目 | 電腦（PC） | 樹莓派 4 |
|---|---|---|
| 健康檢查狀態 | 降級（缺 SLM 執行時） | 降級（缺 SLM 執行時） |
| 健康檢查延遲 | 19.4 毫秒 | 19.6 毫秒 |
| 評分（score）延遲 | 158.4 毫秒 | 493.7 毫秒 |
| 調查（investigate）延遲 | 22.6 毫秒 | 50.8 毫秒 |
| 孤立森林分數 | 0.311513（判定非異常） | 0.311513（判定非異常） |
| LSTM 時序模型 | 暖機中（已累積 2 個 tick，尚未可打分） | 無結果（未載入，缺 torch） |
| 已知攻擊分類（XGBoost） | 無（此組特徵未產出分類） | 無（此組特徵未產出分類） |
| 融合結論／嚴重度 | 異常／高 | 異常／高 |
| SLM 摘要狀態 | 模板備援 | 模板備援 |
| 調查富化（RAG） | 無來源（0 筆） | 無來源（0 筆） |
| 單元測試 | 失敗（1 項）｜約 26.3 秒 | 失敗（1 項）＋錯誤（2 項）｜約 15.8 秒 |

---

## 2. 健康檢查（`/health`）說明

兩邊狀態相同：整體為「降級」，原因都是 **SLM 執行時未載入**，因此摘要改走模板備援。

| 元件 | 電腦 | 樹莓派 | 說明 |
|---|---|---|---|
| 孤立森林（Isolation Forest） | 就緒 | 就緒 | 異常評分主模型之一 |
| LSTM 自動編碼器 | 檔案就緒 | 檔案就緒 | 派上實際推論失敗（缺 torch） |
| XGBoost 多類／二元 | 就緒 | 就緒 | 已知攻擊分類 |
| SLM 小語言模型 | 未載入 | 未載入 | 目前用模板句代替 |
| RAG 編排器 | 就緒 | 就緒 | 規則型、唯讀工具 |
| 事件儲存 | 就緒 | 就緒 | 本地事件紀錄 |

### 電腦原始回應

```json
{
  "status": "degraded",
  "mode": "advisory_only",
  "degraded_components": ["slm_runtime"],
  "policy_version": "0.1",
  "components": {
    "isolation_forest": true,
    "lstm_autoencoder": true,
    "xgboost_category": true,
    "xgboost_binary": true,
    "slm": {
      "model_id": "HuggingFaceTB/SmolLM2-360M-Instruct",
      "runtime_loaded": false,
      "fallback": "template_fallback"
    },
    "rag": {
      "orchestrator": "deterministic_state_machine",
      "max_retrieval_steps": 5,
      "tools": "read_only_allowlist"
    },
    "event_store": true
  }
}
```

### 樹莓派原始回應

```json
{
  "status": "degraded",
  "mode": "advisory_only",
  "degraded_components": ["slm_runtime"],
  "policy_version": "0.1",
  "components": {
    "isolation_forest": true,
    "lstm_autoencoder": true,
    "xgboost_category": true,
    "xgboost_binary": true,
    "slm": {
      "model_id": "HuggingFaceTB/SmolLM2-360M-Instruct",
      "runtime_loaded": false,
      "fallback": "template_fallback"
    },
    "rag": {
      "orchestrator": "deterministic_state_machine",
      "max_retrieval_steps": 5,
      "tools": "read_only_allowlist"
    },
    "event_store": true
  }
}
```

---

## 3. 評分 API（`/api/score`）對比

| 欄位（中文） | 電腦 | 樹莓派 |
|---|---|---|
| 事件編號 | `evt_f42b4a5028bb9f79` | `evt_f42b4a5028bb9f79` |
| 偵測狀態 | 部分偵測 | 部分偵測 |
| 孤立森林分數 | 0.311513 | 0.311513 |
| 孤立森林是否異常 | 否 | 否 |
| LSTM | 暖機中（ticks=2） | 無（null） |
| 已知攻擊 | 無 | 無 |
| 融合判定 | 異常 | 異常 |
| 嚴重度 | 高 | 高 |
| 分類標籤 | 網路行為異常 | 網路行為異常 |
| 摘要產生方式 | 模板備援 | 模板備援 |
| 回應模式 | 僅建議、需人工核准 | 僅建議、需人工核准 |

兩邊摘要文字相同：

> patient_monitor 流量經融合政策判定為 anomalous（已知攻擊不可用，異常訊號為 medium）。

### 電腦原始摘要

```json
{
  "event_id": "evt_f42b4a5028bb9f79",
  "detection_status": "partial_detection",
  "if_score": 0.311513,
  "if_anomalous": false,
  "lstm": {"status": "warming", "score": null, "ticks": 2},
  "known_attack": null,
  "verdict": "anomalous",
  "severity": "high",
  "taxonomy": "network_behavior_anomaly",
  "generation_status": "template_fallback",
  "summary": "patient_monitor traffic assessed as anomalous by fusion policy fusion-policy-0.1 (known_attack=unavailable, anomaly=medium).",
  "enrichment_status": "unavailable",
  "response_mode": "advisory_only"
}
```

### 樹莓派原始摘要

```json
{
  "event_id": "evt_f42b4a5028bb9f79",
  "detection_status": "partial_detection",
  "if_score": 0.311513,
  "if_anomalous": false,
  "lstm": null,
  "known_attack": null,
  "verdict": "anomalous",
  "severity": "high",
  "taxonomy": "network_behavior_anomaly",
  "generation_status": "template_fallback",
  "summary": "patient_monitor traffic assessed as anomalous by fusion policy fusion-policy-0.1 (known_attack=unavailable, anomaly=medium).",
  "enrichment_status": "unavailable",
  "response_mode": "advisory_only"
}
```

---

## 4. 調查 API（`/api/investigate`）對比

這次兩邊調查摘要欄位都幾乎是空的（富化狀態／來源／建議動作皆未取到有效內容），代表此輪對比裡 **RAG 富化沒有產出可用來源**。

| 項目 | 電腦 | 樹莓派 |
|---|---|---|
| 富化狀態 | 無 | 無 |
| 來源筆數 | 0 | 0 |
| 摘要產生狀態 | 無 | 無 |
| 建議動作 | 無 | 無 |

---

## 5. 單元測試對比

| 項目 | 電腦 | 樹莓派 |
|---|---|---|
| 結果 | 失敗 | 失敗 |
| 失敗數 | 1 | 1 |
| 錯誤數 | 0 | 2 |
| 執行測試數 | 38 | 31 |
| 耗時 | 約 26.3 秒（含整段流程）／測試本身約 4.0 秒 | 約 15.8 秒（含 SSH）／測試本身約 3.7 秒 |

### 共同失敗

- `test_unknown_evidence_id_triggers_fallback`  
  預期：碰到未知 evidence_id 應落到 `template_fallback`  
  實際：得到 `generated`  
  → 兩邊程式邏輯一致，屬於現有測試／實作差異，不是派特有問題。

### 樹莓派多出的錯誤（2 項）

- 匯入 `test_lstm_baseline`、以及評測相關模組時失敗  
- 原因：`ModuleNotFoundError: No module named 'torch'`  
- 影響：LSTM 相關單元測試在派上跑不起來；也對應到上面 API 的 LSTM 為空。

<details>
<summary>電腦單元測試結尾（原文）</summary>

```text
test_unknown_evidence_id_triggers_fallback ... FAIL
AssertionError: 'generated' != 'template_fallback'
Ran 38 tests in 4.004s
FAILED (failures=1)
```

</details>

<details>
<summary>樹莓派單元測試結尾（原文）</summary>

```text
ModuleNotFoundError: No module named 'torch'
ERROR: test_lstm_baseline
FAIL: test_unknown_evidence_id_triggers_fallback
Ran 31 tests in 3.717s
FAILED (failures=1, errors=2)
```

</details>

---

## 6. 白話結論

1. **核心異常分數對齊**：孤立森林分數兩邊完全相同（`0.311513`），融合判定與嚴重度也一致，代表「已訓練模型搬上派後，主線推論行為可重現」。
2. **派比較慢**：同樣 score 請求，派大約慢 3 倍（494 ms vs 158 ms），屬硬體效能差，不是算錯。
3. **LSTM 是最大差異**：電腦可進入暖機；派上因未安裝 torch，API 與單元測試都缺 LSTM。
4. **SLM 兩邊都還在模板模式**：目前都不是神經網路生成摘要；派上先前測過的 GGUF 尚未接到這套 API。
5. **單元測試**：共同有 1 個 SLM fallback 相關失敗；派另外因缺 torch 多 2 個錯誤。
