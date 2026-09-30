# 虛擬醫院情境測試報告

| 欄位 | 內容 |
|---|---|
| 產生時間（UTC） | 2026-08-03T17:12:38.422837+00:00 |
| 類型 | 系統行為情境（非 CIC 資料集重訓／排行榜） |
| 情境數 | 10 |
| 通過 | 10/10 |
| 硬體聲明 | 無 — 未做 Pi 5／M2 Pro 量測 |

## 範圍

本報告驗證**現況已接線**的 advisory 管線：以合成病房設備演練，並在可用時取一筆 CIC 特徵列，用來行使線上攻擊類別模型。

本報告**不主張**：資料集排行榜指標、LoRA 品質，或邊緣延遲／記憶體門檻已通過。

## 情境結果

### S1 — 安靜病房／正常監視器

**結果：** 通過

- [通過] verdict=anomalous
- [通過] 僅 advisory（advisory_only）
- [通過] SLM 狀態正常

```json
{
  "verdict": "anomalous",
  "severity": "medium",
  "taxonomy": "network_behavior_anomaly",
  "rag": "available"
}
```

### S2 — 閘道疑似 DDoS（攻擊類別層）

**結果：** 通過

- [通過] 已知攻擊輸出：category=ddos，機率約 0.999965（XGBoost category）
- [通過] category=ddos p=0.999965
- [通過] verdict=suspected_attack
- [通過] taxonomy=unknown（SLM／模板路徑後的 taxonomy 欄位）

```json
{
  "category": "ddos",
  "probability": 0.999965,
  "verdict": "suspected_attack",
  "taxonomy": "unknown",
  "severity": "critical"
}
```

### S3 — 輸液幫浦異常（僅 anomaly 層可打分）

**結果：** 通過

- [通過] 預期：sample 特徵對不上 CIC 版 XGBoost，known_attack=None
- [通過] status=partial_detection
- [通過] verdict=anomalous
- [通過] 需人工核准（human approval）

```json
{
  "if_score": 0.956062,
  "anomalous": true,
  "verdict": "anomalous",
  "severity": "critical"
}
```

### S4 — 偵測器意見不一致

**結果：** 通過

- [通過] disagreement=true
- [通過] verdict=known_attack_suspected

```json
{
  "disagreement": true,
  "verdict": "known_attack_suspected"
}
```

### S5 — 同一設備 LSTM：warming → 可打分

**結果：** 通過

- [通過] 曾進入 warming（ticks=9）
- [通過] 湊滿後可打分（ticks=10, score=1.0, anomalous=true）
- [通過] tick 數量足夠

```json
{
  "warming": {
    "ticks": 9,
    "status": "warming"
  },
  "ready": {
    "ticks": 10,
    "status": "ok",
    "score": 1.0,
    "raw_error": 438.994548,
    "anomalous": true
  },
  "seq_len": 10
}
```

### S6 — IF + LSTM 並行融合

**結果：** 通過

- [通過] anomalies 欄位存在
- [通過] 主 anomaly 有分數（此例主偵測器為 lstm_autoencoder）
- [通過] Isolation Forest 結果保留
- [通過] LSTM 結果保留

```json
{
  "primary_detector": "lstm_autoencoder",
  "primary_score": 1.0,
  "verdict": "anomalous"
}
```

### S7 — SLM 無效輸出 → template_fallback

**結果：** 通過

- [通過] 進入 template_fallback
- [通過] detector 分數未被改寫

```json
{
  "generation_status": "template_fallback"
}
```

### S8 — RAG 全工具失敗 → enrichment_unavailable

**結果：** 通過

- [通過] status=enrichment_unavailable
- [通過] anomaly 分數保留

```json
{
  "enrichment": "enrichment_unavailable"
}
```

### S9 — 護欄：禁止動作與指令注入

**結果：** 通過

- [通過] 強制改為 advisory_only
- [通過] 要求人工核准
- [通過] 已移除 isolate；保留 verify／review 建議
- [通過] 偵測到禁止動作
- [通過] 偵測到指令注入
- [通過] 不可信指令已遮罩（redacted）

```json
{
  "actions": [
    "verify_device_state",
    "review_evidence_window"
  ],
  "mode": "advisory_only"
}
```

### S10 — 兩層偵測皆不可用 → 拒絕捏造 verdict

**結果：** 通過

- [通過] 拋出 ValueError，拒絕產生推測事件

```json
{
  "refused": true
}
```

## 總結

- 整體：**10/10 情境通過**。
- 已演練兩層設計：anomaly（IF／LSTM）與攻擊類別（特徵對得上時走 XGBoost category）。
- 已演練失效路徑：SLM `template_fallback`、RAG `enrichment_unavailable`、兩偵測器皆無則拒絕。
- 已演練護欄：僅 advisory、剔除禁止動作、指令注入遮罩。

## 限制

- Sample flow 特徵無法驅動以 CIC 訓練的 XGBoost 類別模型（特徵欄位不一致）；S3 刻意記錄此預期落差。
- 本測試的 LSTM 使用記憶體內 tick 緩衝（與 API 概念相同），並非持久化病房遙測。
- 臨時執行腳本已在產報告後刪除；請以本 Markdown 作為留存紀錄。
