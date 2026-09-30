# 電腦 vs 樹莓派 4 — 同測對比報告 V2

- 產生時間（UTC）：`2026-08-12T06:10:20.453401+00:00`
- 電腦：`http://127.0.0.1:8000`（SLM：transformers／`try_load()`）
- 樹莓派：`http://192.168.50.90:8000`（LSTM torch ＋ SLM GGUF／llama.cpp）
- 相同示範請求：`monitor-07` + README 特徵；另做冷啟動 IF 快照，再跑滿 `seq_len` 給 LSTM

## 1. 總覽

| 項目 | 電腦（PC） | 樹莓派 4 |
|---|---|---|
| 健康狀態 | `ok` / degraded=[] | `ok` / degraded=[] |
| SLM runtime 已載入 | 是（backend=`transformers`） | 是（backend=`llama_cpp_server`） |
| SLM model_id | HuggingFaceTB/SmolLM2-360M-Instruct | llama-server:http://127.0.0.1:8081 |
| health 延遲 (ms) | 26.5 | 28.8 |
| 單次 score 延遲 (ms) | 168.8 | 1323.8 |
| IF 分數（`anomalies.isolation_forest`） | 0.311513（anomalous=False） | 0.311513（anomalous=False） |
| 冷啟動 IF（獨立 session） | 0.311513 / primary={'detector': 'isolation_forest', 'score': 0.311513, 'anomalous': False} | 0.311513 / primary={'detector': 'isolation_forest', 'score': 0.311513, 'anomalous': False} |
| 主異常欄位 primary_anomaly | {'detector': 'isolation_forest', 'score': 0.311513, 'anomalous': False} | {'detector': 'isolation_forest', 'score': 0.311513, 'anomalous': False} |
| LSTM 最終狀態 | {'status': 'ok', 'score': 0.997258, 'ticks': 12, 'anomalous': True} | {'status': 'ok', 'score': 0.997258, 'ticks': 12, 'anomalous': True} |
| known_attack | None | None |
| verdict / severity | anomalous / high | anomalous / high |
| SLM generation_status（單次 score） | template_fallback | template_fallback |
| investigate generation_status | generated | template_fallback（整輪 suite 曾 timeout；補測成功約 90s） |
| investigate enrichment | available（sources=8） | available（補測；suite 當輪為 timeout） |
| 資料集測試 | OK（2688.1 ms） | OK（23848.5 ms） |
| 完整單元測試 | FAILED (failures=1)（17970.8 ms, rc=1） | FAILED (failures=2, errors=2)（34627.8 ms, rc=1） |

## 2. 這次重測重點

- 電腦：transformers 版 SmolLM2（`backend=transformers`）。
- 樹莓派：接上 GGUF＋llama.cpp **常駐** `llama-server`（`backend=llama_cpp_server`），API 用 HTTP `/completion` 生字；仍走同一套 schema／證據護欄；不過關則 `template_fallback`。
- 評分欄位已分開：`if_score`＝真正 Isolation Forest；`primary_anomaly`＝融合後主異常（取可用偵測器最高分）。
- Pi 完整單元測試會先停掉 uvicorn／llama-server，測完再重啟整疊服務。
- `/api/score` 本身不呼叫 SLM（兩邊 score 的 `generation_status` 多為模板）；真正生字在 `/api/investigate`。

## 2.1 兩邊評分為何看起來不一樣（必讀）

### 真正的 IF

- 冷啟動同特徵：PC IF=`0.311513`，Pi IF=`0.311513`。
- 暖機後摘要：PC IF=`0.311513`，Pi IF=`0.311513`。
- **結論：兩邊 IF 分數相同**，`detector.joblib` 可重現；**不是兩套不同 IF 模型**。

### 以前表格為何會看到 0.997 vs 0.311？

- 舊版報告把 `detection.anomaly`（主異常）誤標成「IF 分數」。
- 主異常會在 IF／LSTM 之間選**較高分**；PC 若 LSTM 已暖機（例如 0.997）就會蓋過 IF（0.311）。
- 本版已分開欄位：`if_score` vs `primary_anomaly`，避免再誤讀。

### 主異常欄位（容易誤讀）

- PC primary=`{'detector': 'isolation_forest', 'score': 0.311513, 'anomalous': False}`
- Pi primary=`{'detector': 'isolation_forest', 'score': 0.311513, 'anomalous': False}`
- 滿 `seq_len` 後 LSTM 兩邊都可到約 `0.997258`（見第 5 節）；若只看當時的 primary，仍可能被 LSTM 蓋過。

### SLM 與評分無關

- SLM（含 GGUF／llama-server）只生說明文字，不改 IF／LSTM／XGBoost 分數。
- Pi investigate：健康檢查 `runtime_loaded=true`；補測曾成功回 `template_fallback`（約 90s，代表有呼叫生字但未過護欄）。整輪 V2 suite 中 Pi investigate 可能因負載 timeout，屬效能／逾時問題，不是「沒接上」。

## 3. 健康檢查原始結果

### 電腦
```json
{
  "status": "ok",
  "mode": "advisory_only",
  "degraded_components": [],
  "policy_version": "0.1",
  "components": {
    "isolation_forest": true,
    "lstm_autoencoder": true,
    "xgboost_category": true,
    "xgboost_binary": true,
    "slm": {
      "model_id": "HuggingFaceTB/SmolLM2-360M-Instruct",
      "runtime_loaded": true,
      "backend": "transformers",
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

### 樹莓派
```json
{
  "status": "ok",
  "mode": "advisory_only",
  "degraded_components": [],
  "policy_version": "0.1",
  "components": {
    "isolation_forest": true,
    "lstm_autoencoder": true,
    "xgboost_category": true,
    "xgboost_binary": true,
    "slm": {
      "model_id": "llama-server:http://127.0.0.1:8081",
      "runtime_loaded": true,
      "backend": "llama_cpp_server",
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

## 4. `/api/score` 摘要

### 冷啟動（獨立 session）

#### 電腦
```json
{
  "event_id": "evt_f42b4a5028bb9f79",
  "detection_status": "partial_detection",
  "if_score": 0.311513,
  "if_anomalous": false,
  "primary_anomaly": {
    "detector": "isolation_forest",
    "score": 0.311513,
    "anomalous": false
  },
  "lstm": {
    "status": "warming",
    "score": null,
    "ticks": 1,
    "anomalous": null
  },
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

#### 樹莓派
```json
{
  "event_id": "evt_f42b4a5028bb9f79",
  "detection_status": "partial_detection",
  "if_score": 0.311513,
  "if_anomalous": false,
  "primary_anomaly": {
    "detector": "isolation_forest",
    "score": 0.311513,
    "anomalous": false
  },
  "lstm": {
    "status": "warming",
    "score": null,
    "ticks": 1,
    "anomalous": null
  },
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

### 暖機後單次

#### 電腦
```json
{
  "event_id": "evt_f42b4a5028bb9f79",
  "detection_status": "partial_detection",
  "if_score": 0.311513,
  "if_anomalous": false,
  "primary_anomaly": {
    "detector": "isolation_forest",
    "score": 0.311513,
    "anomalous": false
  },
  "lstm": {
    "status": "warming",
    "score": null,
    "ticks": 2,
    "anomalous": null
  },
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

#### 樹莓派
```json
{
  "event_id": "evt_f42b4a5028bb9f79",
  "detection_status": "partial_detection",
  "if_score": 0.311513,
  "if_anomalous": false,
  "primary_anomaly": {
    "detector": "isolation_forest",
    "score": 0.311513,
    "anomalous": false
  },
  "lstm": {
    "status": "warming",
    "score": null,
    "ticks": 2,
    "anomalous": null
  },
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

## 5. LSTM 序列追蹤（滿 seq_len）

### 電腦最終
```json
{
  "status": "ok",
  "score": 0.997258,
  "ticks": 12,
  "anomalous": true
}
```

### 樹莓派最終
```json
{
  "status": "ok",
  "score": 0.997258,
  "ticks": 12,
  "anomalous": true
}
```

<details><summary>電腦 LSTM trace</summary>

```json
[
  {
    "i": 1,
    "latency_ms": 167.9,
    "lstm": {
      "status": "warming",
      "score": null,
      "ticks": 3,
      "anomalous": null
    }
  },
  {
    "i": 2,
    "latency_ms": 169.1,
    "lstm": {
      "status": "warming",
      "score": null,
      "ticks": 4,
      "anomalous": null
    }
  },
  {
    "i": 3,
    "latency_ms": 164.8,
    "lstm": {
      "status": "warming",
      "score": null,
      "ticks": 5,
      "anomalous": null
    }
  },
  {
    "i": 4,
    "latency_ms": 168.5,
    "lstm": {
      "status": "warming",
      "score": null,
      "ticks": 6,
      "anomalous": null
    }
  },
  {
    "i": 5,
    "latency_ms": 170.6,
    "lstm": {
      "status": "warming",
      "score": null,
      "ticks": 7,
      "anomalous": null
    }
  },
  {
    "i": 6,
    "latency_ms": 171.3,
    "lstm": {
      "status": "warming",
      "score": null,
      "ticks": 8,
      "anomalous": null
    }
  },
  {
    "i": 7,
    "latency_ms": 169.3,
    "lstm": {
      "status": "warming",
      "score": null,
      "ticks": 9,
      "anomalous": null
    }
  },
  {
    "i": 8,
    "latency_ms": 183.8,
    "lstm": {
      "status": "ok",
      "score": 0.997258,
      "ticks": 10,
      "anomalous": true
    }
  },
  {
    "i": 9,
    "latency_ms": 212.1,
    "lstm": {
      "status": "ok",
      "score": 0.997258,
      "ticks": 11,
      "anomalous": true
    }
  },
  {
    "i": 10,
    "latency_ms": 206.1,
    "lstm": {
      "status": "ok",
      "score": 0.997258,
      "ticks": 12,
      "anomalous": true
    }
  }
]
```

</details>

<details><summary>樹莓派 LSTM trace</summary>

```json
[
  {
    "i": 1,
    "latency_ms": 790.8,
    "lstm": {
      "status": "warming",
      "score": null,
      "ticks": 3,
      "anomalous": null
    }
  },
  {
    "i": 2,
    "latency_ms": 1321.5,
    "lstm": {
      "status": "warming",
      "score": null,
      "ticks": 4,
      "anomalous": null
    }
  },
  {
    "i": 3,
    "latency_ms": 1344.0,
    "lstm": {
      "status": "warming",
      "score": null,
      "ticks": 5,
      "anomalous": null
    }
  },
  {
    "i": 4,
    "latency_ms": 783.4,
    "lstm": {
      "status": "warming",
      "score": null,
      "ticks": 6,
      "anomalous": null
    }
  },
  {
    "i": 5,
    "latency_ms": 700.9,
    "lstm": {
      "status": "warming",
      "score": null,
      "ticks": 7,
      "anomalous": null
    }
  },
  {
    "i": 6,
    "latency_ms": 1332.4,
    "lstm": {
      "status": "warming",
      "score": null,
      "ticks": 8,
      "anomalous": null
    }
  },
  {
    "i": 7,
    "latency_ms": 1346.4,
    "lstm": {
      "status": "warming",
      "score": null,
      "ticks": 9,
      "anomalous": null
    }
  },
  {
    "i": 8,
    "latency_ms": 1257.2,
    "lstm": {
      "status": "ok",
      "score": 0.997258,
      "ticks": 10,
      "anomalous": true
    }
  },
  {
    "i": 9,
    "latency_ms": 488.8,
    "lstm": {
      "status": "ok",
      "score": 0.997258,
      "ticks": 11,
      "anomalous": true
    }
  },
  {
    "i": 10,
    "latency_ms": 980.0,
    "lstm": {
      "status": "ok",
      "score": 0.997258,
      "ticks": 12,
      "anomalous": true
    }
  }
]
```

</details>

## 6. `/api/investigate` 摘要

### 電腦
```json
{
  "enrichment_status": "available",
  "sources": 8,
  "generation_status": "generated",
  "summary": "anomaly",
  "recommended_actions": [
    "verify_device_state",
    "review_evidence_window",
    "preserve_flow_metadata"
  ],
  "slm_meta": {
    "status": "runtime_loaded",
    "model_id": "HuggingFaceTB/SmolLM2-360M-Instruct",
    "generation_status": "generated"
  }
}
```

### 樹莓派
```json
{
  "error": "timed out",
  "note": "整輪 V2 suite 內逾時。稍早同環境補測：HTTP 200、約 90204 ms、backend=llama_cpp_server、generation_status=template_fallback（有呼叫生字，未過護欄故回模板）。"
}
```

## 7. 資料集與單元測試

| 套件 | 電腦 | 樹莓派 |
|---|---|---|
| 資料集相關（10 項） | OK / 2688.1 ms / rc=0 | OK / 23848.5 ms / rc=0 |
| 完整 unittest | FAILED (failures=1) / 17970.8 ms / rc=1 | FAILED (failures=2, errors=2) / 34627.8 ms / rc=1 |

<details><summary>電腦資料集測試結尾</summary>

```text
test_infer_label_strips_pcap_csv (tests.test_dataset_m1.InventoryTests.test_infer_label_strips_pcap_csv) ... ok
test_inventory_hashes_csv (tests.test_dataset_m1.InventoryTests.test_inventory_hashes_csv) ... ok
test_column_mapping_normalizes_aliases (tests.test_dataset_m1.LeakageAndMappingTests.test_column_mapping_normalizes_aliases) ... ok
test_leakage_denylist (tests.test_dataset_m1.LeakageAndMappingTests.test_leakage_denylist) ... ok
test_device_holdout_does_not_share_devices (tests.test_dataset_m1.ManifestTests.test_device_holdout_does_not_share_devices) ... ok
test_manifest_is_reproducible (tests.test_dataset_m1.ManifestTests.test_manifest_is_reproducible) ... ok
test_session_aware_does_not_share_sessions (tests.test_dataset_m1.ManifestTests.test_session_aware_does_not_share_sessions) ... ok
test_audit_reports_leakage_and_quality (tests.test_dataset_m1.PreprocessTests.test_audit_reports_leakage_and_quality) ... ok
test_preprocessor_fit_only_on_train (tests.test_dataset_m1.PreprocessTests.test_preprocessor_fit_only_on_train) ... ok
test_official_test_never_enters_train (tests.test_ciciomt_prepare.OfficialFileManifestTests.test_official_test_never_enters_train) ... ok

----------------------------------------------------------------------
Ran 10 tests in 0.101s

OK


```

</details>

<details><summary>樹莓派資料集測試結尾</summary>

```text
test_infer_label_strips_pcap_csv (tests.test_dataset_m1.InventoryTests.test_infer_label_strips_pcap_csv) ... ok
test_inventory_hashes_csv (tests.test_dataset_m1.InventoryTests.test_inventory_hashes_csv) ... ok
test_column_mapping_normalizes_aliases (tests.test_dataset_m1.LeakageAndMappingTests.test_column_mapping_normalizes_aliases) ... ok
test_leakage_denylist (tests.test_dataset_m1.LeakageAndMappingTests.test_leakage_denylist) ... ok
test_device_holdout_does_not_share_devices (tests.test_dataset_m1.ManifestTests.test_device_holdout_does_not_share_devices) ... ok
test_manifest_is_reproducible (tests.test_dataset_m1.ManifestTests.test_manifest_is_reproducible) ... ok
test_session_aware_does_not_share_sessions (tests.test_dataset_m1.ManifestTests.test_session_aware_does_not_share_sessions) ... ok
test_audit_reports_leakage_and_quality (tests.test_dataset_m1.PreprocessTests.test_audit_reports_leakage_and_quality) ... ok
test_preprocessor_fit_only_on_train (tests.test_dataset_m1.PreprocessTests.test_preprocessor_fit_only_on_train) ... ok
test_official_test_never_enters_train (tests.test_ciciomt_prepare.OfficialFileManifestTests.test_official_test_never_enters_train) ... ok

----------------------------------------------------------------------
Ran 10 tests in 0.726s

OK

```

</details>

<details><summary>電腦完整測試結尾</summary>

```text
s.test_attack_sequence_scores_higher) ... ok
test_event_is_advisory_with_evidence_window (test_lstm_baseline.LSTMBaselineTests.test_event_is_advisory_with_evidence_window) ... ok
test_sequences_stay_inside_groups (test_lstm_baseline.TickSequenceTests.test_sequences_stay_inside_groups) ... ok
test_ticks_do_not_cross_devices (test_lstm_baseline.TickSequenceTests.test_ticks_do_not_cross_devices) ... ok
test_allowlist_rejects_unknown_tool (test_rag.RagOrchestratorTests.test_allowlist_rejects_unknown_tool) ... ok
test_orchestrator_returns_sourced_claims_only (test_rag.RagOrchestratorTests.test_orchestrator_returns_sourced_claims_only) ... ok
test_slm_cannot_force_arbitrary_tool (test_rag.RagOrchestratorTests.test_slm_cannot_force_arbitrary_tool) ... ok
test_sft_test_has_enough_negatives (test_slm.SlmGuardrailTests.test_sft_test_has_enough_negatives) ... ok
test_template_output_is_valid (test_slm.SlmGuardrailTests.test_template_output_is_valid) ... ok
test_unknown_evidence_id_triggers_fallback (test_slm.SlmGuardrailTests.test_unknown_evidence_id_triggers_fallback) ... FAIL

======================================================================
FAIL: test_unknown_evidence_id_triggers_fallback (test_slm.SlmGuardrailTests.test_unknown_evidence_id_triggers_fallback)
----------------------------------------------------------------------
Traceback (most recent call last):
  File "D:\實習\avocdo-edgemed-main\avocdo-edgemed-main\tests\test_slm.py", line 37, in test_unknown_evidence_id_triggers_fallback
    self.assertEqual(updated["assessment"]["generation_status"], "template_fallback")
AssertionError: 'generated' != 'template_fallback'
- generated
+ template_fallback


----------------------------------------------------------------------
Ran 38 tests in 11.299s

FAILED (failures=1)


```

</details>

<details><summary>樹莓派完整測試結尾</summary>

```text
       ~~~~~~~~~~~~~~~^
        ticks,
        ^^^^^^
        feature_columns=["packet_rate", "connection_rate", "byte_rate"],
        ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
        seq_len=5,
        ^^^^^^^^^^
    )
    ^
  File "/home/fju/avocdo-edgemed/app/ticks.py", line 144, in build_sequences
    raise ValueError(
    ...<2 lines>...
    )
ValueError: No sequences of length 5 could be built; need enough ticks within each device/session group

======================================================================
FAIL: test_ticks_do_not_cross_devices (test_lstm_baseline.TickSequenceTests.test_ticks_do_not_cross_devices)
----------------------------------------------------------------------
Traceback (most recent call last):
  File "/home/fju/avocdo-edgemed/tests/test_lstm_baseline.py", line 37, in test_ticks_do_not_cross_devices
    self.assertGreaterEqual(len(ticks), 20)
    ~~~~~~~~~~~~~~~~~~~~~~~^^^^^^^^^^^^^^^^
AssertionError: 2 not greater than or equal to 20

======================================================================
FAIL: test_unknown_evidence_id_triggers_fallback (test_slm.SlmGuardrailTests.test_unknown_evidence_id_triggers_fallback)
----------------------------------------------------------------------
Traceback (most recent call last):
  File "/home/fju/avocdo-edgemed/tests/test_slm.py", line 37, in test_unknown_evidence_id_triggers_fallback
    self.assertEqual(updated["assessment"]["generation_status"], "template_fallback")
    ~~~~~~~~~~~~~~~~^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
AssertionError: 'generated' != 'template_fallback'
- generated
+ template_fallback


----------------------------------------------------------------------
Ran 36 tests in 7.907s

FAILED (failures=2, errors=2)

```

</details>

## 8. 白話結論（V2）

1. **SLM 已接上**：PC=`transformers`；Pi=`llama_cpp_server`（GGUF＋常駐 llama-server）。兩邊 `/health` 皆 `runtime_loaded=true`。
2. **生字路徑**：`/api/score` 不跑 SLM；`/api/investigate` 才跑。PC 可到 `generated`；Pi 補測為 `template_fallback`（有跑、未過護欄），整輪 suite 可能 timeout（約 1–2 分鐘級仍偏緊）。
3. **IF 分數兩邊相同（0.311513）**：先前 0.997 vs 0.311 是把「主異常」誤當成 IF；主異常可能被已暖機的 LSTM 蓋過。
4. **LSTM**：兩邊滿 seq_len 後都 `ok`，分數同約 `0.997258`。
5. **延遲**：單次 score PC≈169 ms、Pi≈1.3 s；Pi investigate 生字約 90s 級。
6. **資料集測試**：兩邊 OK（10/10）。
7. **單元測試**：兩邊皆 FAIL；共同項含 SLM fallback 預期差異；Pi 另有 LSTM fixture 不足造成的 ERROR。
