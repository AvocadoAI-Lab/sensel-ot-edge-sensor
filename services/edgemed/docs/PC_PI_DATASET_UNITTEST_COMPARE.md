# PC vs 樹莓派 4 — CICIoMT 官方 test 全列評測（含硬體／筆數／管線）

- 評測日期：2026-08-12
- 範圍：**方案 A + C** — CICIoMT 官方 **test 全檔、每檔全列**，並寫入硬體、資料集規模、管線順序、演算法
- 原始 JSON：`artifacts/eval/official_test_full_pc.json`、`artifacts/eval/official_test_full_pi.json`

---

## 0. 先分清楚：10／10 單元測試 ≠ 資料集全測

| | 資料集單元測試（10 題） | 本次官方 test 全列評測 |
|---|---|---|
| 測什麼 | 資料治理邏輯（洩漏欄、切分、preprocessor 只在 train fit） | 已部署模型對 **真實 CIC 標籤** 的準確率 |
| 資料 | 程式自製小假 CSV（約數十列） | 官方 test **21 檔、1,614,182 列** |
| 指令 | `python -m unittest tests.test_dataset_m1 tests.test_ciciomt_prepare -v` | `scripts/eval_official_test_full.py`（PC）／`scripts/eval_official_test_full_stream.py`（Pi 分塊） |
| 結果 | 兩邊皆 **10／10 通過** | 見第 5 節 |

**不能**用「10／10」對外宣稱「下載的 CICIoMT 全測過」。全測是下面這份。

---

## 1. 測試環境（硬體）

| 項目 | 電腦（PC） | 樹莓派 4 |
|---|---|---|
| 機型 | Windows 11 筆電 | Raspberry Pi 4 Model B Rev 1.5 |
| CPU | AMD Ryzen 7 6800H | ARM Cortex-A72（4 核，aarch64） |
| 記憶體 | 31.25 GB（評測時可用約 17 GB） | 系統可見 3.71 GB（評測時可用約 3.35 GB） |
| Python | 3.12.1 | 3.13.5（venv） |
| 角色 | 對照端；一次載入全表 | 邊緣端；**必須分塊**，不可 concat 全表 |
| 評測耗時 | 24.1 秒 | 235.1 秒（約 3.9 分鐘；XGBoost only） |

Pi 4GB 若把 21 個 test CSV 一次拼成 DataFrame 會 OOM／當機。本次改 **chunk_size=3000** 串流。評測期間關掉 uvicorn／llama-server，避免記憶體與供電尖峰。

---

## 2. 資料集規模（CICIoMT Wi-Fi + MQTT）

| 切分 | 檔數 | 列數 | 約略大小 | 路徑 |
|---|---|---|---|---|
| 官方 train | 51 | **7,160,831** | （本機 `D:\實習\資料集\WiFI_and_MQTTattacksCSVtrain`） | 本次**不評測**（只作訓練來源說明） |
| 官方 test | 21 | **1,614,182** | 約 394–413 MB | PC：`D:\實習\資料集\WiFI_and_MQTTattacksCSVtest`；Pi：`/home/fju/dataset/WiFI_and_MQTTattacksCSVtest` |

官方 test 標籤分布（由檔名推斷）：

| 類別 | 列數 |
|---|---|
| Attack | 1,576,575 |
| Benign | 37,607 |
| 合計 | 1,614,182 |

類別模型（attack family）另排除 encoder 沒有的 `spoofing`（ARP Spoofing 1,744 列），故 category 評測列數為 **1,612,438**。

Manifest：`artifacts/ciciomt/official_file_manifest.json`（官方 test 永不進 train）。

---

## 3. 管線順序與演算法

### 3.1 本次「全列評測」實際跑的順序

1. 讀 CICIoMT 官方 test CSV（PC 全表；Pi 分塊）
2. 欄位對應（`app/data/columns.py`）＋由檔名推斷 label／attack family
3. **Isolation Forest**（異常分數 vs 二分類標籤）— PC 有跑；Pi 為避免整板重開而 **跳過**
4. **XGBoost binary**（Attack / Benign）
5. **XGBoost category**（attack family：benign / ddos / dos / mqtt / recon）
6. 對 ground-truth 算 accuracy / F1 / ROC-AUC 等

**LSTM autoencoder 未評測**：官方 CIC CSV 沒有可信的 device／session 時間鍵，無法組成與線上 API 相同的 tick 序列。

### 3.2 線上 API 推論順序（對照，本次沒有對 161 萬列打 `/api/score`）

1. Isolation Forest（`artifacts/detector.joblib`）
2. LSTM autoencoder（裝置 tick 緩衝夠才打分）
3. XGBoost binary / category（已知攻擊）
4. Fusion（選主異常、嚴重度）
5. SLM 摘要（過護欄才用生成句，否則 `template_fallback`）
6. RAG／investigate（可選）

### 3.3 演算法與產物

| 元件 | 演算法 | 產物 | 備註 |
|---|---|---|---|
| Isolation Forest | sklearn `IsolationForest`（200 trees）+ RobustScaler | `artifacts/detector.joblib` | **示範 8 特徵**（`flow_duration` 等），**不是** CIC 45 欄訓練的模型 |
| XGBoost binary | XGBoost Attack/Benign | `artifacts/classifiers/xgboost_binary.joblib` | 對 CIC 官方 test 全列 |
| XGBoost category | XGBoost attack-family | `artifacts/classifiers/xgboost_category.joblib` | 同上；無 `spoofing` 類 |
| LSTM AE | 時序重建誤差 | `artifacts/lstm_ae.joblib` | 全列 CIC CSV **不適用** |

---

## 4. 總覽對照

| 項目 | PC | Pi 4 |
|---|---|---|
| test 檔／列 | 21／1,614,182 | 同左 |
| XGBoost binary acc / F1 / ROC-AUC | 0.99755／0.99875／0.99983 | **完全相同**（acc／F1；AUC 差在浮點尾數） |
| XGBoost category acc／macro-F1 | 0.96403／0.89963 | **完全相同** |
| Isolation Forest | 有跑（見下；對 CIC 無效） | **未跑**（整檔 IF 曾導致 Pi 重開） |
| LSTM | 跳過 | 跳過 |
| 資料集單元測試 | 10／10（約 0.1 秒） | 10／10（約 0.7 秒） |

---

## 5. 全列指標

### 5.1 XGBoost binary（Attack vs Benign，1,614,182 列）

| 指標 | PC | Pi |
|---|---|---|
| accuracy | 0.997552 | 0.997552 |
| F1 | 0.998748 | 0.998748 |
| ROC-AUC | 0.999834 | 0.999834 |
| PR-AUC | 0.999996 | 0.999996 |
| Benign recall | 0.910 | 0.910 |
| Attack recall | 0.9996 | 0.9996 |

兩邊數字對齊，代表 **同一組已部署 XGBoost 權重在 PC／Pi 上推論一致**。

### 5.2 XGBoost category（1,612,438 列）

| 指標 | PC | Pi |
|---|---|---|
| accuracy | 0.964027 | 0.964027 |
| macro-F1 | 0.899627 | 0.899627 |

| family | precision | recall | F1 | support |
|---|---|---|---|---|
| benign | 0.996 | 0.904 | 0.947 | 37,607 |
| ddos | 0.999 | 0.953 | 0.975 | 1,117,096 |
| dos | 0.892 | 0.997 | 0.942 | 428,312 |
| mqtt | 0.557 | 0.934 | 0.698 | 1,747 |
| recon | 0.886 | 0.992 | 0.936 | 27,676 |

`mqtt` 支援數很少，macro-F1 被它拉低；`ddos`／`dos` 佔絕大多數列。

### 5.3 Isolation Forest（僅 PC；1,614,182 列）

| 指標 | PC |
|---|---|
| accuracy | 0.0233 |
| F1 | 0.0 |
| anomalous_rate（全體／Benign／Attack） | 0／0／0 |
| ROC-AUC | 0.433 |

這 **不是**「IF 演算法壞了」，而是部署中的 `detector.joblib` 只認 8 個示範欄位；CIC CSV 是另一套約 45 欄。對不齊的欄會變成 NaN，分數幾乎全低於閾值 → 全部判成「非異常」。**不能**用這組數字宣稱 IF 在 CIC 上的偵測力。

Pi 未重跑 IF：先前一次載入大檔或 IF scoring 與 Pi 重開高度相關（4GB + 供電／熱）。XGBoost 分塊路徑可穩定跑完。

---

## 6. 資料集單元測試（仍保留，但不是全測）

指令：`python -m unittest tests.test_dataset_m1 tests.test_ciciomt_prepare -v`

| 結果 | 電腦 | 樹莓派 |
|---|---|---|
| 通過數 | 10／10 | 10／10 |
| 耗時 | 0.102 秒 | 0.661 秒 |

涵蓋：洩漏 denylist、欄位對應、inventory、manifest（官方 test 永不進 train）、preprocessor 只在 train fit。

**結論：資料治理邏輯兩邊一致；與第 5 節的準確率是兩件事。**

---

## 7. 白話結論

1. **官方 test 全列（161 萬列）已在 PC 與 Pi 跑完 XGBoost**；binary／category 指標兩邊相同。
2. **10／10 只證明切分與防洩漏程式沒壞**，不能代替全列評測。
3. **IF 目前的 joblib 是 8 特徵示範模型**，拿去打 CIC 全列會得到近乎全「正常」——PC 數字已記錄，但不應解讀為 CIC 上的 IF 效能。
4. **Pi 4GB 不能一次載入全 test 表**；分塊 + 單執行緒 + 評測時關掉 API／SLM 才能跑完。
5. 線上完整鏈（IF → LSTM → XGBoost → fusion → SLM）的延遲／摘要對比見 `docs/PI4_VS_PC_COMPARE_V2.md`，不是這份全列分類評測。
