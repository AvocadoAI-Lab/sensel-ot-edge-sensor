# SenseL Edge ARM64 ML Runtime Audit

P0-C audit 確認原始 `packet-sensor` 只有規則與 signature-based detection pipeline。P1-B 已加入 Isolation Forest、XGBoost 與 Tiny LSTM 的 ONNX adapters，但 repository 仍沒有 production model artifact、training lineage 或 evaluation report。因此 inference 預設關閉，不可將 smoke fixture 當成正式模型。

## 🔎 現況證據

| 問題 | Repository 現況 | 結論 |
|---|---|---|
| Feature extraction | `FeaturePublisher` 輸出 window summary，但沒有凍結 ML feature vector/order | 需先建立 `FeatureContract` |
| Isolation Forest | 已有 ONNX adapter、digest gate、calibration；無 production artifact | Adapter 完成，artifact 待供應 |
| XGBoost | 已有 ONNX adapter、digest gate、calibration；無 production artifact | Adapter 完成，artifact 待供應 |
| Tiny LSTM | 已有 60-frame sequence adapter 與 ONNX Runtime；無 production artifact | Adapter 完成，artifact 待供應 |
| PyTorch runtime | requirements 與 image 均未包含 | Edge 不需要加入 PyTorch |
| ONNX export | 沒有可匯出的 checkpoint、network definition 或 normalization metadata | 現階段不可聲稱已完成 export |
| Existing detection | OT-001～019、IEC 61850、IOC、Snort、Suricata | 可保留為 deterministic detection input |

> [!WARNING]
> 在 feature order、normalization、sequence length 與 label meaning 尚未凍結前直接訓練模型，會產生無法安全部署或 federate 的 artifact。

## 🏗️ P0-C Runtime 邊界

新增的 `OnnxSequenceRuntime` 是可觀測 adapter，不會接管 packet hot path。它提供 `disabled`、`missing`、`dependency_missing`、`load_error`、`ready` 與 `inference_error` 狀態；模型不可用時回傳 explicit unavailable result，而不是靜默 `None`。

```mermaid
flowchart LR
    packet["Packet parser + deterministic rules"] --> summary["Feature window summary"]
    summary --> contract["P1-A FeatureContract + sequence builder"]
    contract --> onnx["OnnxSequenceRuntime"]
    onnx --> score["Versioned inference score"]
    score --> fusion["P1-A deterministic risk fusion"]
    fusion --> episode["TrustEpisode protobuf"]
    packet --> event["Existing SecurityEvent path remains active"]
```

Runtime 使用單執行緒 `CPUExecutionProvider` 與 sequential execution，避免在 1 GB 級 Edge device 產生不可控 thread/memory contention。ML dependencies 由 Docker build arg `INSTALL_ML_RUNTIME=true` 選用；預設 packet-sensor image 不增加重量。

本輪 image size 為 base 約 70.3 MB、啟用 ONNX Runtime 約 110.8 MB，增加約 40.5 MB。因此預設維持停用，只有需要本地 sequence inference 的 hardware profile 才安裝。

---

## 🧪 Smoke Model 與 Benchmark

`tests/fixtures/sequence-risk-smoke.onnx` 是未訓練的 `ReduceMean` graph，只驗證 ARM64 wheel、tensor shape、session load、推論與量測流程。它不是 Tiny LSTM，也不能進 production registry。

Fixture 使用 `requirements-ml-tools.txt` 的 development-only `onnx` package 產生；Tier 1 runtime 不安裝 exporter。

建立含 ONNX Runtime 的 image：

```bash
docker build \
  --build-arg INSTALL_ML_RUNTIME=true \
  -t sensel-packet-sensor:onnx-p0 \
  services/packet-sensor
```

在 target hardware 量測：

```bash
docker run --rm \
  -v "$PWD/services/packet-sensor/tests/fixtures:/fixtures:ro" \
  sensel-packet-sensor:onnx-p0 \
  python -m src.inference.benchmark \
    --model /fixtures/sequence-risk-smoke.onnx
```

P0 smoke budget 為 batch 1、shape `[1,8,4]`、p95 ≤ 25 ms、process max RSS ≤ 256 MiB。這只是 runtime gate；P1 真實 Tiny LSTM 必須另設較嚴格、依硬體 profile 區分的 budget。

本輪在 ARM64 開發主機與 ARM64 Python 3.11 container 的實測如下：

| 環境 | p95 | Process max RSS | 結果 |
|---|---:|---:|---|
| macOS ARM64 / Python 3.12 | 0.0162 ms | 52.73 MiB | Pass |
| Linux aarch64 container / Python 3.11 | 0.0060 ms | 56.74 MiB | Pass |

> [!NOTE]
> Docker 數字來自 Docker Desktop VM，且 graph 只有 314 bytes。這些結果證明 runtime/toolchain 可用，不可外推為真實 Tiny LSTM latency。

---

## 📌 P1-B 完成與後續工作

1. 已定義 `ot-window-v1` FeatureContract、missing policy、normalization 與 60-frame sequence builder。
2. 已建立 deterministic `fusion-v1` 及 SLM-independent Trust Episode protobuf/codec。
3. 已實作 Isolation Forest、XGBoost、Tiny LSTM ONNX adapters、artifact SHA-256 gate 與 versioned Platt/isotonic/identity calibration；raw score 不會直接進 fusion。
4. 已將 model status、version、calibration version、latency 與 last result 寫入 `model-runtime.json`，並納入 Edge Agent health。
5. 下一步取得可重現的 training code、checkpoint、dataset lineage 與 evaluation report，再於 training environment 匯出 ONNX；Edge image 只安裝 ONNX Runtime。
6. Model distribution 尚需補數位簽章、staging health check、atomic activation 與上一版本 artifact rollback；目前可用 `MODEL_INFERENCE_ENABLED=false` 緊急停用。
7. XGBoost federation 不得套用 FedAvg，需使用 model-specific aggregation 或只共享統計/蒸餾成果。
