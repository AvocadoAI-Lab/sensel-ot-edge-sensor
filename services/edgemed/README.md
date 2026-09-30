# SenseL EdgeMed

**sensel-ot-edge** repo 內的偵測服務目錄（`services/edgemed/`）。**不是**獨立 GitHub repo；上傳時與 packet-sensor、edge-agent 同一 repo。

原 `avocdo-edgemed` 已併入此目錄。Pi 上由 `deploy/pi4/start-native-edgemed.sh` 啟動；Packet Sensor 以 `inference.backend: edgemed` 將特徵 + baseline profile POST 至 `/api/score`，在此完成 Baseline / XGB / IF 平行判斷與一次 fusion。

Local-first medical AIoT/OT security research slice. The current vertical
slice trains an Isolation Forest on benign numeric flow records, scores new
flows, emits a versioned evidence event, and serves a small dashboard/API.

It also builds fixed-length observe ticks per device/session and trains an LSTM
Autoencoder on benign tick sequences as the temporal anomaly baseline.

The Q3 Alpha target adds parallel XGBoost known-threat classification, evidence
fusion, a fine-tuned SmolLM2-360M event formatter, deterministic Agentic RAG,
and read-only safety guardrails.

> Research preview only. It must not block or isolate medical devices and is
> not validated for clinical use.

## Quick start

```bash
cd services/edgemed
python3 scripts/generate_sample.py
python3 scripts/train.py --csv data/sample_flows.csv --label-column label
python3 scripts/score.py --csv data/sample_flows.csv --limit 20
uvicorn app.main:app --host 127.0.0.1 --port 8000
```

### Tick + LSTM baseline

Sample flows include `timestamp`, `device_id`, and `session_id`. Train the LSTM
AE on benign-only tick sequences:

```bash
python3 scripts/generate_sample.py
python3 scripts/train_lstm.py --csv data/sample_flows.csv --label-column label
python3 scripts/score_lstm.py --csv data/sample_flows.csv --limit 20
```

Ticks never cross devices or sessions. Default tick length is 60 seconds and
default sequence length is 10 ticks.

Open <http://127.0.0.1:8000>. API documentation is at
<http://127.0.0.1:8000/docs>.

## CICIoMT2024 usage

Raw CICIoMT2024 is not redistributed here. After completing the official CIC
terms/download step, record provenance, inventory files, freeze a manifest, and
fit preprocessing on the train split only:

```bash
python scripts/record_provenance.py --local-root /path/to/CICIoMT2024 --archive /path/to/archive.zip
python scripts/inventory_dataset.py --root /path/to/CICIoMT2024
python scripts/build_manifest.py --csv data/sample_flows.csv --strategy device_holdout
python scripts/fit_preprocessor.py --csv data/sample_flows.csv --manifest artifacts/manifests/dataset_manifest.json
```

After local download:

```bash
python scripts/prepare_ciciomt.py --root "D:\實習\資料集"
```

This writes `artifacts/ciciomt/official_file_manifest.json`, a train-only
preprocessor, leakage audit, and a sampled `train_sample.csv` for smoke tests.
Official CIC test files never enter train/validation.

Point detectors at a CSV after governance. Numeric columns are selected
automatically; identifiers and known leakage-prone columns are excluded.

```bash
python scripts/train.py \
  --csv /path/to/CICIoMT2024.csv \
  --label-column label \
  --benign-value Benign
```

For the LSTM path, the CSV must also provide `timestamp` and `device_id`
(plus `session_id` when available):

```bash
python scripts/train_lstm.py \
  --csv /path/to/CICIoMT2024.csv \
  --label-column label \
  --benign-value Benign \
  --tick-seconds 60 \
  --seq-len 10
```

Inspect `artifacts/training_report.json` or `artifacts/lstm_training_report.json`
before trusting the model. Release claims must use a frozen group-aware
manifest, not a random row split.

## Product specifications

- [`docs/SOW.md`](docs/SOW.md) — scope, work packages, milestones, and gates.
- [`docs/PRD.md`](docs/PRD.md) — product behavior and acceptance criteria.
- [`docs/BACKLOG.md`](docs/BACKLOG.md) — executable Q3 engineering backlog.
- [`docs/data/DATASET_CARD.md`](docs/data/DATASET_CARD.md) — CICIoMT2024 access and governance.
- [`docs/DESIGN_BRIEFING_ZH.md`](docs/DESIGN_BRIEFING_ZH.md) — 整體設計說明（師生報告用）
- [`docs/METRICS_BEFORE_AFTER_ZH.md`](docs/METRICS_BEFORE_AFTER_ZH.md) — XGBoost／LSTM 指標與 SLM 訓練前後對比
- [`docs/RELEASE_NOTES.md`](docs/RELEASE_NOTES.md) — alpha release notes and known limitations.
- [`AGENTS.md`](AGENTS.md) — repository safety and verification instructions.

## Current status

- [x] Synthetic flow generator
- [x] Isolation Forest anomaly baseline
- [x] Tick aggregation and device/session sequence builder
- [x] LSTM Autoencoder benign-sequence baseline
- [x] CICIoMT2024 governance path (inventory/manifest/leakage/preprocess)
- [x] Official CICIoMT2024 CSV prepared locally
- [x] Logistic Regression + XGBoost known-threat baselines
- [x] Evidence fusion and schema v0.1 event contract
- [x] SmolLM2-360M pin, SFT dataset, template formatter + fallback
- [x] Deterministic Agentic RAG (allowlisted tools + state machine)
- [x] Safety guardrails, failure injection, degraded dashboard
- [x] Evidence-grounded event schema v0.1
- [x] FastAPI and dashboard
- [x] Unit and API smoke tests
- [ ] LoRA fine-tune + GGUF/Pi 5 measurements (hardware-gated)
- [ ] Q4 virtual-hospital hardening

## API

- `GET /health`
- `GET /api/model`
- `GET /api/demo-events?limit=25`
- `POST /api/score`
- `POST /api/investigate`
- `GET /api/events/{event_id}`

Example score request:

```json
{
  "device_id": "monitor-07",
  "device_type": "patient_monitor",
  "operating_state": "idle",
  "features": {
    "flow_duration": 1.2,
    "packet_rate": 84,
    "byte_rate": 25000,
    "syn_count": 2,
    "ack_count": 8,
    "connection_rate": 6,
    "mean_packet_size": 320,
    "iat_mean": 0.08
  }
}
```
