# Q3 Alpha engineering backlog

This backlog translates `SOW.md` work packages and `PRD.md` requirements into
an implementation order. Q3 Alpha is due 2026-09-30; W9–12 hardening is a Q4
follow-on and is not a Q3 validation claim.

## M0 — Repository bootstrap (complete)

- [x] Local Git repository
- [x] FastAPI vertical slice
- [x] Isolation Forest baseline
- [x] Evidence event JSON
- [x] Synthetic sample generator
- [x] Unit/API smoke tests
- [x] SOW and PRD checked into `docs/`

## M1 — CICIoMT2024 data foundation

- [x] Download from the official source after required user form/terms step
- [x] Record source URL, retrieval time, archive size, and SHA-256
- [x] Inventory CSV/PCAP files and available device/session metadata
- [x] Add a feature dictionary and normalized column mapping
- [x] Implement NaN/inf/duplicate audit
- [x] Implement leakage-field denylist
- [x] Create device/session/scenario group-aware manifests
- [x] Add tests proving preprocessing is fit only on training data
- [x] Official CICIoMT WiFi/MQTT CSV prepare path (`scripts/prepare_ciciomt.py`)

Exit: a frozen manifest produces the same train/validation/test membership on
repeated runs.

Notes: raw CICIoMT archives stay outside git. Local path used in this workspace:
`D:\實習\資料集` with 51 train + 21 test CSVs. File-level official manifest keeps
CIC test files out of train/validation.

## M2 — Parallel detectors

- [x] Logistic Regression baseline
- [x] XGBoost known-threat classifier
- [x] Probability calibration and per-class metrics
- [x] Sequence builder that never crosses device/session boundaries
- [x] LSTM Autoencoder trained on benign-only training sequences
- [x] Isolation Forest versus LSTM AE comparison
- [x] Leave-one-attack-family-out evaluation

Exit: detector outputs are independently versioned and preserve their original
scores and evidence.

Notes: CICIoMT classifiers currently train on deterministic per-file samples via
`scripts/train_classifiers.py`. Online scoring prefers `xgboost_category` (attack
family) and falls back to `xgboost_binary`. Isolation Forest and LSTM AE both
run on `/api/score`; LSTM uses an in-memory per-device tick buffer and reports
`warming` until `seq_len` ticks accumulate.

## M3 — Fusion and event contract

- [x] Freeze evidence schema v0.1
- [x] Add deterministic severity policy
- [x] Add detector disagreement and unavailable states
- [x] Add schema validator and fallback template
- [x] Add event persistence suitable for related-event lookup

Exit: no generated component can mutate detector-owned fields.

## M4 — Starting SLM

- [x] Pin `HuggingFaceTB/SmolLM2-360M-Instruct`
- [x] Generate reviewed JSONL SFT records from fused events
- [x] Include at least 30% negative/insufficient/conflict records in frozen test
- [x] Implement M2 Pro 16GB LoRA/PEFT training configuration
- [x] Evaluate baseline schema/grounding gates on frozen SFT test
- [ ] Run one targeted LoRA fine-tune on M2 Pro 16GB (hardware-gated)
- [ ] Export adapter and Q4_K_M GGUF
- [ ] Benchmark single-event `llama.cpp` inference on Pi 5 8GB
- [x] Write Model Card and provenance report

Exit: evidence-ID precision is 100%; invalid output falls back and never reaches
RAG or the external event API.

Notes: Runtime currently uses deterministic template formatter with full
schema/grounding fallback. `scripts/train_slm_lora.py` is ready for M2 Pro;
adapter/GGUF/Pi 5 measurements remain pending hardware.

## M5 — Deterministic Agentic RAG

- [x] Define Asset, Behavior, Threat, Playbook, and Evidence namespaces
- [x] Implement read-only tool interfaces
- [x] Implement allowlisted deterministic investigation state machine
- [x] Treat SLM retrieval intent as an enum suggestion only
- [x] Add source-ID validation and citation coverage checks
- [x] Add maximum five retrievals, timeout, and audit events

Exit: the SLM cannot select arbitrary tools, create arguments, or execute a
function call.

## M6 — Safety and edge release

- [x] Input/output schema guardrails
- [x] Untrusted log/document instruction tests
- [x] Prohibited-action filter
- [x] Failure injection for each detector, SLM, and RAG
- [x] Dashboard component/degraded-state display
- [ ] Pi 5 latency/RAM/CPU/temperature measurements
- [x] Release Notes, Data Card, Model Cards, and Known Limitations

Exit: advisory-only Q3 Alpha release gate in `docs/SOW.md` passes.

Notes: `scripts/measure_pi5.py` records an explicit unavailable report on
non-Pi hosts so latency/RAM numbers cannot be fabricated. Complete Pi 5
warm-run measurements before claiming edge readiness.

## Q4 hardening

- [ ] 24-hour Pi 5 soak test
- [ ] Independent safety review
- [ ] Virtual-hospital scenario package
- [ ] Testbed data-handling and rollback procedure

Notes: A lightweight system-behavior scenario report (not a full Q4 package) is at
`docs/VIRTUAL_SCENARIO_REPORT.md` (10/10 virtual ward scenarios passed on 2026-08-04).
