# Avocdo EdgeMed Security — Release Notes v0.1 (Q3 Alpha research preview)

| Field | Value |
|---|---|
| Release | 0.1.0-alpha |
| Date | 2026-08-04 |
| Type | Research / Developer Preview |

## Summary

Local-first medical AIoT/OT advisory detection slice with:

- Isolation Forest + tick/LSTM anomaly baselines
- Logistic Regression / XGBoost known-threat baselines on CICIoMT2024 CSV samples
- Deterministic fusion + Security Event Schema v0.1
- SmolLM2-360M pin with template formatter + grounding fallback
- Deterministic allowlisted Agentic RAG
- Input/output safety guardrails and failure-injection tests

## Advisory-only boundary

- No device isolation, packet injection, active scanning, or firewall writes
- Human approval required for any operational response
- Detector-owned scores/evidence cannot be overwritten by SLM/RAG

## Known limitations

- CICIoMT official CSV extracts lack device/session timestamps; LSTM comparison uses synthetic temporal flows
- Classifier training currently uses deterministic per-file sampling, not full-corpus offline training
- SmolLM2 LoRA adapter / GGUF / Pi 5 latency-RAM measurements are hardware-gated and not claimed here
- RAG knowledge is a small synthetic local KB for Q3 architecture proof, not a clinical CMDB
- Dashboard is a research preview, not a SOC product

## Verification commands

```bash
python -m unittest discover -s tests -v
python scripts/run_failure_injection.py
python scripts/measure_pi5.py
```

## Documents

- `docs/PRD.md`, `docs/SOW.md`, `docs/BACKLOG.md`
- `docs/data/DATASET_CARD.md`
- `docs/models/SMOLLM2_360M_MODEL_CARD.md`
- `config/security_policy.yaml`
