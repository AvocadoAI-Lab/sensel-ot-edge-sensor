# SmolLM2-360M-Instruct Model Card (Q3 Alpha)

| Field | Value |
|---|---|
| Model | `HuggingFaceTB/SmolLM2-360M-Instruct` |
| License | Apache-2.0 |
| Role | Evidence-grounded security event formatter |
| Status | Pinned starting SLM for Q3 Alpha |

## Intended use

- Produce short English JSON summaries grounded only in fused evidence events.
- Select allowlisted taxonomy and retrieval intents.
- Cite existing evidence IDs only.

## Out of scope

- Creating or overwriting detector scores, thresholds, or severity.
- Free-form tool calling or device/network write actions.
- Clinical decision making.

## Training data

- SFT JSONL generated from versioned fused evidence events.
- Includes negative cases: insufficient evidence, detector conflict, unknown taxonomy,
  instruction-like untrusted text, and empty retrieval intents.
- Train/validation/test split by `split_group`; frozen test is evaluation-only.

## Evaluation gates (frozen test)

- Raw/template JSON schema validity and post-guardrail 100% valid emission via fallback.
- Evidence-ID precision = 100% (unknown IDs force fallback).
- `insufficient_evidence` quality tracked by F1.
- See `artifacts/slm/sft_eval_report.json` after `scripts/evaluate_sft_gates.py`.

## Fine-tune / edge notes

- LoRA/PEFT config: `config/lora_smollm2_360m.yaml`
- Fine-tune target hardware: Apple M2 Pro 16GB
- Edge inference target: Raspberry Pi 5 8GB, quantized GGUF (`Q4_K_M`) via `llama.cpp`
- Adapter/GGUF artifacts are not committed to git

## Provenance

- Config pin: `config/slm.yaml`
- ADR: `docs/adr/0001-starting-slm.md`
- Dataset provenance: `artifacts/slm/sft/provenance.json`
