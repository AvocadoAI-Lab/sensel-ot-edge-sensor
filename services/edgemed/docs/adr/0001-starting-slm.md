# ADR-0001: Starting SLM is SmolLM2-360M-Instruct

- Status: accepted for Q3 Alpha
- Date: 2026-08-02

## Decision

Use `HuggingFaceTB/SmolLM2-360M-Instruct` as the single starting generative SLM.
Fine-tune with LoRA/PEFT on Apple M2 Pro 16GB and evaluate quantized GGUF
inference with `llama.cpp` on Raspberry Pi 5 8GB.

## Allowed responsibilities

- Produce a short English summary grounded only in supplied evidence.
- Select an allowlisted taxonomy value.
- Return existing evidence IDs.
- Return an allowlisted retrieval-intent enum.
- Return `insufficient_evidence` when support is missing.

## Prohibited responsibilities

- Creating or overwriting detector scores, thresholds, severity scores, or
  evidence.
- Free-form function calling or tool argument creation.
- Network or device writes, containment, exploitation, or clinical decisions.

## Exit criteria

Evaluate a larger model only after a baseline and one targeted fine-tune fail
the frozen test gates, or Pi 5 measurements show the 360M path is unacceptable.
The only initial upgrade candidates are SmolLM2-1.7B-Instruct and an eligible
approximately 2B IBM Granite instruct model.
