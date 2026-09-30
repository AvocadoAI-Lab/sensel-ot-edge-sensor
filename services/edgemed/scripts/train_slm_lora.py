#!/usr/bin/env python3
"""LoRA/PEFT trainer for SmolLM2-360M-Instruct.

This script is intentionally explicit about hardware/dependency gates:
- Requires transformers, peft, datasets, accelerate
- Designed for Apple M2 Pro 16GB (or equivalent)
- Does not download/commit model weights into git
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", default=str(ROOT / "config" / "lora_smollm2_360m.yaml"))
    parser.add_argument("--dry-run", action="store_true", help="Validate config and data only")
    args = parser.parse_args()

    config = yaml.safe_load(Path(args.config).read_text(encoding="utf-8"))
    train_path = ROOT / config["data"]["train_jsonl"]
    val_path = ROOT / config["data"]["validation_jsonl"]
    if not train_path.exists() or not val_path.exists():
        print(json.dumps({
            "status": "blocked",
            "reason": "SFT JSONL missing; run scripts/generate_sft_dataset.py first",
            "train_jsonl": str(train_path),
            "validation_jsonl": str(val_path),
        }, indent=2))
        return 2

    if args.dry_run:
        print(json.dumps({
            "status": "dry_run_ok",
            "base_model": config["base_model"],
            "train_rows": sum(1 for _ in train_path.open(encoding="utf-8") if _.strip()),
            "validation_rows": sum(1 for _ in val_path.open(encoding="utf-8") if _.strip()),
            "lora": config["lora"],
            "export": config["export"],
        }, indent=2))
        return 0

    try:
        import torch
        from datasets import Dataset
        from peft import LoraConfig, get_peft_model
        from transformers import (
            AutoModelForCausalLM,
            AutoTokenizer,
            DataCollatorForLanguageModeling,
            Trainer,
            TrainingArguments,
        )
    except ImportError as exc:
        print(json.dumps({
            "status": "blocked",
            "reason": "Missing training dependencies (transformers/peft/datasets/accelerate/torch)",
            "detail": str(exc),
            "hint": "Install training extras on the M2 Pro machine before fine-tune",
        }, indent=2))
        return 3

    def format_example(item: dict, tokenizer) -> str:
        user = (
            "You are an evidence-grounded security event formatter. "
            "Return ONLY one JSON object with exactly these keys: "
            "summary_en, taxonomy, evidence_ids, retrieval_intents, status. "
            "taxonomy MUST be one of: network_behavior_anomaly, known_attack_suspected, "
            "detector_conflict, baseline_traffic, unknown, insufficient_evidence. "
            "status MUST be one of: ok, insufficient_evidence, conflict, invalid. "
            "Do NOT use status values like inconclusive, partial_detection, or inconsistent_detector_output. "
            "retrieval_intents MUST be a list chosen from: asset_context, behavior_baseline, "
            "threat_context, playbook_lookup, related_events, none. "
            "Do NOT invent intents such as assessment_context, run_shell, or fallback. "
            "Do NOT copy detector attack family names into taxonomy "
            "(never use dos, ddos, mqtt, recon, spoofing, benign as taxonomy). "
            "Mention device_type/operating_state from asset_context in summary_en. "
            "evidence_ids MUST only use IDs present in INPUT.evidence. "
            "summary_en must be a short English sentence. Do not add other keys.\n"
            f"INPUT:\n{json.dumps(item['input'], ensure_ascii=True)}"
        )
        assistant = json.dumps(item["target"], ensure_ascii=True)
        messages = [
            {"role": "user", "content": user},
            {"role": "assistant", "content": assistant},
        ]
        if hasattr(tokenizer, "apply_chat_template"):
            return tokenizer.apply_chat_template(
                messages,
                tokenize=False,
                add_generation_prompt=False,
            )
        return user + "\nOUTPUT:\n" + assistant

    def load_jsonl(path: Path, tokenizer) -> list[dict]:
        rows = []
        for line in path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            item = json.loads(line)
            rows.append({"text": format_example(item, tokenizer)})
        return rows

    tokenizer = AutoTokenizer.from_pretrained(config["base_model"])
    if tokenizer.pad_token is None:
        tokenizer.pad_token = tokenizer.eos_token
    model = AutoModelForCausalLM.from_pretrained(config["base_model"])
    if torch.cuda.is_available():
        model = model.to("cuda")
    lora = LoraConfig(
        r=int(config["lora"]["r"]),
        lora_alpha=int(config["lora"]["lora_alpha"]),
        lora_dropout=float(config["lora"]["lora_dropout"]),
        bias=config["lora"]["bias"],
        task_type=config["lora"]["task_type"],
        target_modules=list(config["lora"]["target_modules"]),
    )
    model = get_peft_model(model, lora)

    train_ds = Dataset.from_list(load_jsonl(train_path, tokenizer))
    val_ds = Dataset.from_list(load_jsonl(val_path, tokenizer))

    def tokenize(batch):
        return tokenizer(
            batch["text"],
            truncation=True,
            max_length=int(config["train"]["max_seq_length"]),
            padding=False,
        )

    train_ds = train_ds.map(tokenize, batched=True, remove_columns=["text"])
    val_ds = val_ds.map(tokenize, batched=True, remove_columns=["text"])

    output_dir = ROOT / config["output_dir"]
    output_dir.mkdir(parents=True, exist_ok=True)
    args_tr = TrainingArguments(
        output_dir=str(output_dir),
        num_train_epochs=float(config["train"]["num_train_epochs"]),
        per_device_train_batch_size=int(config["train"]["per_device_train_batch_size"]),
        gradient_accumulation_steps=int(config["train"]["gradient_accumulation_steps"]),
        learning_rate=float(config["train"]["learning_rate"]),
        lr_scheduler_type=config["train"]["lr_scheduler_type"],
        warmup_ratio=float(config["train"]["warmup_ratio"]),
        logging_steps=int(config["train"]["logging_steps"]),
        eval_strategy=config["train"]["eval_strategy"],
        save_strategy=config["train"]["save_strategy"],
        bf16=bool(config["train"]["bf16"]),
        fp16=bool(config["train"]["fp16"]),
        report_to=[],
    )
    trainer = Trainer(
        model=model,
        args=args_tr,
        train_dataset=train_ds,
        eval_dataset=val_ds,
        data_collator=DataCollatorForLanguageModeling(tokenizer=tokenizer, mlm=False),
    )
    trainer.train()
    adapter_dir = ROOT / config["export"]["adapter_dir"]
    adapter_dir.mkdir(parents=True, exist_ok=True)
    model.save_pretrained(adapter_dir)
    tokenizer.save_pretrained(adapter_dir)
    print(json.dumps({
        "status": "trained",
        "adapter_dir": str(adapter_dir),
        "torch": torch.__version__,
        "note": "Export to GGUF with llama.cpp convert scripts on the edge build host",
    }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
