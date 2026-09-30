"""Freeze 10 CICIoMT rows and score base SmolLM2-360M (pre-finetune baseline).

Re-run after LoRA with --adapter to compare the same frozen inputs.
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from app.classifier import load_classifier, score_known_attack
from app.data.ciciomt import discover_ciciomt_csv_dirs, resolve_manifest_files
from app.data.columns import apply_column_mapping, load_column_map
from app.data.inventory import infer_attack_family, infer_label_from_filename
from app.fusion import fuse_detections
from app.slm import build_slm_input, template_slm_output

HOLDOUT_DIR = ROOT / "artifacts" / "slm" / "holdout_10"
ROWS_PATH = HOLDOUT_DIR / "rows.jsonl"
META_PATH = HOLDOUT_DIR / "manifest.json"
BEFORE_JSON = HOLDOUT_DIR / "before_base_smollm2.json"
BEFORE_MD = HOLDOUT_DIR / "BEFORE_BASE_SMOLLM2_REPORT.md"


def _numeric_features(row: pd.Series, feature_names: list[str]) -> dict[str, float]:
    out: dict[str, float] = {}
    for name in feature_names:
        if name not in row.index or pd.isna(row[name]):
            continue
        try:
            out[name] = float(row[name])
        except (TypeError, ValueError):
            continue
    return out


def build_holdout(
    *,
    dataset_root: Path,
    manifest_path: Path,
    n: int,
    seed: int,
) -> list[dict]:
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    dirs = discover_ciciomt_csv_dirs(dataset_root)
    resolved = resolve_manifest_files(manifest, dirs)
    test_files = resolved["test"]
    if not test_files:
        raise FileNotFoundError("No official test CSV files resolved from manifest")

    rng = np.random.default_rng(seed)
    mapping = load_column_map()
    # Sample candidate rows stratified by attack_family across test files.
    buckets: dict[str, list[dict]] = {}
    for path in test_files:
        label = infer_label_from_filename(path)
        family = infer_attack_family(label)
        # Read a deterministic slice per file to keep IO bounded.
        frame = pd.read_csv(path, nrows=400)
        if frame.empty:
            continue
        rename = apply_column_mapping(list(frame.columns), mapping)
        frame = frame.rename(columns=rename)
        pick = frame.sample(n=min(20, len(frame)), random_state=seed).reset_index(drop=True)
        for idx, row in pick.iterrows():
            feat: dict[str, float] = {}
            for key, value in row.items():
                if key in {"label", "attack_family", "source_file"}:
                    continue
                if pd.isna(value):
                    continue
                try:
                    feat[str(key)] = float(value)
                except (TypeError, ValueError):
                    continue
            buckets.setdefault(family, []).append({
                "source_file": path.name,
                "source_path": str(path),
                "row_index_in_sample": int(idx),
                "label": label,
                "attack_family": family,
                "features": feat,
            })

    families = sorted(buckets)
    if not families:
        raise RuntimeError("No rows collected from CIC test CSVs")

    selected: list[dict] = []
    # Round-robin families for diversity, then fill.
    while len(selected) < n:
        progressed = False
        for family in families:
            if len(selected) >= n:
                break
            if not buckets[family]:
                continue
            i = int(rng.integers(0, len(buckets[family])))
            item = buckets[family].pop(i)
            item["holdout_id"] = f"h{len(selected)+1:02d}"
            selected.append(item)
            progressed = True
        if not progressed:
            break

    if len(selected) < n:
        raise RuntimeError(f"Only collected {len(selected)} rows; need {n}")
    return selected[:n]


def fuse_row(item: dict, xgb) -> dict:
    features = item.get("model_features") or item.get("features") or {}
    known = score_known_attack(xgb, features) if xgb is not None else None
    if known is None and xgb is not None:
        # Fill missing classifier features with 0.0 so holdout still scores.
        filled = {name: float(features.get(name, 0.0)) for name in xgb.features}
        known = score_known_attack(xgb, filled)
        features = filled
    if known is None:
        raise ValueError(f"Unable to score known_attack for {item.get('holdout_id')}")
    event = fuse_detections(
        device_id=f"cic-{item['holdout_id']}",
        device_type="medical_aiot",
        operating_state="unknown",
        criticality="medium",
        session_id=item["source_file"],
        known_attack=known,
        anomaly=None,
        feature_evidence=[
            {"feature": "source_file", "observed": item["source_file"], "source": "dataset:ciciomt"},
            {"feature": "attack_family_label", "observed": item["attack_family"], "source": "dataset:label"},
        ],
        persist_reason="slm_holdout_10",
    )
    return event


def generate_with_model(
    event: dict,
    model_id: str,
    *,
    adapter: str | None = None,
    max_new_tokens: int = 256,
) -> tuple[str, dict | None]:
    """Generate with chat template; optional LoRA adapter. Returns (raw_text, parsed_or_none)."""
    from transformers import AutoModelForCausalLM, AutoTokenizer
    import torch

    cache_key = f"{model_id}::{adapter or 'base'}"
    if not hasattr(generate_with_model, "_cache"):
        generate_with_model._cache = {}
    if cache_key not in generate_with_model._cache:
        tokenizer = AutoTokenizer.from_pretrained(model_id)
        model = AutoModelForCausalLM.from_pretrained(model_id)
        if adapter:
            from peft import PeftModel
            model = PeftModel.from_pretrained(model, adapter)
        if torch.cuda.is_available():
            model = model.to("cuda")
        model.eval()
        generate_with_model._cache[cache_key] = (tokenizer, model)
    tokenizer, model = generate_with_model._cache[cache_key]

    payload = build_slm_input(event)
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
            "Do NOT invent intents such as assessment_context or run_shell. "
            "evidence_ids MUST only use IDs present in INPUT.evidence. "
            "summary_en must be a short English sentence. Do not add other keys.\n"
            f"INPUT:\n{json.dumps(payload, ensure_ascii=True)}\n"
    )
    messages = [{"role": "user", "content": user}]
    prompt = tokenizer.apply_chat_template(messages, tokenize=False, add_generation_prompt=True)
    inputs = tokenizer(prompt, return_tensors="pt")
    if next(model.parameters()).is_cuda:
        inputs = {k: v.to("cuda") for k, v in inputs.items()}
    with torch.no_grad():
        output_ids = model.generate(
            **inputs,
            max_new_tokens=max_new_tokens,
            do_sample=False,
            pad_token_id=tokenizer.eos_token_id,
        )
    raw = tokenizer.decode(output_ids[0][inputs["input_ids"].shape[1] :], skip_special_tokens=True)
    from app.slm import parse_slm_json_text

    parsed = parse_slm_json_text(raw)
    if parsed is None:
        try:
            start = raw.find("{")
            if start >= 0:
                obj, _ = json.JSONDecoder().raw_decode(raw[start:])
                if isinstance(obj, dict):
                    parsed = obj
        except Exception:
            parsed = None
    return raw.strip(), parsed


def run_slm_on_events(events: list[dict], model_id: str, *, adapter: str | None = None) -> list[dict]:
    from app.slm import apply_slm_to_event, load_slm_config

    label = f"{model_id}" + (f" + adapter {adapter}" if adapter else " (base)")
    print(f"Loading model: {label} ...")
    generate_with_model(events[0], model_id, adapter=adapter)
    print("Model loaded. Generating...")
    config = load_slm_config()
    config["model_id"] = model_id
    outputs = []
    for index, event in enumerate(events, start=1):
        print(f"  [{index}/{len(events)}] {event.get('event_id')}")
        raw, parsed = generate_with_model(event, model_id, adapter=adapter)
        updated = apply_slm_to_event(event, parsed, config=config)
        template = template_slm_output(event)
        outputs.append({
            "event_id": event.get("event_id"),
            "slm_input": build_slm_input(event),
            "raw_model_output": raw,
            "parsed_model_output": parsed,
            "template_output": template,
            "model_applied": {
                "summary": (updated.get("assessment") or {}).get("summary"),
                "taxonomy": (updated.get("assessment") or {}).get("taxonomy"),
                "generation_status": (updated.get("assessment") or {}).get("generation_status"),
                "slm_status": (updated.get("assessment") or {}).get("slm_status"),
                "slm_validation_errors": (updated.get("assessment") or {}).get("slm_validation_errors"),
                "retrieval_intents": (updated.get("enrichment") or {}).get("retrieval_intents"),
                "evidence_ids": (updated.get("assessment") or {}).get("evidence_ids"),
            },
        })
    return outputs


def render_md(payload: dict) -> str:
    lines = [
        "# SmolLM2 微調前基準報告（CICIoMT 固定 10 筆）",
        "",
        "| 欄位 | 內容 |",
        "|---|---|",
        f"| 產生時間（UTC） | {payload['generated_at']} |",
        f"| 模型 | `{payload['model_id']}`（未 LoRA） |",
        f"| 資料 | CICIoMT official test 抽樣，已凍結 |",
        f"| 筆數 | {payload['n']} |",
        f"| generated（通過 schema） | {payload['stats']['generated']} |",
        f"| template_fallback | {payload['stats']['template_fallback']} |",
        "",
        "## 說明",
        "",
        "- 這 10 筆凍結在 `artifacts/slm/holdout_10/`，fine-tune 後請用同一批再跑對比。",
        "- 事件以 XGBoost category 為 known-attack；CIC 特徵與 sample-schema IF 不同，故本 holdout 為 partial_detection（僅攻擊層）。",
        "- `generation_status=generated` 表示模型 JSON 通過驗證；否則已強制 template_fallback。",
        "",
        "## 逐筆結果",
        "",
    ]
    for row in payload["rows"]:
        m = row["model_applied"]
        lines.append(f"### {row['holdout_id']} — {row['attack_family']} / {row['label']}")
        lines.append("")
        lines.append(f"- 來源檔：`{row['source_file']}`")
        lines.append(f"- known_attack：`{row.get('known_attack_category')}` p={row.get('known_attack_probability')}")
        lines.append(f"- generation_status：**{m.get('generation_status')}**")
        lines.append(f"- taxonomy（套用後）：`{m.get('taxonomy')}`")
        lines.append(f"- retrieval_intents：`{m.get('retrieval_intents')}`")
        if m.get("slm_validation_errors"):
            lines.append(f"- validation_errors：`{m.get('slm_validation_errors')}`")
        lines.append("")
        lines.append("**模型原始輸出（raw）：**")
        lines.append("")
        lines.append("```")
        lines.append(str(row.get("raw_model_output") or "")[:1200])
        lines.append("```")
        lines.append("")
        lines.append("**套用後 summary（若 fallback 則為 template）：**")
        lines.append("")
        lines.append(f"> {m.get('summary')}")
        lines.append("")
        lines.append("**template 對照：**")
        lines.append("")
        lines.append(f"> {row['template_output'].get('summary_en')}")
        lines.append("")
    lines.extend([
        "## 之後怎麼對比",
        "",
        "```bash",
        "python scripts/run_slm_holdout10.py --phase after --adapter artifacts/slm/lora_adapter",
        "```",
        "",
        "會讀同一 `rows.jsonl`，輸出 `after_*.json` 與對照表。",
        "",
    ])
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--dataset-root", default=r"D:\實習\資料集")
    parser.add_argument("--manifest", default=str(ROOT / "artifacts" / "ciciomt" / "official_file_manifest.json"))
    parser.add_argument("--n", type=int, default=10)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--phase", choices=["before", "after"], default="before")
    parser.add_argument("--adapter", default=None, help="Optional LoRA adapter path for after phase")
    parser.add_argument("--rebuild-holdout", action="store_true")
    parser.add_argument("--model-id", default="HuggingFaceTB/SmolLM2-360M-Instruct")
    args = parser.parse_args()

    HOLDOUT_DIR.mkdir(parents=True, exist_ok=True)
    xgb_path = ROOT / "artifacts" / "classifiers" / "xgboost_category.joblib"
    xgb = load_classifier(xgb_path) if xgb_path.exists() else None

    if args.rebuild_holdout or not ROWS_PATH.exists():
        selected = build_holdout(
            dataset_root=Path(args.dataset_root),
            manifest_path=Path(args.manifest),
            n=args.n,
            seed=args.seed,
        )
        # Attach model-aligned features for stable reload.
        for item in selected:
            raw = item["features"]
            if xgb is not None:
                item["model_features"] = {
                    name: float(raw[name]) if name in raw and raw[name] is not None else 0.0
                    for name in xgb.features
                }
            else:
                item["model_features"] = {
                    k: float(v) for k, v in raw.items() if isinstance(v, (int, float))
                }
        with ROWS_PATH.open("w", encoding="utf-8") as handle:
            for item in selected:
                # Drop bulky unused object columns from raw features for portability.
                slim = {
                    "holdout_id": item["holdout_id"],
                    "source_file": item["source_file"],
                    "label": item["label"],
                    "attack_family": item["attack_family"],
                    "model_features": item["model_features"],
                }
                handle.write(json.dumps(slim, ensure_ascii=False) + "\n")
        META_PATH.write_text(
            json.dumps(
                {
                    "created_at": datetime.now(timezone.utc).isoformat(),
                    "dataset_root": args.dataset_root,
                    "manifest": args.manifest,
                    "n": args.n,
                    "seed": args.seed,
                    "split": "official_test",
                    "note": "Frozen SLM before/after comparison holdout",
                },
                indent=2,
            ),
            encoding="utf-8",
        )
    else:
        selected = []
        with ROWS_PATH.open(encoding="utf-8") as handle:
            for line in handle:
                selected.append(json.loads(line))

    events = []
    row_meta = []
    for item in selected:
        event = fuse_row(item, xgb)
        events.append(event)
        known = (event.get("detection") or {}).get("known_attack") or {}
        row_meta.append({
            "holdout_id": item["holdout_id"],
            "source_file": item["source_file"],
            "label": item["label"],
            "attack_family": item["attack_family"],
            "known_attack_category": known.get("category"),
            "known_attack_probability": known.get("probability"),
            "detection_status": (event.get("detection") or {}).get("status"),
            "event_id": event.get("event_id"),
        })

    adapter = args.adapter if args.phase == "after" else None
    if args.phase == "after" and not adapter:
        adapter = str(ROOT / "artifacts" / "slm" / "smollm2-360m-lora-ab" / "adapter")
    outputs = run_slm_on_events(events, args.model_id, adapter=adapter)

    rows_out = []
    gen = 0
    fb = 0
    for meta, out in zip(row_meta, outputs):
        status = out["model_applied"].get("generation_status")
        if status == "generated":
            gen += 1
        else:
            fb += 1
        rows_out.append({**meta, **out})

    payload = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "phase": args.phase,
        "model_id": args.model_id,
        "adapter": args.adapter,
        "n": len(rows_out),
        "stats": {"generated": gen, "template_fallback": fb},
        "holdout_manifest": str(META_PATH),
        "rows": rows_out,
    }

    if args.phase == "before":
        BEFORE_JSON.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
        BEFORE_MD.write_text(render_md(payload), encoding="utf-8")
        print(json.dumps({"json": str(BEFORE_JSON), "md": str(BEFORE_MD), "stats": payload["stats"]}, indent=2))
    else:
        after_json = HOLDOUT_DIR / "after_lora_smollm2.json"
        after_md = HOLDOUT_DIR / "AFTER_LORA_SMOLLM2_REPORT.md"
        after_json.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
        # Simple side-by-side if before exists
        compare_lines = [
            "# SmolLM2 微調後報告與對照",
            "",
            f"- after generated: {gen}/{len(rows_out)}",
            f"- after fallback: {fb}/{len(rows_out)}",
            "",
        ]
        if BEFORE_JSON.exists():
            before = json.loads(BEFORE_JSON.read_text(encoding="utf-8"))
            compare_lines.append("| ID | family | before status | after status | before taxonomy | after taxonomy |")
            compare_lines.append("|---|---|---|---|---|---|")
            before_map = {r["holdout_id"]: r for r in before["rows"]}
            for row in rows_out:
                b = before_map.get(row["holdout_id"], {})
                compare_lines.append(
                    f"| {row['holdout_id']} | {row['attack_family']} | "
                    f"{(b.get('model_applied') or {}).get('generation_status')} | "
                    f"{row['model_applied'].get('generation_status')} | "
                    f"`{(b.get('model_applied') or {}).get('taxonomy')}` | "
                    f"`{row['model_applied'].get('taxonomy')}` |"
                )
        after_md.write_text("\n".join(compare_lines) + "\n", encoding="utf-8")
        print(json.dumps({"json": str(after_json), "md": str(after_md), "stats": payload["stats"]}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
