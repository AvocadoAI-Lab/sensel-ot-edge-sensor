"""End-to-end demo: CIC features -> XGBoost (+IF) -> Fusion(with device allowlist) -> SLM -> RAG."""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from app.classifier import load_classifier, score_known_attack
from app.data.columns import apply_column_mapping, load_column_map
from app.data.ciciomt import discover_ciciomt_csv_dirs, resolve_manifest_files
from app.data.inventory import infer_attack_family, infer_label_from_filename
from app.detector import load_bundle
from app.fusion import fuse_detections
from app.guardrails import enforce_advisory_response, load_security_policy
from app.rag import build_default_orchestrator
from app.schema import assert_detector_fields_unchanged, detector_owned_snapshot
from app.slm import apply_slm_to_event, build_slm_input, parse_slm_json_text


def load_allowlist(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def pick_preset(allowlist: dict, preset_id: str | None) -> dict:
    presets = allowlist.get("demo_presets") or []
    if preset_id:
        for item in presets:
            if item.get("id") == preset_id:
                return item
        raise SystemExit(f"Unknown preset_id: {preset_id}")
    if not presets:
        raise SystemExit("No demo_presets in allowlist")
    return presets[0]


def load_attack_row(
    *,
    dataset_root: Path,
    manifest_path: Path,
    family: str,
    seed: int = 42,
) -> dict:
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    dirs = discover_ciciomt_csv_dirs(dataset_root)
    resolved = resolve_manifest_files(manifest, dirs)
    test_files = resolved.get("test") or []
    if not test_files:
        raise SystemExit("No CICIoMT test files resolved")

    mapping = load_column_map()
    candidates: list[dict] = []
    for path in test_files:
        label = infer_label_from_filename(path)
        fam = infer_attack_family(label)
        if fam != family:
            continue
        frame = pd.read_csv(path, nrows=80)
        if frame.empty:
            continue
        rename = apply_column_mapping(list(frame.columns), mapping)
        frame = frame.rename(columns=rename)
        for idx, row in frame.iterrows():
            features: dict[str, float] = {}
            for key, value in row.items():
                if key in {"label", "attack_family", "source_file"}:
                    continue
                if pd.isna(value):
                    continue
                try:
                    features[str(key)] = float(value)
                except (TypeError, ValueError):
                    continue
            candidates.append(
                {
                    "source_file": path.name,
                    "attack_family": fam,
                    "label": label,
                    "row_index": int(idx),
                    "features": features,
                }
            )
            if len(candidates) >= 5:
                break
        if candidates:
            break
    if not candidates:
        raise SystemExit(f"No test rows found for attack_family={family}")
    return candidates[seed % len(candidates)]


def score_anomaly_if(features: dict[str, float], detector_path: Path) -> tuple[dict | None, list]:
    if not detector_path.exists():
        return None, []
    bundle = load_bundle(detector_path)
    normalized, anomalous, evidence = bundle.score(features)
    payload = {
        "score": round(float(normalized), 6),
        "threshold": round(float(bundle.threshold), 6),
        "anomalous": bool(anomalous),
        "model_version": bundle.metadata.get("artifact_version", "if-0.1.0"),
        "detector": "isolation_forest",
    }
    feature_evidence = [
        {
            "feature": item["feature"],
            "observed": item.get("observed"),
            "baseline": None,
            "source": "detector:isolation_forest",
        }
        for item in evidence
    ]
    return payload, feature_evidence


def generate_slm(event: dict, model_id: str, adapter: str | None, max_new_tokens: int = 220) -> tuple[str, dict | None]:
    from transformers import AutoModelForCausalLM, AutoTokenizer
    import torch

    cache_key = f"{model_id}::{adapter or 'base'}"
    if not hasattr(generate_slm, "_cache"):
        generate_slm._cache = {}
    if cache_key not in generate_slm._cache:
        tokenizer = AutoTokenizer.from_pretrained(model_id)
        model = AutoModelForCausalLM.from_pretrained(model_id)
        if adapter:
            from peft import PeftModel

            model = PeftModel.from_pretrained(model, adapter)
        if torch.cuda.is_available():
            model = model.to("cuda")
        model.eval()
        generate_slm._cache[cache_key] = (tokenizer, model)
    tokenizer, model = generate_slm._cache[cache_key]

    payload = build_slm_input(event)
    user = (
        "You are an evidence-grounded security event formatter. "
        "Return ONLY one JSON object with exactly these keys: "
        "summary_en, taxonomy, evidence_ids, retrieval_intents, status. "
        "taxonomy MUST be one of: network_behavior_anomaly, known_attack_suspected, "
        "detector_conflict, baseline_traffic, unknown, insufficient_evidence. "
        "status MUST be one of: ok, insufficient_evidence, conflict, invalid. "
        "Do NOT use taxonomy values dos, ddos, mqtt, recon, spoofing, or benign. "
        "Do NOT use retrieval intent fallback. "
        "Mention device_type and operating_state from asset_context in summary_en. "
        "Use only provided evidence IDs. Do not invent detector scores.\n"
        f"INPUT:\n{json.dumps(payload, ensure_ascii=True)}"
    )
    messages = [
        {"role": "system", "content": "Return only valid JSON for the security event formatter."},
        {"role": "user", "content": user},
    ]
    prompt = tokenizer.apply_chat_template(messages, tokenize=False, add_generation_prompt=True)
    inputs = tokenizer(prompt, return_tensors="pt")
    if torch.cuda.is_available():
        inputs = {k: v.to("cuda") for k, v in inputs.items()}
    with torch.no_grad():
        out = model.generate(
            **inputs,
            max_new_tokens=max_new_tokens,
            do_sample=False,
            pad_token_id=tokenizer.eos_token_id,
        )
    text = tokenizer.decode(out[0][inputs["input_ids"].shape[-1] :], skip_special_tokens=True)
    parsed = parse_slm_json_text(text)
    return text.strip(), parsed


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--dataset-root", default=r"D:\實習\資料集")
    parser.add_argument("--manifest", default=str(ROOT / "artifacts" / "ciciomt" / "official_file_manifest.json"))
    parser.add_argument("--allowlist", default=str(ROOT / "config" / "devices" / "ciciomt_device_allowlist.json"))
    parser.add_argument("--preset", default="demo-blink-dos")
    parser.add_argument("--xgb", default=str(ROOT / "artifacts" / "classifiers" / "xgboost_category.joblib"))
    parser.add_argument("--detector", default=str(ROOT / "artifacts" / "detector.joblib"))
    parser.add_argument("--model-id", default="HuggingFaceTB/SmolLM2-360M-Instruct")
    parser.add_argument("--adapter", default=str(ROOT / "artifacts" / "slm" / "smollm2-360m-lora-ab" / "adapter"))
    parser.add_argument("--skip-slm-model", action="store_true", help="Use template formatter only")
    parser.add_argument(
        "--output",
        default=str(ROOT / "artifacts" / "e2e" / "asset_pipeline_demo.json"),
    )
    args = parser.parse_args()

    allowlist = load_allowlist(Path(args.allowlist))
    preset = pick_preset(allowlist, args.preset)
    if preset["device_type"] not in allowlist["allowed_device_types"]:
        raise SystemExit(f"preset device_type not in allowlist: {preset['device_type']}")

    row = load_attack_row(
        dataset_root=Path(args.dataset_root),
        manifest_path=Path(args.manifest),
        family=str(preset.get("preferred_attack_family", "dos")),
    )

    xgb = load_classifier(Path(args.xgb))
    features = {name: float(row["features"].get(name, 0.0)) for name in xgb.features}
    known = score_known_attack(xgb, features)
    if known is None:
        raise SystemExit("XGBoost returned no known_attack score")

    anomaly, if_evidence = score_anomaly_if(features, Path(args.detector))
    feature_evidence = [
        {"feature": "source_file", "observed": row["source_file"], "source": "dataset:ciciomt"},
        {"feature": "attack_family_label", "observed": row["attack_family"], "source": "dataset:label"},
        {
            "feature": "asset_allowlist_device",
            "observed": preset["device_name"],
            "source": "config:ciciomt_device_allowlist",
        },
    ] + if_evidence

    event = fuse_detections(
        device_id=preset["device_id"],
        device_type=preset["device_type"],
        operating_state=preset["operating_state"],
        criticality=preset.get("criticality", "high"),
        session_id=f"{preset['id']}:{row['source_file']}",
        known_attack=known,
        anomaly=anomaly,
        anomalies={"isolation_forest": anomaly} if anomaly else None,
        feature_evidence=feature_evidence,
        persist_reason="e2e_asset_pipeline",
    )
    # Keep interaction mode as non-detector metadata for report clarity.
    event["asset"]["device_name"] = preset.get("device_name")
    event["asset"]["interaction_mode"] = preset.get("interaction_mode")
    event["asset"]["allowlist_ref"] = "config/devices/ciciomt_device_allowlist.json"

    security_policy = load_security_policy()
    event = enforce_advisory_response(event, security_policy)

    stage_features = {
        "n_features": len(features),
        "source_file": row["source_file"],
        "dataset_attack_family": row["attack_family"],
    }
    stage_xgb = {
        "task": known.get("task"),
        "category": known.get("category"),
        "probability": known.get("probability"),
        "top_probability": known.get("top_probability"),
        "probabilities": known.get("probabilities"),
        "model_version": known.get("model_version"),
    }
    stage_anomaly = anomaly
    stage_fusion = {
        "event_id": event.get("event_id"),
        "detection_status": (event.get("detection") or {}).get("status"),
        "disagreement": (event.get("detection") or {}).get("disagreement"),
        "verdict": (event.get("assessment") or {}).get("verdict"),
        "severity": (event.get("assessment") or {}).get("severity"),
        "taxonomy": (event.get("assessment") or {}).get("taxonomy"),
        "asset": event.get("asset"),
    }

    before = detector_owned_snapshot(event)
    raw_slm = None
    parsed_slm = None
    if args.skip_slm_model:
        event = apply_slm_to_event(event, None)
        slm_mode = "template_only"
    else:
        adapter = args.adapter if Path(args.adapter).exists() else None
        raw_slm, parsed_slm = generate_slm(event, args.model_id, adapter)
        event = apply_slm_to_event(event, parsed_slm)
        slm_mode = "lora" if adapter else "base"

    rag = build_default_orchestrator(related_events_provider=lambda device_id, limit=5: [])
    event = rag.apply(event)
    assert_detector_fields_unchanged(
        {"detection": before["detection"], "evidence": before["evidence"]},
        event,
    )
    event = enforce_advisory_response(event, security_policy)

    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "pipeline": [
            "features",
            "xgboost",
            "isolation_forest",
            "fusion_with_device_allowlist",
            "slm",
            "rag",
        ],
        "allowlist_path": str(Path(args.allowlist).as_posix()),
        "preset": preset,
        "stages": {
            "features": stage_features,
            "xgboost": stage_xgb,
            "anomaly": stage_anomaly,
            "fusion": stage_fusion,
            "slm_input_asset_context": build_slm_input(event).get("asset_context"),
            "slm": {
                "mode": slm_mode,
                "model_id": args.model_id,
                "adapter": args.adapter if slm_mode == "lora" else None,
                "raw_model_output": raw_slm,
                "parsed_model_output": parsed_slm,
                "applied": {
                    "summary": (event.get("assessment") or {}).get("summary"),
                    "taxonomy": (event.get("assessment") or {}).get("taxonomy"),
                    "generation_status": (event.get("assessment") or {}).get("generation_status"),
                    "evidence_ids": (event.get("assessment") or {}).get("evidence_ids"),
                    "retrieval_intents": (event.get("enrichment") or {}).get("retrieval_intents"),
                },
            },
            "rag": {
                "status": (event.get("enrichment") or {}).get("status"),
                "retrieval_count": (event.get("enrichment") or {}).get("retrieval_count"),
                "sources": (event.get("enrichment") or {}).get("sources"),
                "claims": (event.get("enrichment") or {}).get("claims"),
                "audit": (event.get("enrichment") or {}).get("audit"),
            },
        },
        "final_event": {
            "event_id": event.get("event_id"),
            "asset": event.get("asset"),
            "detection": {
                "status": (event.get("detection") or {}).get("status"),
                "disagreement": (event.get("detection") or {}).get("disagreement"),
                "known_attack": (event.get("detection") or {}).get("known_attack"),
                "anomaly": (event.get("detection") or {}).get("anomaly"),
            },
            "assessment": event.get("assessment"),
            "enrichment": {
                "status": (event.get("enrichment") or {}).get("status"),
                "sources": (event.get("enrichment") or {}).get("sources"),
                "claims": (event.get("enrichment") or {}).get("claims"),
            },
            "response": event.get("response"),
        },
    }

    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")

    md = out.with_suffix(".md")
    applied = report["stages"]["slm"]["applied"]
    rag_stage = report["stages"]["rag"]
    lines = [
        "# E2E Asset Pipeline Demo",
        "",
        f"- Preset: `{preset['id']}` / `{preset['device_type']}` / `{preset['operating_state']}`",
        f"- Source attack file: `{row['source_file']}`",
        f"- XGBoost: category=`{stage_xgb.get('category')}` p≈{stage_xgb.get('probability')}",
        f"- Fusion verdict: `{stage_fusion.get('verdict')}` severity=`{stage_fusion.get('severity')}`",
        f"- SLM mode: `{slm_mode}` generation_status=`{applied.get('generation_status')}`",
        f"- RAG status: `{rag_stage.get('status')}`",
        "",
        "## Asset (environment)",
        "",
        "```json",
        json.dumps(event.get("asset"), ensure_ascii=False, indent=2),
        "```",
        "",
        "## SLM applied",
        "",
        "```json",
        json.dumps(applied, ensure_ascii=False, indent=2),
        "```",
        "",
        "## RAG enrichment",
        "",
        "```json",
        json.dumps(
            {"status": rag_stage.get("status"), "sources": rag_stage.get("sources"), "claims": rag_stage.get("claims")},
            ensure_ascii=False,
            indent=2,
        ),
        "```",
        "",
        f"Full JSON: `{out.as_posix()}`",
    ]
    md.write_text("\n".join(lines), encoding="utf-8")
    print(json.dumps({"ok": True, "json": str(out), "md": str(md), "slm_mode": slm_mode}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
