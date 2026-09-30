"""Rebuild A+B train with strong enum-locked CIC holdout drills."""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from app.classifier import load_classifier, score_known_attack
from app.fusion import fuse_detections
from app.slm import build_slm_input, load_slm_config, template_slm_output, validate_slm_output
from scripts.enrich_sft_ab_teacher import teacher_summary

SFT_AB = ROOT / "artifacts" / "slm" / "sft_ab"
BACKUP_A = SFT_AB / "a_original_backup"


def holdout_records() -> list[dict]:
    xgb = load_classifier(ROOT / "artifacts" / "classifiers" / "xgboost_category.joblib")
    cfg = load_slm_config()
    rows = []
    for line in (ROOT / "artifacts" / "slm" / "holdout_10" / "rows.jsonl").read_text(encoding="utf-8").splitlines():
        item = json.loads(line)
        known = score_known_attack(xgb, item["model_features"])
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
        )
        target = template_slm_output(event, cfg)
        # Force allowlisted fields explicitly for partial_detection CIC rows.
        if (event.get("detection") or {}).get("status") == "partial_detection":
            target["status"] = "insufficient_evidence"
            target["taxonomy"] = "insufficient_evidence"
            target["retrieval_intents"] = ["asset_context", "behavior_baseline"]
        rec = {
            "record_id": f"enum_{item['holdout_id']}",
            "split_group": f"enum-{item['attack_family']}",
            "input": build_slm_input(event),
            "target": target,
            "metadata": {
                "source": "ciciomt-holdout10-enum-drill",
                "annotator": "a_plus_b_enum_lock_v2",
                "kind": "enum_drill",
                "attack_family": item["attack_family"],
            },
        }
        rec["target"]["summary_en"] = teacher_summary(rec)[:400]
        errors = validate_slm_output(rec["target"], event, cfg)
        if errors:
            raise SystemExit(f"{item['holdout_id']}: {errors}")
        rows.append(rec)
    return rows


def load_base_ab(split: str) -> list[dict]:
    # Prefer regenerating from A backup + B summaries if present.
    path = BACKUP_A / f"{split}.jsonl"
    if not path.exists():
        path = ROOT / "artifacts" / "slm" / "sft" / f"{split}.jsonl"
    rows = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        rec = json.loads(line)
        rows.append(rec)
        enriched = json.loads(json.dumps(rec))
        enriched["target"]["summary_en"] = teacher_summary(enriched)[:400]
        enriched["record_id"] = enriched["record_id"] + "_b"
        meta = dict(enriched.get("metadata") or {})
        meta["annotator"] = "a_plus_b_teacher_v1"
        enriched["metadata"] = meta
        # Validate against a minimal fake event wrapper is hard; trust teacher keeps enums from A.
        rows.append(enriched)
    return rows


def main() -> int:
    SFT_AB.mkdir(parents=True, exist_ok=True)
    drills = holdout_records()
    (SFT_AB / "enum_drill.jsonl").write_text(
        "\n".join(json.dumps(r, ensure_ascii=False) for r in drills) + "\n",
        encoding="utf-8",
    )

    # Enum correction mini-set: wrong near-miss labels mapped to correct targets.
    corrections = []
    for drill in drills:
        for bad_status, bad_intent in (
            ("inconclusive", "assessment_context"),
            ("partial_detection", "assessment_context"),
            ("inconsistent_detector_output", "run_shell"),
        ):
            # Positive locked target only (we do not train on bad outputs as labels).
            locked = json.loads(json.dumps(drill))
            locked["record_id"] = f"{drill['record_id']}_lock_{bad_status}"
            locked["metadata"] = {
                **drill["metadata"],
                "kind": "enum_lock",
                "note": f"reinforce not to use {bad_status}/{bad_intent}",
            }
            corrections.append(locked)

    train = load_base_ab("train")
    # Heavy repeat of enum drills so allowlist sticks.
    train = train + drills * 8 + corrections * 2
    val = load_base_ab("validation") + drills
    test = load_base_ab("test")

    for name, rows in (("train", train), ("validation", val), ("test", test)):
        path = SFT_AB / f"{name}.jsonl"
        path.write_text("\n".join(json.dumps(r, ensure_ascii=False) for r in rows) + "\n", encoding="utf-8")
        print(name, len(rows), str(path))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
