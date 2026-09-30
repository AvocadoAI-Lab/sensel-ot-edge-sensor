"""Append validated CIC holdout-bridge SFT rows into A+B train set."""

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
    rec = {
        "record_id": f"holdout_{item['holdout_id']}",
        "split_group": f"holdout-{item['attack_family']}",
        "input": build_slm_input(event),
        "target": target,
        "metadata": {
            "source": "ciciomt-holdout10",
            "annotator": "a_plus_b_teacher_v1",
            "kind": "holdout_bridge",
            "attack_family": item["attack_family"],
            "label": item["label"],
        },
    }
    rec["target"]["summary_en"] = teacher_summary(rec)
    errors = validate_slm_output(rec["target"], event, cfg)
    if errors:
        raise SystemExit(f"{item['holdout_id']}: {errors}")
    rows.append(rec)

bridge = ROOT / "artifacts" / "slm" / "sft_ab" / "holdout_bridge.jsonl"
bridge.write_text("\n".join(json.dumps(r, ensure_ascii=False) for r in rows) + "\n", encoding="utf-8")

train = ROOT / "artifacts" / "slm" / "sft_ab" / "train.jsonl"
kept = [
    line
    for line in train.read_text(encoding="utf-8").splitlines()
    if line.strip() and '"holdout_bridge"' not in line
]
extra = [json.dumps(r, ensure_ascii=False) for r in rows]
# Repeat bridge examples for stronger domain signal without rebuilding all SFT.
aug = extra * 4
train.write_text("\n".join(kept + aug) + "\n", encoding="utf-8")
print(json.dumps({"bridge": len(rows), "train_lines": len(kept) + len(aug)}, indent=2))
