import argparse
import json
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from app.slm import validate_slm_output
from app.data import write_json

parser = argparse.ArgumentParser(
    description="Evaluate SLM schema/grounding gates on frozen SFT test JSONL (template or model outputs)"
)
parser.add_argument("--test-jsonl", default=str(ROOT / "artifacts" / "slm" / "sft" / "test.jsonl"))
parser.add_argument("--output", default=str(ROOT / "artifacts" / "slm" / "sft_eval_report.json"))
args = parser.parse_args()

path = Path(args.test_jsonl)
if not path.exists():
    raise SystemExit(f"Missing frozen test set: {path}. Run scripts/generate_sft_dataset.py first.")

rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
valid = 0
evidence_precision_hits = 0
evidence_total = 0
insufficient_tp = insufficient_fp = insufficient_fn = 0

for row in rows:
    # Reconstruct a minimal event shell for evidence allowlisting.
    event = {
        "evidence": row["input"].get("evidence", []),
        "detection": row["input"].get("detector_outputs", {}),
        "assessment": {},
        "asset": row["input"].get("asset_context", {}),
    }
    target = row["target"]
    errors = validate_slm_output(target, event)
    if not errors:
        valid += 1

    allowed = {item.get("evidence_id") for item in event.get("evidence", []) if item.get("evidence_id")}
    predicted_ids = target.get("evidence_ids") or []
    for evidence_id in predicted_ids:
        evidence_total += 1
        if evidence_id in allowed:
            evidence_precision_hits += 1

    gold_insufficient = target.get("status") == "insufficient_evidence"
    pred_insufficient = target.get("status") == "insufficient_evidence"
    if gold_insufficient and pred_insufficient:
        insufficient_tp += 1
    elif pred_insufficient and not gold_insufficient:
        insufficient_fp += 1
    elif gold_insufficient and not pred_insufficient:
        insufficient_fn += 1

precision = evidence_precision_hits / max(evidence_total, 1)
schema_valid_rate = valid / max(len(rows), 1)
insuff_precision = insufficient_tp / max(insufficient_tp + insufficient_fp, 1)
insuff_recall = insufficient_tp / max(insufficient_tp + insufficient_fn, 1)
insuff_f1 = (
    0.0
    if insuff_precision + insuff_recall == 0
    else 2 * insuff_precision * insuff_recall / (insuff_precision + insuff_recall)
)

negatives = sum(1 for row in rows if row.get("metadata", {}).get("kind") not in {"sufficient"})
report = {
    "model_pin": "HuggingFaceTB/SmolLM2-360M-Instruct",
    "rows": len(rows),
    "negative_ratio": negatives / max(len(rows), 1),
    "schema_valid_rate": schema_valid_rate,
    "evidence_id_precision": precision,
    "insufficient_evidence_f1": insuff_f1,
    "notes": [
        "This baseline evaluates reviewed target JSON / template contract on the frozen set.",
        "LoRA fine-tune and Pi 5 GGUF latency measurements remain hardware-gated.",
    ],
    "gates": {
        "schema_valid_rate_ge_0_95": schema_valid_rate >= 0.95,
        "evidence_id_precision_eq_1": precision == 1.0,
        "negative_ratio_ge_0_30": (negatives / max(len(rows), 1)) >= 0.30,
    },
}
write_json(Path(args.output), report)
print(json.dumps(report, indent=2))
