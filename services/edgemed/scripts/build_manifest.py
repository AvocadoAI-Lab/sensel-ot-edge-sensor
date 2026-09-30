import argparse
import json
import sys
from pathlib import Path

import pandas as pd
import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from app.data import (
    apply_column_mapping,
    audit_frame,
    build_manifest,
    write_json,
)
from app.data.inventory import infer_attack_family

parser = argparse.ArgumentParser(description="Build a frozen group-aware dataset manifest")
parser.add_argument("--csv", required=True, help="Input CSV (local sample or mapped CICIoMT extract)")
parser.add_argument(
    "--strategy",
    default="session_aware",
    choices=["random", "session_aware", "device_holdout", "attack_family_holdout"],
)
parser.add_argument("--seed", type=int, default=42)
parser.add_argument("--train-ratio", type=float, default=0.7)
parser.add_argument("--validation-ratio", type=float, default=0.15)
parser.add_argument("--label-column", default="label")
parser.add_argument(
    "--output",
    default=str(ROOT / "artifacts" / "manifests" / "dataset_manifest.json"),
)
parser.add_argument(
    "--audit-output",
    default=str(ROOT / "artifacts" / "manifests" / "leakage_audit.json"),
)
args = parser.parse_args()

frame = pd.read_csv(args.csv)
rename = apply_column_mapping(list(frame.columns))
frame = frame.rename(columns=rename)

if "attack_family" not in frame.columns and args.label_column in frame.columns:
    frame["attack_family"] = frame[args.label_column].astype(str).map(infer_attack_family)

denylist_path = ROOT / "config" / "leakage_denylist.yaml"
extra = []
if denylist_path.exists():
    extra = list((yaml.safe_load(denylist_path.read_text(encoding="utf-8")) or {}).get("extra_denylist", []))

audit = audit_frame(frame, label_column=args.label_column, extra_denylist=extra)
manifest = build_manifest(
    frame,
    strategy=args.strategy,
    seed=args.seed,
    train_ratio=args.train_ratio,
    validation_ratio=args.validation_ratio,
    label_column=args.label_column,
    source={"csv": str(Path(args.csv).resolve()), "strategy": args.strategy},
)

output = Path(args.output)
audit_output = Path(args.audit_output)
write_json(output, manifest)
write_json(audit_output, audit)
print(json.dumps({
    "manifest": str(output),
    "audit": str(audit_output),
    "membership_sha256": manifest["membership_sha256"],
    "split_sizes": manifest["split_sizes"],
    "strategy": manifest["strategy"],
    "leakage_columns_present": audit["leakage_columns_present"],
}, indent=2))
