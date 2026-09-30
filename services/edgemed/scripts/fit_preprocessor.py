import argparse
import json
import sys
from pathlib import Path

import pandas as pd
import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from app.data import apply_manifest, fit_preprocessor, save_preprocessor, write_json

parser = argparse.ArgumentParser(description="Fit preprocessing only on the manifest train split")
parser.add_argument("--csv", required=True)
parser.add_argument("--manifest", required=True)
parser.add_argument("--label-column", default="label")
parser.add_argument(
    "--output",
    default=str(ROOT / "artifacts" / "preprocessor.joblib"),
)
parser.add_argument(
    "--report",
    default=str(ROOT / "artifacts" / "preprocess_report.json"),
)
args = parser.parse_args()

frame = pd.read_csv(args.csv)
manifest = json.loads(Path(args.manifest).read_text(encoding="utf-8"))
splits = apply_manifest(frame, manifest)

denylist_path = ROOT / "config" / "leakage_denylist.yaml"
extra = []
if denylist_path.exists():
    extra = list((yaml.safe_load(denylist_path.read_text(encoding="utf-8")) or {}).get("extra_denylist", []))

bundle = fit_preprocessor(
    splits["train"],
    label_column=args.label_column if args.label_column in splits["train"].columns else None,
    extra_denylist=extra,
)
output = Path(args.output)
save_preprocessor(bundle, output)
report = {
    **bundle.metadata,
    "manifest_membership_sha256": manifest.get("membership_sha256"),
    "split_sizes": {name: int(len(values)) for name, values in splits.items()},
}
write_json(Path(args.report), report)
print(json.dumps({"preprocessor": str(output), "report": args.report, **report}, indent=2))
