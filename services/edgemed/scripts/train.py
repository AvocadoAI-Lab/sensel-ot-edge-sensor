import argparse
import json
import sys
from pathlib import Path

import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from app.detector import save_bundle, train_detector

parser = argparse.ArgumentParser()
parser.add_argument("--csv", required=True)
parser.add_argument("--label-column", default="label")
parser.add_argument("--benign-value", default="Benign")
parser.add_argument("--output", default=str(ROOT / "artifacts" / "detector.joblib"))
args = parser.parse_args()

frame = pd.read_csv(args.csv)
label = args.label_column if args.label_column in frame.columns else None
bundle = train_detector(frame, label, args.benign_value)
output = Path(args.output)
save_bundle(bundle, output)
report = {**bundle.metadata, "features": bundle.features, "threshold": bundle.threshold}
report_path = output.with_name("training_report.json")
report_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
print(json.dumps({"model": str(output), "report": str(report_path), **report}, indent=2))
