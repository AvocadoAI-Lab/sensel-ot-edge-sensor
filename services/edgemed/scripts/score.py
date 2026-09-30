import argparse
import json
import sys
from pathlib import Path

import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from app.detector import load_bundle, security_event

parser = argparse.ArgumentParser()
parser.add_argument("--csv", required=True)
parser.add_argument("--model", default=str(ROOT / "artifacts" / "detector.joblib"))
parser.add_argument("--limit", type=int, default=20)
args = parser.parse_args()

bundle = load_bundle(Path(args.model))
frame = pd.read_csv(args.csv).tail(args.limit)
for index, row in frame.iterrows():
    features = {name: float(row[name]) for name in bundle.features}
    event = security_event(
        bundle,
        f"csv-{index}",
        str(row.get("device_type", "medical_aiot")),
        str(row.get("operating_state", "unknown")),
        features,
    )
    print(json.dumps(event))
