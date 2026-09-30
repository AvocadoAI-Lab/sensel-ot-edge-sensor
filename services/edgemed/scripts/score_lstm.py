import argparse
import json
import sys
from pathlib import Path

import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from app.lstm_ae import load_lstm_bundle, score_frame_sequences

parser = argparse.ArgumentParser(description="Score tick sequences with the LSTM AE baseline")
parser.add_argument("--csv", required=True)
parser.add_argument("--model", default=str(ROOT / "artifacts" / "lstm_ae.joblib"))
parser.add_argument("--timestamp-column", default="timestamp")
parser.add_argument("--label-column", default="label")
parser.add_argument("--limit", type=int, default=20)
args = parser.parse_args()

bundle = load_lstm_bundle(Path(args.model))
frame = pd.read_csv(args.csv)
events = score_frame_sequences(
    bundle,
    frame,
    timestamp_column=args.timestamp_column,
    label_column=args.label_column if args.label_column in frame.columns else None,
    limit=args.limit,
)
for event in events:
    print(json.dumps(event))
