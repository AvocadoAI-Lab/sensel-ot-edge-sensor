import argparse
import json
import sys
from pathlib import Path

import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from app.data import write_json
from app.eval import compare_isolation_forest_and_lstm

parser = argparse.ArgumentParser(description="Compare Isolation Forest vs LSTM AE anomaly baselines")
parser.add_argument("--csv", default=str(ROOT / "data" / "sample_flows.csv"))
parser.add_argument("--label-column", default="label")
parser.add_argument("--benign-value", default="Benign")
parser.add_argument("--seq-len", type=int, default=5)
parser.add_argument("--epochs", type=int, default=8)
parser.add_argument(
    "--output",
    default=str(ROOT / "artifacts" / "classifiers" / "if_vs_lstm.json"),
)
args = parser.parse_args()

frame = pd.read_csv(args.csv)
report = compare_isolation_forest_and_lstm(
    frame,
    label_column=args.label_column,
    benign_value=args.benign_value,
    seq_len=args.seq_len,
    lstm_epochs=args.epochs,
)
output = Path(args.output)
write_json(output, report)
print(json.dumps({"output": str(output), **report}, indent=2))
