import argparse
import json
import sys
from pathlib import Path

import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from app.lstm_ae import save_lstm_bundle, train_lstm_detector

parser = argparse.ArgumentParser(description="Train tick + LSTM Autoencoder baseline")
parser.add_argument("--csv", required=True)
parser.add_argument("--label-column", default="label")
parser.add_argument("--benign-value", default="Benign")
parser.add_argument("--timestamp-column", default="timestamp")
parser.add_argument("--tick-seconds", type=int, default=60)
parser.add_argument("--seq-len", type=int, default=10)
parser.add_argument("--epochs", type=int, default=25)
parser.add_argument("--output", default=str(ROOT / "artifacts" / "lstm_ae.joblib"))
args = parser.parse_args()

frame = pd.read_csv(args.csv)
label = args.label_column if args.label_column in frame.columns else None
bundle = train_lstm_detector(
    frame,
    label_column=label,
    benign_value=args.benign_value,
    timestamp_column=args.timestamp_column,
    tick_seconds=args.tick_seconds,
    seq_len=args.seq_len,
    epochs=args.epochs,
)
output = Path(args.output)
save_lstm_bundle(bundle, output)
report = {
    **bundle.metadata,
    "features": bundle.features,
    "threshold": bundle.threshold,
    "seq_len": bundle.seq_len,
    "tick_seconds": bundle.tick_seconds,
}
report_path = output.with_name("lstm_training_report.json")
report_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
print(json.dumps({"model": str(output), "report": str(report_path), **report}, indent=2))
