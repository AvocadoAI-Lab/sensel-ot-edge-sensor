import argparse
import json
import sys
from pathlib import Path

import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from app.classifier import save_classifier, train_classifier
from app.data import write_json
from app.data.ciciomt import (
    discover_ciciomt_csv_dirs,
    resolve_manifest_files,
    sample_split_frame,
)
from app.data.inventory import infer_attack_family
from app.eval import compare_logreg_and_xgboost, leave_one_attack_family_out

parser = argparse.ArgumentParser(description="Train Logistic Regression and XGBoost known-threat baselines")
parser.add_argument("--csv", default=None, help="Optional single CSV; otherwise use CICIoMT manifest sampling")
parser.add_argument("--manifest", default=str(ROOT / "artifacts" / "ciciomt" / "official_file_manifest.json"))
parser.add_argument("--dataset-root", default=r"D:\實習\資料集")
parser.add_argument("--label-column", default="label")
parser.add_argument("--benign-value", default="Benign")
parser.add_argument("--rows-per-file", type=int, default=1500)
parser.add_argument("--seed", type=int, default=42)
parser.add_argument("--output-dir", default=str(ROOT / "artifacts" / "classifiers"))
args = parser.parse_args()

output_dir = Path(args.output_dir)
output_dir.mkdir(parents=True, exist_ok=True)

if args.csv:
    frame = pd.read_csv(args.csv)
    if "attack_family" not in frame.columns and args.label_column in frame.columns:
        frame["attack_family"] = frame[args.label_column].astype(str).map(infer_attack_family)
    # Simple holdout for ad-hoc CSV mode.
    frame = frame.sample(frac=1.0, random_state=args.seed).reset_index(drop=True)
    cut = int(len(frame) * 0.8)
    train_frame, test_frame = frame.iloc[:cut].copy(), frame.iloc[cut:].copy()
else:
    manifest = json.loads(Path(args.manifest).read_text(encoding="utf-8"))
    dirs = discover_ciciomt_csv_dirs(Path(args.dataset_root))
    resolved = resolve_manifest_files(manifest, dirs)
    train_frame = sample_split_frame(
        resolved["train"],
        rows_per_file=args.rows_per_file,
        seed=args.seed,
    )
    test_frame = sample_split_frame(
        resolved["test"],
        rows_per_file=max(500, args.rows_per_file // 2),
        seed=args.seed + 1,
    )

comparison = compare_logreg_and_xgboost(
    train_frame,
    test_frame,
    label_column=args.label_column,
    benign_value=args.benign_value,
    seed=args.seed,
)
write_json(output_dir / "logreg_xgb_comparison.json", comparison)

artifacts = {}
for model_name in ("logreg", "xgboost"):
    for task in ("binary", "category"):
        bundle = train_classifier(
            train_frame,
            model_name=model_name,
            task=task,
            label_column=args.label_column,
            benign_value=args.benign_value,
            calibrate=(task == "binary"),
            seed=args.seed,
        )
        path = output_dir / f"{model_name}_{task}.joblib"
        save_classifier(bundle, path)
        artifacts[f"{model_name}_{task}"] = str(path)

loafa = leave_one_attack_family_out(
    pd.concat([train_frame, test_frame], ignore_index=True),
    model_name="xgboost",
    label_column=args.label_column,
    benign_value=args.benign_value,
    seed=args.seed,
)
write_json(output_dir / "leave_one_attack_family_out.json", loafa)

summary = {
    "train_rows": int(len(train_frame)),
    "test_rows": int(len(test_frame)),
    "artifacts": artifacts,
    "comparison": comparison,
    "leave_one_attack_family_out": {
        "folds": len(loafa.get("folds", [])),
        "mean_roc_auc": loafa.get("mean_roc_auc"),
    },
}
print(json.dumps(summary, indent=2))
