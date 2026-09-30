import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from app.data import audit_frame, fit_preprocessor, save_preprocessor, write_json
from app.data.ciciomt import (
    assert_file_manifest_reproducible,
    build_official_file_manifest,
    discover_ciciomt_csv_dirs,
    list_split_csvs,
    resolve_manifest_files,
    sample_split_frame,
)
from app.data.inventory import inventory_dataset
from app.data.provenance import build_provenance_record

parser = argparse.ArgumentParser(
    description="Prepare CICIoMT2024 CSV tree: inventory, official file manifest, train-only preprocessor"
)
parser.add_argument("--root", required=True, help="Dataset root containing train/test CSV folders")
parser.add_argument("--seed", type=int, default=42)
parser.add_argument("--validation-file-ratio", type=float, default=0.15)
parser.add_argument("--rows-per-file", type=int, default=2000, help="Rows sampled per train file for preprocess fit/audit")
parser.add_argument("--output-dir", default=str(ROOT / "artifacts" / "ciciomt"))
args = parser.parse_args()

root = Path(args.root)
output_dir = Path(args.output_dir)
output_dir.mkdir(parents=True, exist_ok=True)

dirs = discover_ciciomt_csv_dirs(root)
train_files = list_split_csvs(dirs["train"])
test_files = list_split_csvs(dirs["test"])

inventory = inventory_dataset(root)
write_json(output_dir / "dataset_inventory.json", inventory)

provenance = build_provenance_record(
    local_root=root,
    notes=(
        f"Prepared official CSV splits from {dirs['train']} and {dirs['test']}; "
        f"{len(train_files)} train files, {len(test_files)} test files."
    ),
)
write_json(output_dir / "dataset_provenance.json", provenance)

manifest = build_official_file_manifest(
    train_files=train_files,
    test_files=test_files,
    seed=args.seed,
    validation_file_ratio=args.validation_file_ratio,
    source={
        "root": str(root.resolve()),
        "train_dir": str(dirs["train"]),
        "test_dir": str(dirs["test"]),
    },
)
assert_file_manifest_reproducible(train_files, test_files, manifest)
manifest_path = output_dir / "official_file_manifest.json"
write_json(manifest_path, manifest)

resolved = resolve_manifest_files(manifest, dirs)
train_sample = sample_split_frame(
    resolved["train"],
    rows_per_file=args.rows_per_file,
    seed=args.seed,
)
audit = audit_frame(train_sample, label_column="label")
write_json(output_dir / "train_sample_leakage_audit.json", audit)

bundle = fit_preprocessor(train_sample, label_column="label")
preprocessor_path = output_dir / "preprocessor.joblib"
save_preprocessor(bundle, preprocessor_path)
report = {
    **bundle.metadata,
    "manifest_membership_sha256": manifest["membership_sha256"],
    "split_sizes_files": manifest["split_sizes_files"],
    "sampled_train_rows": int(len(train_sample)),
    "rows_per_file": args.rows_per_file,
}
write_json(output_dir / "preprocess_report.json", report)

# Keep a small reviewed sample for smoke training without shipping the full corpus.
sample_path = output_dir / "train_sample.csv"
train_sample.to_csv(sample_path, index=False)

summary = {
    "root": str(root.resolve()),
    "train_dir": str(dirs["train"]),
    "test_dir": str(dirs["test"]),
    "train_files": len(train_files),
    "test_files": len(test_files),
    "manifest": str(manifest_path),
    "membership_sha256": manifest["membership_sha256"],
    "split_sizes_files": manifest["split_sizes_files"],
    "preprocessor": str(preprocessor_path),
    "train_sample": str(sample_path),
    "leakage_columns_present": audit["leakage_columns_present"],
    "usable_numeric_features": len(audit["usable_numeric_features"]),
}
print(json.dumps(summary, indent=2))
