import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from app.sft import generate_sft_dataset, write_sft_splits

parser = argparse.ArgumentParser(description="Generate SmolLM2 SFT JSONL from fused evidence events")
parser.add_argument("--records-per-kind", type=int, default=40)
parser.add_argument("--seed", type=int, default=42)
parser.add_argument("--output-dir", default=str(ROOT / "artifacts" / "slm" / "sft"))
args = parser.parse_args()

splits = generate_sft_dataset(records_per_kind=args.records_per_kind, seed=args.seed)
report = write_sft_splits(splits, Path(args.output_dir))
print(json.dumps(report, indent=2))
