import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from app.data import build_provenance_record, write_json

parser = argparse.ArgumentParser(
    description=(
        "Record CICIoMT2024 provenance after you complete the official download/terms step. "
        "This script never downloads the dataset."
    )
)
parser.add_argument("--local-root", required=True, help="Extracted dataset directory")
parser.add_argument(
    "--archive",
    action="append",
    default=[],
    help="Optional archive file to hash (repeatable)",
)
parser.add_argument("--source-url", default=None)
parser.add_argument("--retrieved-at", default=None, help="ISO-8601 retrieval timestamp")
parser.add_argument("--notes", default=None)
parser.add_argument(
    "--output",
    default=str(ROOT / "artifacts" / "dataset_provenance.json"),
)
args = parser.parse_args()

record = build_provenance_record(
    local_root=Path(args.local_root),
    archive_paths=[Path(item) for item in args.archive],
    retrieved_at=args.retrieved_at,
    source_url=args.source_url,
    notes=args.notes,
)
output = Path(args.output)
write_json(output, record)
print(json.dumps({"output": str(output), "archives": len(record["archives"])}, indent=2))
