import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from app.data import inventory_dataset, write_json

parser = argparse.ArgumentParser(description="Inventory a local CICIoMT2024 (or CSV/PCAP) tree")
parser.add_argument("--root", required=True, help="Dataset root directory")
parser.add_argument(
    "--output",
    default=str(ROOT / "artifacts" / "dataset_inventory.json"),
    help="Where to write the inventory JSON",
)
args = parser.parse_args()

payload = inventory_dataset(Path(args.root))
output = Path(args.output)
write_json(output, payload)
print(json.dumps({
    "output": str(output),
    "file_count": payload["file_count"],
    "csv_count": payload["csv_count"],
    "pcap_count": payload["pcap_count"],
}, indent=2))
