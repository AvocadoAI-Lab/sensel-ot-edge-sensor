"""Emit a sensel.baseline.profile.v1 artifact for a new asset from a CIC template."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from app.baseline_templates import bind_asset, list_templates, load_template


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--profile-id",
        required=True,
        choices=[str(item.get("profile_id")) for item in list_templates()],
        help="Baseline template profile_id",
    )
    parser.add_argument("--asset-id", required=True, help="New asset identifier (e.g. blink-camera-01)")
    parser.add_argument("--sensor-id", default="ot-edge-pi4", help="Target edge sensor id")
    parser.add_argument("--site-id", default="factory-lab-pi")
    parser.add_argument("--tenant-id", default="default")
    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        help="Write JSON artifact to file (default: stdout)",
    )
    args = parser.parse_args()

    template = load_template(args.profile_id)
    artifact = bind_asset(
        template,
        asset_id=args.asset_id,
        sensor_id=args.sensor_id,
        site_id=args.site_id,
        tenant_id=args.tenant_id,
    )
    text = json.dumps(artifact, ensure_ascii=False, indent=2) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(text, encoding="utf-8")
        print(f"Wrote {args.output}")
    else:
        print(text, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
