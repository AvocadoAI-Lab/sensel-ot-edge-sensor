#!/usr/bin/env python3
"""Export a candidate detection baseline from learned (commissioning) state.

    python3 scripts/observed-to-baseline.py data/assets/learned-state.db --stdout
    python3 scripts/observed-to-baseline.py data/assets/learned-state.db \
        --out config/policy/baseline.json --force

Run the sensor in detection.mode=learning for a representative period first, then
review this candidate before switching to monitoring. Refuses to clobber an
existing --out without --force.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "services" / "packet-sensor"))

from src.policy.from_observed import baseline_from_state_db  # noqa: E402
from src.policy.schema import validate_policy  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser(description="Derive candidate baseline from learned state DB")
    ap.add_argument("state_db", help="path to the learning state SQLite DB")
    ap.add_argument("--out", default=str(ROOT / "config/policy/baseline.json"))
    ap.add_argument("--site-id", default="")
    ap.add_argument("--stdout", action="store_true")
    ap.add_argument("--force", action="store_true", help="overwrite --out if it exists")
    args = ap.parse_args()

    if not Path(args.state_db).is_file():
        print(f"ERROR: state DB not found: {args.state_db}", file=sys.stderr)
        return 1

    baseline = baseline_from_state_db(args.state_db, site_id=args.site_id)
    for w in validate_policy(baseline):
        print(f"WARN schema: {w}", file=sys.stderr)

    text = json.dumps(baseline, indent=2, ensure_ascii=False) + "\n"
    summary = (
        f"{len(baseline['assets'])} assets, "
        f"{len(baseline['iec61850']['goose_publishers'])} GOOSE publishers, "
        f"{len(baseline['iec61850']['mms_ieds'])} MMS IEDs"
    )

    if args.stdout:
        sys.stdout.write(text)
        print(f"candidate baseline: {summary}", file=sys.stderr)
        return 0

    out = Path(args.out)
    if out.exists() and not args.force:
        print(f"ERROR: {out} exists; use --force to overwrite or --stdout to preview", file=sys.stderr)
        return 2
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(text, encoding="utf-8")
    print(f"wrote {out} — {summary}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
