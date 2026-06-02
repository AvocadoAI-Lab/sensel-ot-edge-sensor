#!/usr/bin/env python3
"""Generate a detection baseline from an IEC 61850 SCD/SCL file.

    python3 scripts/scd-to-baseline.py lab/61850/sample.scd --stdout
    python3 scripts/scd-to-baseline.py substation.scd --out config/policy/baseline.json --force

Refuses to overwrite an existing --out unless --force (so a hand-tuned baseline
is never clobbered silently). Warns about GOOSE blocks with no/odd APPID and
IEDs lacking an IP, and validates the result against the policy schema.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "services" / "packet-sensor"))

from src.parser.scl.scd import parse_scd  # noqa: E402
from src.policy.from_scl import derive_baseline  # noqa: E402
from src.policy.schema import validate_policy  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser(description="Derive detection baseline from an IEC 61850 SCD/SCL file")
    ap.add_argument("scd", help="path to .scd/.scl/.icd/.cid file")
    ap.add_argument("--out", default=str(ROOT / "config/policy/baseline.json"))
    ap.add_argument("--site-id", default="")
    ap.add_argument("--silence-factor", type=float, default=4.0)
    ap.add_argument("--appid-base", type=int, default=16, help="APPID radix (16 per IEC 61850-6)")
    ap.add_argument("--stdout", action="store_true", help="print to stdout instead of writing --out")
    ap.add_argument("--force", action="store_true", help="overwrite --out if it exists")
    args = ap.parse_args()

    try:
        model = parse_scd(args.scd, appid_base=args.appid_base)
    except (FileNotFoundError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    baseline = derive_baseline(model, site_id=args.site_id, silence_factor=args.silence_factor)

    for w in validate_policy(baseline):
        print(f"WARN schema: {w}", file=sys.stderr)
    for g in model.goose:
        if g.appid is None:
            print(f"WARN: GOOSE {g.ied_name}/{g.cb_name} has no APPID — skipped", file=sys.stderr)
        elif not g.appid_in_goose_range:
            print(f"WARN: GOOSE {g.ied_name}/{g.cb_name} APPID {g.appid:#06x} out of GOOSE "
                  f"range (>0x3FFF) — check --appid-base", file=sys.stderr)
    for ied in model.ieds:
        if not ied.ip:
            print(f"WARN: IED {ied.ied_name} has no IP in the Communication section", file=sys.stderr)

    text = json.dumps(baseline, indent=2, ensure_ascii=False) + "\n"
    summary = (
        f"{len(baseline['assets'])} assets, "
        f"{len(baseline['iec61850']['goose_publishers'])} GOOSE publishers, "
        f"{len(baseline['iec61850']['mms_ieds'])} MMS IEDs"
    )

    if args.stdout:
        sys.stdout.write(text)
        print(f"derived baseline: {summary}", file=sys.stderr)
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
