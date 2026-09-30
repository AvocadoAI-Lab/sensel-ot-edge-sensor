"""Learn a candidate baseline from a pcap file.

Runs inside the packet-sensor container (it owns scapy + the parsers). The
edge-console invokes it via ``docker exec``:

    python -m src.baseline.learn --pcap /app/data/agent/baseline/uploads/x.pcap \
        --out /app/data/assets/baseline/candidate.json --source-ref x.pcap

Writes the candidate JSON atomically to ``--out`` and prints a summary to
stdout so the caller can surface progress without re-reading the file.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
import time
from pathlib import Path

from src.baseline.collector import BaselineCollector


def _atomic_write(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, ensure_ascii=False, indent=2)
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def learn_from_pcap(pcap_path: str, *, limit: int = 0, source_ref: str = "") -> dict:
    from scapy.all import sniff  # imported lazily; only needed at runtime

    collector = BaselineCollector()
    kwargs = {"offline": pcap_path, "prn": collector.observe, "store": False}
    if limit and limit > 0:
        kwargs["count"] = int(limit)
    sniff(**kwargs)
    return collector.to_candidate(
        source="pcap_import",
        source_ref=source_ref or Path(pcap_path).name,
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="baseline.learn")
    parser.add_argument("--pcap", required=True, help="Path to pcap/pcapng file")
    parser.add_argument("--out", required=True, help="Path to write candidate JSON")
    parser.add_argument("--source-ref", default="", help="Human-readable source label")
    parser.add_argument("--limit", type=int, default=0, help="Max packets (0 = all)")
    args = parser.parse_args(argv)

    pcap = Path(args.pcap)
    if not pcap.is_file():
        print(json.dumps({"ok": False, "error": f"pcap not found: {pcap}"}))
        return 2

    started = time.time()
    try:
        candidate = learn_from_pcap(str(pcap), limit=args.limit, source_ref=args.source_ref)
    except Exception as exc:  # noqa: BLE001 — report any scapy/parse failure to caller
        print(json.dumps({"ok": False, "error": f"{type(exc).__name__}: {exc}"}))
        return 1

    candidate["elapsed_sec"] = round(time.time() - started, 2)
    _atomic_write(Path(args.out), candidate)
    print(json.dumps({"ok": True, "out": args.out, "stats": candidate["stats"], "elapsed_sec": candidate["elapsed_sec"]}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
