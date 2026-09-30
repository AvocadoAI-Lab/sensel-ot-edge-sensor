"""Enrich CIC baseline templates with profiling CSV statistics when available."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from app.baseline_templates import TEMPLATES_DIR, list_templates, template_path_for
from app.data.columns import apply_column_mapping, load_column_map

PROFILING_SEARCH_NAMES = ["profiling", "Profiling", "PROFILING"]
STAT_COLUMNS = ["rate", "duration", "syn_count", "ack_count", "header_length"]


def discover_profiling_dirs(dataset_root: Path) -> list[Path]:
    root = dataset_root.resolve()
    found: list[Path] = []
    explicit = [
        root / "WiFi_and_MQTT" / "profiling" / "CSV",
        root / "WiFi_and_MQTT" / "profiling",
        root / "WiFI_and_MQTT" / "profiling" / "CSV",
        root / "WiFI_and_MQTT" / "profiling",
        root / "WiFI_and_MQTTprofilingCSV",
        root / "WiFi_and_MQTTprofilingCSV",
    ]
    for path in explicit:
        if path.is_dir() and any(path.glob("*.csv")):
            found.append(path)
    if found:
        return found
    for path in root.rglob("*"):
        if not path.is_dir():
            continue
        if path.name in PROFILING_SEARCH_NAMES and any(path.glob("*.csv")):
            found.append(path)
        elif path.name == "CSV" and path.parent.name in PROFILING_SEARCH_NAMES and any(path.glob("*.csv")):
            found.append(path)
    return found


def _keywords(reference_device: str) -> list[str]:
    tokens = re.split(r"[/\s\-_]+", reference_device.lower())
    stop = {"camera", "monitor", "sensor", "button", "mini", "the", "and"}
    out = [t for t in tokens if t and t not in stop]
    if "blink" in reference_device.lower():
        out.append("blink")
    if "pager" in reference_device.lower() or "sos" in reference_device.lower():
        out.extend(["sos", "pager", "singcall"])
    if "withings" in reference_device.lower() or "bpm" in reference_device.lower():
        out.extend(["withings", "bpm", "blood"])
    return sorted(set(out))


def find_profiling_csv(
    profiling_dirs: list[Path],
    reference_device: str,
    *,
    csv_hint: str = "",
) -> Path | None:
    if csv_hint.strip():
        for directory in profiling_dirs:
            candidate = directory / csv_hint.strip()
            if candidate.is_file():
                return candidate
    keys = _keywords(reference_device)
    best: tuple[int, Path] | None = None
    for directory in profiling_dirs:
        for csv_path in directory.glob("*.csv"):
            name = csv_path.name.lower()
            score = sum(1 for key in keys if key in name)
            if score <= 0:
                continue
            if best is None or score > best[0]:
                best = (score, csv_path)
    return best[1] if best else None


def find_benign_fallback_csv(dataset_root: Path) -> Path | None:
    root = dataset_root.resolve()
    candidates = [
        root / "WiFI_and_MQTTattacksCSVtest" / "Benign_test.pcap.csv",
        root / "WiFI_and_MQTTattacksCSVtrain" / "Benign_train.pcap.csv",
        root / "WiFi_and_MQTT" / "attacks" / "CSV" / "test" / "Benign_test.pcap.csv",
    ]
    for path in candidates:
        if path.is_file():
            return path
    return None


def compute_stats(csv_path: Path) -> dict[str, Any]:
    mapping = apply_column_mapping(list(pd.read_csv(csv_path, nrows=0).columns), load_column_map())
    frame = pd.read_csv(csv_path)
    frame = frame.rename(columns=mapping)
    stats: dict[str, Any] = {"source_csv": str(csv_path), "rows": int(len(frame))}
    for column in STAT_COLUMNS:
        if column not in frame.columns:
            continue
        series = pd.to_numeric(frame[column], errors="coerce").dropna()
        if series.empty:
            continue
        stats[column] = {
            "p50": float(np.percentile(series, 50)),
            "p95": float(np.percentile(series, 95)),
            "max": float(series.max()),
        }
    return stats


def enrich_template(template: dict[str, Any], stats: dict[str, Any]) -> dict[str, Any]:
    out = dict(template)
    observed = dict(out.get("observed") or {})
    thresholds = dict(observed.get("thresholds") or {})
    rate = stats.get("rate") if isinstance(stats.get("rate"), dict) else {}
    if rate:
        thresholds["rate_p50_hint"] = rate.get("p50")
        thresholds["rate_p95_hint"] = rate.get("p95")
    duration = stats.get("duration") if isinstance(stats.get("duration"), dict) else {}
    if duration:
        thresholds["duration_p50_hint"] = duration.get("p50")
        thresholds["duration_p95_hint"] = duration.get("p95")
    observed["thresholds"] = thresholds
    observed["cic_profiling_stats"] = stats
    out["observed"] = observed
    out["stats_source"] = "cic_profiling"
    return out


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--dataset-root",
        type=Path,
        default=Path(r"D:\實習\資料集"),
        help="CICIoMT dataset root (expects WiFi_and_MQTT/profiling when present)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print planned updates without writing template files",
    )
    args = parser.parse_args()

    profiling_dirs = discover_profiling_dirs(args.dataset_root)
    if not profiling_dirs:
        print(f"No profiling CSV directory found under {args.dataset_root}; templates unchanged.")
        return 0

    updated = 0
    for entry in list_templates():
        profile_id = str(entry.get("profile_id") or "")
        reference = str(entry.get("cic_reference_device") or "")
        csv_hint = str(entry.get("profiling_csv_hint") or "")
        csv_path = find_profiling_csv(profiling_dirs, reference, csv_hint=csv_hint)
        template_path = template_path_for(entry)
        template = json.loads(template_path.read_text(encoding="utf-8"))
        stats_source = "cic_profiling"
        if csv_path is None and profile_id == "cic-template-bp-monitor-v1":
            csv_path = find_benign_fallback_csv(args.dataset_root)
            stats_source = "cic_benign_fallback"
        if csv_path is None:
            print(f"[skip] {profile_id}: no profiling CSV match for {reference!r}")
            continue
        stats = compute_stats(csv_path)
        enriched = enrich_template(template, stats)
        enriched["stats_source"] = stats_source
        print(f"[ok] {profile_id}: {csv_path.name} rows={stats.get('rows')}")
        if not args.dry_run:
            template_path.write_text(
                json.dumps(enriched, ensure_ascii=False, indent=2) + "\n",
                encoding="utf-8",
            )
            updated += 1

    if args.dry_run:
        print("Dry run complete; no files written.")
    else:
        print(f"Updated {updated} template file(s).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
