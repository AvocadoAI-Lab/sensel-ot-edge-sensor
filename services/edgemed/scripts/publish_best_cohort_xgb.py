"""Publish the highest-accuracy per-cohort XGBoost models for Edge deployment."""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from app.cohort_xgb_registry import (
    CLASSIFIERS_DIR,
    MANIFEST_PATH,
    THRESHOLDS_PATH,
    cohort_artifact_name,
    load_cohort_thresholds,
)
from app.fl_protocol_cohorts import DEVICE_TYPE_TO_FL_COHORT, FL_COHORT_LABELS

DEFAULT_EXPERIMENT = ROOT / "artifacts" / "fl-experiment-six-cohort-hpo-full"


def _utc() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def select_best_cohort_models(experiment_dir: Path) -> dict[str, dict[str, Any]]:
    summary = json.loads((experiment_dir / "summary.json").read_text(encoding="utf-8"))
    e2_scores = summary.get("cohort_final_macro_f1") or {}
    e3_scores = summary.get("E3_cohort_per_cohort_macro_f1") or {}
    rounds = int(summary.get("rounds") or 5)
    models_dir = experiment_dir / "models"
    if not models_dir.is_dir():
        raise FileNotFoundError(f"Missing models directory: {models_dir}")

    selections: dict[str, dict[str, Any]] = {}
    for cohort in sorted(set(e2_scores) | set(e3_scores)):
        e2_f1 = float(e2_scores.get(cohort) or 0.0)
        e3_f1 = float(e3_scores.get(cohort) or 0.0)
        e2_path = models_dir / f"cohort-{cohort}-round-{rounds:03d}.joblib"
        e3_path = models_dir / f"centralized-cohort-{cohort}.joblib"

        if e3_f1 >= e2_f1:
            selected_source = "E3_cohort"
            source_path = e3_path
            macro_f1 = e3_f1
        else:
            selected_source = "E2_cohort_fl"
            source_path = e2_path
            macro_f1 = e2_f1

        if not source_path.is_file():
            raise FileNotFoundError(f"Selected model missing for {cohort}: {source_path}")

        selections[cohort] = {
            "fl_protocol_group": cohort,
            "cohort_label": FL_COHORT_LABELS.get(cohort, cohort),
            "selected_source": selected_source,
            "macro_f1": round(macro_f1, 6),
            "alternatives": {
                "E2_cohort_fl": round(e2_f1, 6),
                "E3_cohort": round(e3_f1, 6),
            },
            "source_path": str(source_path),
            "artifact": cohort_artifact_name(cohort),
        }
    return selections


def publish(
    *,
    experiment_dir: Path,
    output_dir: Path,
    write_manifest: bool = True,
) -> dict[str, Any]:
    selections = select_best_cohort_models(experiment_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    published: dict[str, Any] = {}
    for cohort, entry in selections.items():
        dest = output_dir / entry["artifact"]
        shutil.copy2(entry["source_path"], dest)
        entry["artifact_path"] = str(dest)
        entry["artifact_bytes"] = dest.stat().st_size
        entry["artifact_sha256"] = _sha256(dest)
        published[cohort] = entry
        print(
            f"  [{cohort}] {entry['selected_source']} macro_f1={entry['macro_f1']} -> {dest.name}",
            flush=True,
        )

    manifest = {
        "schema": "sensel.cohort_xgb_manifest.v1",
        "published_at": _utc(),
        "source_experiment": str(experiment_dir),
        "selection_policy": "per_cohort_max_macro_f1_between_E2_cohort_fl_final_and_E3_cohort",
        "metric": "macro_f1_within_cohort",
        "device_type_map": dict(DEVICE_TYPE_TO_FL_COHORT),
        "decision_thresholds": load_cohort_thresholds(),
        "thresholds_path": str(THRESHOLDS_PATH),
        "cohorts": published,
    }
    if write_manifest:
        MANIFEST_PATH.write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        print(f"Wrote {MANIFEST_PATH}", flush=True)
    return manifest


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--experiment-dir",
        type=Path,
        default=DEFAULT_EXPERIMENT,
        help="Protocol-cohort FL experiment with E2 + E3-cohort artifacts",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=CLASSIFIERS_DIR,
        help="EdgeMed classifier deployment directory",
    )
    args = parser.parse_args()

    print(f"==> Selecting best per-cohort XGB from {args.experiment_dir}", flush=True)
    manifest = publish(experiment_dir=args.experiment_dir, output_dir=args.output_dir)
    print(json.dumps(
        {
            cohort: {
                "selected_source": entry["selected_source"],
                "macro_f1": entry["macro_f1"],
                "artifact": entry["artifact"],
            }
            for cohort, entry in manifest["cohorts"].items()
        },
        indent=2,
    ))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
