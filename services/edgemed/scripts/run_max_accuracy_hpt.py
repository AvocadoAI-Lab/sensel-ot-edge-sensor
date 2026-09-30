#!/usr/bin/env python3
"""Run gap-driven max-accuracy HPT: per-cohort XGB + per-cohort FL, publish, report."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

ARTIFACTS = ROOT / "artifacts"
XGB_BY_COHORT = ARTIFACTS / "hpo-xgb-by-cohort.json"
FL_BY_COHORT = ARTIFACTS / "hpo-fl-by-cohort.json"
OUTPUT_SIX = ARTIFACTS / "fl-experiment-six-cohort-max-accuracy"
REPORT = ARTIFACTS / "max-accuracy-hpt-results.json"


def _utc() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _ensure_network_hpo() -> None:
    network_hpo = ARTIFACTS / "hpo-network-cohort-results.json"
    if network_hpo.is_file():
        return
    subprocess.run([sys.executable, str(ROOT / "scripts" / "run_hpo_network_cohort.py")], check=True)


def _run_six_cohort_max(args: argparse.Namespace) -> dict[str, Any]:
    _ensure_network_hpo()
    cmd = [
        sys.executable,
        str(ROOT / "scripts" / "run_protocol_cohort_fl_experiment.py"),
        "--splits-dir",
        str(args.splits_dir),
        "--dataset-root",
        str(args.dataset_root),
        "--output-dir",
        str(OUTPUT_SIX),
        "--experiment-id",
        "fl-six-cohort-max-accuracy",
        "--seed",
        str(args.seed),
        "--xgb-params-by-cohort",
        str(XGB_BY_COHORT),
        "--fl-params-by-cohort",
        str(FL_BY_COHORT),
        "--skip-single-global",
    ]
    print("==> Six-site max-accuracy cohort FL", flush=True)
    subprocess.run(cmd, check=True)
    summary = _load_json(OUTPUT_SIX / "summary.json")
    return summary


def _publish_e2_fl_models() -> None:
    """Deploy E2 FL final models (not E3 oracle) for federated Edge scoring."""
    import shutil

    from app.cohort_xgb_registry import CLASSIFIERS_DIR, MANIFEST_PATH, cohort_artifact_name, load_cohort_thresholds

    fl_cfg = _load_json(FL_BY_COHORT)["cohorts"]
    manifest = _load_json(MANIFEST_PATH) if MANIFEST_PATH.is_file() else {}
    cohorts_meta: dict[str, Any] = {}
    summary = _load_json(OUTPUT_SIX / "summary.json")
    e2_cohort = summary.get("cohort_final_macro_f1") or {}

    for cohort, cfg in fl_cfg.items():
        rounds = int(cfg["rounds"])
        src = OUTPUT_SIX / "models" / f"cohort-{cohort}-round-{rounds:03d}.joblib"
        dst = CLASSIFIERS_DIR / cohort_artifact_name(cohort)
        shutil.copy2(src, dst)
        cohorts_meta[cohort] = {
            "fl_protocol_group": cohort,
            "selected_source": "E2_cohort_fl",
            "macro_f1": e2_cohort.get(cohort),
            "artifact": cohort_artifact_name(cohort),
            "fl_params": cfg,
            "source_path": str(src),
        }
        print(f"  [deploy E2] {cohort} round-{rounds:03d} macro_f1={e2_cohort.get(cohort)}", flush=True)

    manifest.update(
        {
            "schema": "sensel.cohort_xgb_manifest.v1",
            "published_at": _utc(),
            "source_experiment": str(OUTPUT_SIX),
            "selection_policy": "E2_cohort_fl_per_cohort_max_accuracy_hpt",
            "metric": "macro_f1_within_cohort",
            "decision_thresholds": load_cohort_thresholds(),
            "xgb_by_cohort": _load_json(XGB_BY_COHORT),
            "fl_by_cohort": _load_json(FL_BY_COHORT),
            "cohorts": cohorts_meta,
        }
    )
    MANIFEST_PATH.write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"Wrote {MANIFEST_PATH}", flush=True)


def _optimal_three_site_configs() -> dict[str, Any]:
    """Three-site: baseline XGB wins; document best FL from prior grid."""
    three_cohort = _load_json(ARTIFACTS / "fl-experiment-three-cohort" / "summary.json")
    three_global = _load_json(ARTIFACTS / "fl-experiment-three" / "summary.json")
    hpo_cohort = _load_json(ARTIFACTS / "hpo-fl-params-three-cohort.json")
    hpo_global = _load_json(ARTIFACTS / "hpo-fl-params-three-global.json")
    return {
        "three_site_global": {
            "recommendation": "baseline_default_xgb",
            "E2_macro_f1": three_global.get("E2_round5_macro_f1"),
            "fl_params": hpo_global.get("best_fl_params"),
            "note": "Global XGB HPO hurts; keep baseline 5x8 equal",
        },
        "three_site_cohort": {
            "recommendation": "baseline_default_xgb",
            "E2_macro_f1": three_cohort.get("E2_cohort_aware_round5_macro_f1"),
            "best_fl_if_using_hpo_xgb": hpo_cohort.get("best_fl_params"),
            "best_fl_e2_with_hpo_xgb": hpo_cohort.get("best_metrics", {}).get("E2_final_macro_f1"),
            "note": "Baseline 0.995 still beats any HPT combo",
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset-root", type=Path, default=Path(r"D:\實習\資料集"))
    parser.add_argument("--splits-dir", type=Path, default=ARTIFACTS / "fl-experiment-six" / "splits")
    parser.add_argument("--seed", type=int, default=20260818)
    parser.add_argument("--skip-run", action="store_true")
    parser.add_argument("--skip-publish", action="store_true")
    args = parser.parse_args()

    prior = _load_json(ARTIFACTS / "targeted-hpt-optimization-results.json") if (
        ARTIFACTS / "targeted-hpt-optimization-results.json"
    ).is_file() else {}

    six_summary: dict[str, Any] = {}
    if not args.skip_run:
        six_summary = _run_six_cohort_max(args)
        if not args.skip_publish:
            _publish_e2_fl_models()
    elif OUTPUT_SIX.joinpath("summary.json").is_file():
        six_summary = _load_json(OUTPUT_SIX / "summary.json")

    full_hpt = _load_json(ARTIFACTS / "fl-experiment-six-cohort-hpo-full" / "summary.json")
    baseline = _load_json(ARTIFACTS / "fl-experiment-six-cohort" / "summary.json")

    report = {
        "generated_at": _utc(),
        "six_site_cohort": {
            "baseline_E2": baseline.get("E2_cohort_aware_round5_macro_f1"),
            "full_hpt_E2": full_hpt.get("E2_cohort_aware_round5_macro_f1"),
            "prior_hybrid_E2": prior.get("E2_attack_f1_mean", {}).get("full_hpt_plus_network_xgb_default_0.5"),
            "max_accuracy_E2": six_summary.get("E2_cohort_aware_round5_macro_f1"),
            "max_accuracy_cohort_final": six_summary.get("cohort_final_macro_f1"),
            "xgb_by_cohort": _load_json(XGB_BY_COHORT),
            "fl_by_cohort": _load_json(FL_BY_COHORT),
            "experiment_dir": str(OUTPUT_SIX),
        },
        "three_site": _optimal_three_site_configs(),
        "deployment": {
            "six_site": "fl-experiment-six-cohort-max-accuracy + cohort_thresholds all 0.5",
            "three_site_cohort": "fl-experiment-three-cohort baseline",
            "three_site_global": "fl-experiment-three baseline",
        },
    }
    REPORT.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report["six_site_cohort"], indent=2), flush=True)
    print(f"Wrote {REPORT}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
