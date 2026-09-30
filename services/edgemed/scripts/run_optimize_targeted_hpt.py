#!/usr/bin/env python3
"""Targeted HPT optimization: network XGB HPO + network FL + cohort thresholds + hybrid eval."""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from app.classifier import DEFAULT_XGB_BINARY, evaluate_classifier, load_classifier
from app.cohort_xgb_registry import load_cohort_thresholds
from app.data.columns import load_column_map
from app.fl_protocol_cohorts import group_site_ids_by_cohort

import run_three_site_fl_experiment as fl_lab
from scripts.run_protocol_cohort_fl_experiment import (
    _load_site_cohort_map,
    _metrics_for_cohort_models,
    _run_cohort_fl,
)


def _utc() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _evaluate_with_thresholds(
    cohort_models: dict[str, Any],
    site_cohort: dict[str, str],
    frames: dict[str, dict[str, pd.DataFrame]],
    thresholds: dict[str, float],
) -> dict[str, Any]:
    per_site: list[dict[str, Any]] = []
    f1s: list[float] = []
    for site_id, payload in frames.items():
        cohort = site_cohort[site_id]
        bundle = cohort_models[cohort]
        test = fl_lab._align(payload["test"], bundle.features)
        if test.empty:
            continue
        threshold = float(thresholds.get(cohort, 0.5))
        metrics = evaluate_classifier(bundle, test, decision_threshold=threshold)
        per_site.append({"site_id": site_id, "cohort": cohort, "threshold": threshold, **metrics})
        f1s.append(float(metrics["f1"]))
    return {
        "thresholds": thresholds,
        "macro_f1_mean_attack_f1": round(float(np.mean(f1s)) if f1s else 0.0, 6),
        "per_site": per_site,
        "pooled_fp": sum(int(row["confusion_matrix"]["fp"]) for row in per_site),
        "pooled_fn": sum(int(row["confusion_matrix"]["fn"]) for row in per_site),
    }


def _run_network_fl(
    *,
    output_dir: Path,
    network_xgb_params: dict[str, Any],
    seed: int,
    splits_dir: Path,
    dataset_root: Path,
) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    models_dir = output_dir / "models"
    models_dir.mkdir(parents=True, exist_ok=True)

    site_ids = fl_lab.discover_site_ids(splits_dir)
    site_cohort = _load_site_cohort_map(splits_dir, site_ids)
    cohort_groups = group_site_ids_by_cohort(site_ids, splits_dir=splits_dir)
    network_ids = cohort_groups["network"]

    mapping = load_column_map()
    frames = fl_lab.load_site_frames(
        splits_dir=splits_dir,
        dataset_root=dataset_root,
        mapping=mapping,
        max_train=2000,
        max_test=2000,
        max_benign=3000,
        seed=seed,
        site_ids=site_ids,
    )
    round0 = load_classifier(ROOT / "artifacts" / "classifiers" / "xgboost_binary.joblib")
    federation_base = fl_lab._uncalibrated_federation_base(round0)

    final_model, rounds_payload, summary = _run_cohort_fl(
        cohort="network",
        cohort_site_ids=network_ids,
        frames=frames,
        federation_base=federation_base,
        models_dir=models_dir,
        rounds=7,
        trees_per_site=12,
        client_weighting="sample_count",
        seed=seed,
        xgb_params=network_xgb_params,
        skip_control_plane=True,
        cp_artifacts_dir=None,
    )
    (output_dir / "cohorts" / "network-summary.json").parent.mkdir(parents=True, exist_ok=True)
    (output_dir / "cohorts" / "network-summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    return models_dir / "cohort-network-round-007.joblib"


def _hybrid_models(
    *,
    mqtt_wifi_dir: Path,
    network_model: Path,
    rounds: int = 7,
) -> dict[str, Any]:
    models: dict[str, Any] = {}
    for cohort in ("mqtt", "wifi"):
        path = mqtt_wifi_dir / "models" / f"cohort-{cohort}-round-{rounds:03d}.joblib"
        models[cohort] = load_classifier(path)
    models["network"] = load_classifier(network_model)
    return models


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset-root", type=Path, default=Path(r"D:\實習\資料集"))
    parser.add_argument("--splits-dir", type=Path, default=ROOT / "artifacts" / "fl-experiment-six" / "splits")
    parser.add_argument(
        "--base-experiment",
        type=Path,
        default=ROOT / "artifacts" / "fl-experiment-six-cohort-hpo-full",
    )
    parser.add_argument("--output-dir", type=Path, default=ROOT / "artifacts" / "fl-experiment-six-cohort-targeted-opt")
    parser.add_argument("--network-hpo-output", type=Path, default=ROOT / "artifacts" / "hpo-network-cohort-results.json")
    parser.add_argument("--skip-network-hpo", action="store_true")
    parser.add_argument("--skip-network-fl", action="store_true")
    parser.add_argument("--seed", type=int, default=20260818)
    args = parser.parse_args()

    if not args.skip_network_hpo and not args.network_hpo_output.is_file():
        print("==> Running network cohort XGB HPO", flush=True)
        subprocess.run(
            [sys.executable, str(ROOT / "scripts" / "run_hpo_network_cohort.py"), "--output", str(args.network_hpo_output)],
            check=True,
        )

    network_params = dict(DEFAULT_XGB_BINARY)
    if args.network_hpo_output.is_file():
        hpo = json.loads(args.network_hpo_output.read_text(encoding="utf-8"))
        network_params.update(hpo.get("best_params") or {})
        print(f"==> Network XGB best: {hpo.get('best_params')}", flush=True)

    network_model_path = args.output_dir / "models" / "cohort-network-round-007.joblib"
    if not args.skip_network_fl:
        print("==> Running network cohort FL (7x12 sample_count)", flush=True)
        network_model_path = _run_network_fl(
            output_dir=args.output_dir,
            network_xgb_params=network_params,
            seed=args.seed,
            splits_dir=args.splits_dir,
            dataset_root=args.dataset_root,
        )

    site_ids = fl_lab.discover_site_ids(args.splits_dir)
    site_cohort = _load_site_cohort_map(args.splits_dir, site_ids)
    mapping = load_column_map()
    frames = fl_lab.load_site_frames(
        splits_dir=args.splits_dir,
        dataset_root=args.dataset_root,
        mapping=mapping,
        max_train=2000,
        max_test=2000,
        max_benign=3000,
        seed=args.seed,
        site_ids=site_ids,
    )

    hybrid = _hybrid_models(mqtt_wifi_dir=args.base_experiment, network_model=network_model_path)
    thresholds = load_cohort_thresholds()

    baseline_full = json.loads((args.base_experiment / "summary.json").read_text(encoding="utf-8"))
    full_models = _hybrid_models(mqtt_wifi_dir=args.base_experiment, network_model=args.base_experiment / "models" / "cohort-network-round-007.joblib")

    eval_default = _metrics_for_cohort_models(full_models, site_cohort, frames)
    eval_threshold = _evaluate_with_thresholds(hybrid, site_cohort, frames, thresholds)
    eval_hybrid_default = _metrics_for_cohort_models(hybrid, site_cohort, frames)

    report = {
        "generated_at": _utc(),
        "base_experiment": str(args.base_experiment),
        "network_fl_output": str(args.output_dir),
        "network_xgb_params": network_params,
        "decision_thresholds": thresholds,
        "E2_attack_f1_mean": {
            "full_hpt_default_0.5": eval_default.get("macro_f1"),
            "full_hpt_plus_network_xgb_default_0.5": eval_hybrid_default.get("macro_f1"),
            "hybrid_with_cohort_thresholds": eval_threshold["macro_f1_mean_attack_f1"],
        },
        "pooled_errors": {
            "full_hpt_default": {
                "fp": sum(int(s["confusion_matrix"]["fp"]) for s in eval_default["per_site"].values()),
                "fn": sum(int(s["confusion_matrix"]["fn"]) for s in eval_default["per_site"].values()),
            },
            "hybrid_threshold": {"fp": eval_threshold["pooled_fp"], "fn": eval_threshold["pooled_fn"]},
        },
        "baseline_summary_E2": baseline_full.get("E2_cohort_aware_round5_macro_f1"),
        "network_hpo_best_test": json.loads(args.network_hpo_output.read_text(encoding="utf-8")).get("best_network_test")
        if args.network_hpo_output.is_file()
        else None,
    }

    out_json = ROOT / "artifacts" / "targeted-hpt-optimization-results.json"
    out_json.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report["E2_attack_f1_mean"], indent=2), flush=True)
    print(f"Wrote {out_json}", flush=True)

    # Publish hybrid: copy mqtt/wifi from base, network from optimized run
    classifiers = ROOT / "artifacts" / "classifiers"
    for cohort in ("mqtt", "wifi"):
        src = args.base_experiment / "models" / f"cohort-{cohort}-round-007.joblib"
        dst = classifiers / f"xgboost_binary_{cohort}.joblib"
        shutil.copy2(src, dst)
        print(f"Published {cohort} from Full HPT", flush=True)
    shutil.copy2(network_model_path, classifiers / "xgboost_binary_network.joblib")
    print(f"Published network from {network_model_path.name}", flush=True)

    subprocess.run(
        [
            sys.executable,
            str(ROOT / "scripts" / "publish_best_cohort_xgb.py"),
            "--experiment-dir",
            str(args.base_experiment),
        ],
        check=True,
    )
    # Re-copy network after publish (publish picks E2/E3 best from base experiment only)
    shutil.copy2(network_model_path, classifiers / "xgboost_binary_network.joblib")
    manifest_path = classifiers / "cohort_model_manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["decision_thresholds"] = thresholds
    manifest["targeted_optimization"] = {
        "network_model": str(network_model_path),
        "network_xgb_params": network_params,
        "report": str(out_json),
    }
    manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"Updated manifest with thresholds + network model", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
