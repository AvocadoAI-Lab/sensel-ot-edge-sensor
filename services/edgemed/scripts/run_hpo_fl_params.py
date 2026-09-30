#!/usr/bin/env python3
"""Stage-2 FL hyperparameter search (rounds / trees / client weighting).

Supports six-site cohort (default), three-site cohort, and three-site single-global.
Uses Stage-1 XGB best params; selects by E2 final cross-site macro-F1.
"""

from __future__ import annotations

import argparse
import json
import statistics
import subprocess
import sys
import tempfile
import time
from copy import deepcopy
from pathlib import Path
from typing import Any, Literal

import numpy as np

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from app.classifier import DEFAULT_XGB_BINARY, load_classifier, save_classifier
from app.data.columns import load_column_map
from app.fl_protocol_cohorts import group_site_ids_by_cohort

import run_protocol_cohort_fl_experiment as cohort_lab
import run_three_site_fl_experiment as fl_lab

Mode = Literal["cohort", "single-global"]


def _run_e2_cohort_only(
    *,
    frames: dict[str, dict],
    site_cohort: dict[str, str],
    cohort_groups: dict[str, tuple[str, ...]],
    federation_base,
    xgb_params: dict[str, Any],
    rounds: int,
    trees_per_site: int,
    client_weighting: str,
    seed: int,
    models_dir: Path,
) -> dict[str, Any]:
    cohort_final_models = {}
    per_cohort_round_f1: dict[str, list[float]] = {}

    for cohort in sorted(cohort_groups):
        final_model, rounds_payload, summary = cohort_lab._run_cohort_fl(
            cohort=cohort,
            cohort_site_ids=cohort_groups[cohort],
            frames=frames,
            federation_base=deepcopy(federation_base),
            models_dir=models_dir,
            rounds=rounds,
            trees_per_site=trees_per_site,
            client_weighting=client_weighting,
            seed=seed,
            xgb_params=xgb_params,
            skip_control_plane=True,
        )
        cohort_final_models[cohort] = final_model
        per_cohort_round_f1[cohort] = [
            float(item["metrics"]["macro_f1"]) for item in rounds_payload
        ]

    combined = cohort_lab._metrics_for_cohort_models(
        cohort_final_models, site_cohort, frames
    )
    tail = max(1, min(3, rounds))
    round_means: list[float] = []
    for r_idx in range(rounds):
        vals = [per_cohort_round_f1[cohort][r_idx] for cohort in sorted(cohort_groups)]
        round_means.append(float(np.mean(vals)))

    return {
        "E2_final_macro_f1": float(combined.get("macro_f1") or 0.0),
        "E2_tail_mean_macro_f1": round(float(np.mean(round_means[-tail:])), 6),
        "per_cohort_final_macro_f1": {
            cohort: per_cohort_round_f1[cohort][-1] for cohort in sorted(cohort_groups)
        },
        "round_macro_f1_means": [round(v, 6) for v in round_means],
    }


def _run_e2_single_global_only(
    *,
    site_ids: tuple[str, ...],
    frames: dict[str, dict],
    federation_base,
    xgb_params: dict[str, Any],
    rounds: int,
    trees_per_site: int,
    client_weighting: str,
    seed: int,
    models_dir: Path,
) -> dict[str, Any]:
    current = deepcopy(federation_base)
    round_f1s: list[float] = []

    for round_no in range(1, rounds + 1):
        local_updates = {}
        round_train_sizes = {
            site_id: int(len(fl_lab._align(payload["train"], current.features)))
            for site_id, payload in frames.items()
        }
        median_train = statistics.median(round_train_sizes.values()) if round_train_sizes else 1.0

        for site_index, site_id in enumerate(site_ids):
            train = fl_lab._align(frames[site_id]["train"], current.features)
            sample_count = int(len(train))
            if client_weighting == "sample_count":
                ratio = sample_count / max(median_train, 1.0)
                extra_trees = max(1, min(round(trees_per_site * ratio), trees_per_site * 2))
            else:
                extra_trees = trees_per_site
            local_updates[site_id] = fl_lab.continue_binary(
                deepcopy(current),
                train,
                extra_trees=extra_trees,
                seed=seed + round_no * 10 + site_index,
                xgb_params=xgb_params,
            )

        current, _ = fl_lab.aggregate_independent_tree_updates(
            current, local_updates, site_order=site_ids
        )
        model_path = models_dir / f"fl-round-{round_no:03d}.joblib"
        save_classifier(current, model_path)
        metrics = fl_lab._metrics_for(current, frames)
        round_f1s.append(float(metrics.get("macro_f1") or 0.0))

    tail = max(1, min(3, rounds))
    return {
        "E2_final_macro_f1": round_f1s[-1] if round_f1s else 0.0,
        "E2_tail_mean_macro_f1": round(float(np.mean(round_f1s[-tail:])), 6),
        "per_cohort_final_macro_f1": None,
        "round_macro_f1_means": [round(v, 6) for v in round_f1s],
    }


def _run_full_experiment(
    *,
    mode: Mode,
    splits_dir: Path,
    output_dir: Path,
    experiment_id: str,
    xgb_params_path: Path,
    best_cfg: dict[str, Any],
) -> None:
    if mode == "cohort":
        cmd = [
            sys.executable,
            str(ROOT / "scripts" / "run_protocol_cohort_fl_experiment.py"),
            "--splits-dir",
            str(splits_dir),
            "--output-dir",
            str(output_dir),
            "--experiment-id",
            experiment_id,
            "--skip-single-global",
            "--xgb-params",
            str(xgb_params_path),
            "--rounds",
            str(best_cfg["rounds"]),
            "--trees-per-site",
            str(best_cfg["trees_per_site"]),
            "--client-weighting",
            best_cfg["client_weighting"],
        ]
    else:
        cmd = [
            sys.executable,
            str(ROOT / "scripts" / "run_three_site_fl_experiment.py"),
            "--splits-dir",
            str(splits_dir),
            "--output-dir",
            str(output_dir),
            "--experiment-id",
            experiment_id,
            "--skip-control-plane",
            "--xgb-params",
            str(xgb_params_path),
            "--rounds",
            str(best_cfg["rounds"]),
            "--trees-per-site",
            str(best_cfg["trees_per_site"]),
            "--client-weighting",
            best_cfg["client_weighting"],
        ]
    subprocess.run(cmd, cwd=str(ROOT), check=True)


def main() -> int:
    parser = argparse.ArgumentParser(description="FL hyperparameter search")
    parser.add_argument("--dataset-root", type=Path, default=Path(r"D:\實習\資料集"))
    parser.add_argument(
        "--splits-dir",
        type=Path,
        default=ROOT / "artifacts" / "fl-experiment-six" / "splits",
    )
    parser.add_argument(
        "--mode",
        choices=("cohort", "single-global"),
        default="cohort",
    )
    parser.add_argument(
        "--layout-label",
        type=str,
        default="",
        help="Human-readable layout label for the report JSON",
    )
    parser.add_argument(
        "--xgb-params",
        type=Path,
        default=ROOT / "artifacts" / "hpo-macro-f1-results.json",
    )
    parser.add_argument("--seed", type=int, default=20260818)
    parser.add_argument("--output", type=Path, default=ROOT / "artifacts" / "hpo-fl-params-results.json")
    parser.add_argument("--final-output-dir", type=Path, default=None)
    parser.add_argument("--experiment-id", type=str, default="")
    parser.add_argument("--skip-full-run", action="store_true")
    args = parser.parse_args()

    mode: Mode = args.mode
    site_ids = fl_lab.discover_site_ids(args.splits_dir)
    layout_label = args.layout_label or f"{len(site_ids)}-site-{mode}"
    if args.final_output_dir is None:
        suffix = "cohort-hpo-full" if mode == "cohort" else "hpo-full"
        args.final_output_dir = args.splits_dir.parent.parent / f"fl-experiment-{len(site_ids)}-{suffix}"
        if "three" in str(args.splits_dir):
            if mode == "cohort":
                args.final_output_dir = ROOT / "artifacts" / "fl-experiment-three-cohort-hpo-full"
            else:
                args.final_output_dir = ROOT / "artifacts" / "fl-experiment-three-hpo-full"

    xgb_params = dict(DEFAULT_XGB_BINARY)
    if args.xgb_params.is_file():
        loaded = json.loads(args.xgb_params.read_text(encoding="utf-8"))
        xgb_params.update(loaded.get("best_params") or loaded)

    mapping = load_column_map()
    print(f"==> Loading frames ({len(site_ids)} sites, mode={mode})", flush=True)
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
    round0 = load_classifier(ROOT / "artifacts" / "classifiers" / "xgboost_binary.joblib")
    federation_base = fl_lab._uncalibrated_federation_base(round0)

    site_cohort: dict[str, str] = {}
    cohort_groups: dict[str, tuple[str, ...]] = {}
    if mode == "cohort":
        site_cohort = cohort_lab._load_site_cohort_map(args.splits_dir, site_ids)
        cohort_groups = group_site_ids_by_cohort(site_ids, splits_dir=args.splits_dir)

    rounds_grid = (3, 5, 7)
    trees_grid = (4, 8, 12)
    weighting_grid = ("equal_tree_count", "sample_count")
    candidates = [
        {"rounds": r, "trees_per_site": t, "client_weighting": w}
        for r in rounds_grid
        for t in trees_grid
        for w in weighting_grid
    ]

    trials: list[dict[str, Any]] = []
    best: tuple[tuple[float, float], dict[str, Any]] | None = None
    total = len(candidates)
    print(f"FL HPO trials={total} layout={layout_label} selection=E2_final_macro_f1", flush=True)

    for index, cfg in enumerate(candidates):
        started = time.perf_counter()
        with tempfile.TemporaryDirectory(prefix="fl-hpo-") as tmp:
            models_dir = Path(tmp) / "models"
            models_dir.mkdir()
            if mode == "cohort":
                metrics = _run_e2_cohort_only(
                    frames=frames,
                    site_cohort=site_cohort,
                    cohort_groups=cohort_groups,
                    federation_base=federation_base,
                    xgb_params=xgb_params,
                    rounds=cfg["rounds"],
                    trees_per_site=cfg["trees_per_site"],
                    client_weighting=cfg["client_weighting"],
                    seed=args.seed,
                    models_dir=models_dir,
                )
            else:
                metrics = _run_e2_single_global_only(
                    site_ids=site_ids,
                    frames=frames,
                    federation_base=federation_base,
                    xgb_params=xgb_params,
                    rounds=cfg["rounds"],
                    trees_per_site=cfg["trees_per_site"],
                    client_weighting=cfg["client_weighting"],
                    seed=args.seed,
                    models_dir=models_dir,
                )
        trial = {"trial": index, "fl_params": cfg, "seconds": round(time.perf_counter() - started, 3), **metrics}
        trials.append(trial)
        score = (float(metrics["E2_final_macro_f1"]), float(metrics["E2_tail_mean_macro_f1"]))
        if best is None or score > best[0]:
            best = (score, trial)
        print(
            f"[{index + 1}/{total}] E2={metrics['E2_final_macro_f1']:.4f} "
            f"rounds={cfg['rounds']} trees={cfg['trees_per_site']} weight={cfg['client_weighting']}",
            flush=True,
        )

    assert best is not None
    best_cfg = best[1]["fl_params"]
    baseline_cfg = {"rounds": 5, "trees_per_site": 8, "client_weighting": "equal_tree_count"}
    baseline_trial = next((t for t in trials if t["fl_params"] == baseline_cfg), None)

    report = {
        "stage": "fl_hyperparameter_search",
        "mode": mode,
        "selection_criterion": "E2_final_macro_f1_then_tail3_mean",
        "layout": layout_label,
        "splits_dir": str(args.splits_dir),
        "seed": args.seed,
        "xgb_params_source": str(args.xgb_params),
        "xgb_params": xgb_params,
        "best_fl_params": best_cfg,
        "best_metrics": {
            "E2_final_macro_f1": best[1]["E2_final_macro_f1"],
            "E2_tail_mean_macro_f1": best[1]["E2_tail_mean_macro_f1"],
            "per_cohort_final_macro_f1": best[1].get("per_cohort_final_macro_f1"),
            "round_macro_f1_means": best[1]["round_macro_f1_means"],
        },
        "baseline_fl_params": baseline_cfg,
        "baseline_metrics": (
            {
                "E2_final_macro_f1": baseline_trial["E2_final_macro_f1"],
                "per_cohort_final_macro_f1": baseline_trial.get("per_cohort_final_macro_f1"),
            }
            if baseline_trial
            else None
        ),
        "trials": trials,
    }

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    experiment_id = args.experiment_id or f"fl-{layout_label}-hpo-full"
    if not args.skip_full_run:
        print("==> Running full FL experiment with best FL params", flush=True)
        _run_full_experiment(
            mode=mode,
            splits_dir=args.splits_dir,
            output_dir=args.final_output_dir,
            experiment_id=experiment_id,
            xgb_params_path=args.xgb_params,
            best_cfg=best_cfg,
        )

    print(
        json.dumps(
            {
                "mode": mode,
                "layout": layout_label,
                "best_fl_params": best_cfg,
                "E2_final_macro_f1": best[1]["E2_final_macro_f1"],
                "baseline_E2": baseline_trial["E2_final_macro_f1"] if baseline_trial else None,
                "output": str(args.output),
                "full_run": str(args.final_output_dir),
            },
            indent=2,
        ),
        flush=True,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
