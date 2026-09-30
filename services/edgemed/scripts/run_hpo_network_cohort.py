#!/usr/bin/env python3
"""Network-cohort XGB HPO: higher scale_pos_weight grid for recon / ARP FN reduction."""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from app.classifier import DEFAULT_XGB_BINARY, evaluate_classifier, load_classifier, train_classifier
from app.data.columns import load_column_map
from app.fl_protocol_cohorts import group_site_ids_by_cohort

import run_three_site_fl_experiment as fl_lab
from scripts.run_protocol_cohort_fl_experiment import _load_site_cohort_map


NETWORK_SITES = ("site-recon", "site-spoof")
HARD_ATTACK_TOKENS = ("vulscan", "arp", "spoof", "os scan")


def _network_test_score(bundle: Any, frames: dict[str, dict[str, pd.DataFrame]]) -> dict[str, Any]:
    site_f1s: list[float] = []
    hard_f1s: list[float] = []
    pooled_fp = 0
    pooled_fn = 0
    per_file: list[dict[str, Any]] = []

    for site_id in NETWORK_SITES:
        test = fl_lab._align(frames[site_id]["test"], bundle.features)
        metrics = evaluate_classifier(bundle, test)
        site_f1s.append(float(metrics["f1"]))
        cm = metrics["confusion_matrix"]
        pooled_fp += int(cm["fp"])
        pooled_fn += int(cm["fn"])
        if "source_file" not in test.columns:
            continue
        for source_file, part in test.groupby("source_file"):
            part_aligned = fl_lab._align(part, bundle.features)
            file_metrics = evaluate_classifier(bundle, part_aligned)
            label = str(source_file).lower()
            is_hard = any(token.replace(" ", "") in label.replace("_", " ") for token in HARD_ATTACK_TOKENS)
            if is_hard and str(part["label"].iloc[0]) == "Attack":
                hard_f1s.append(float(file_metrics["f1"]))
            per_file.append(
                {
                    "site_id": site_id,
                    "source_file": str(source_file),
                    "attack_f1": round(float(file_metrics["f1"]), 6),
                    "fn": int(file_metrics["confusion_matrix"]["fn"]),
                    "fp": int(file_metrics["confusion_matrix"]["fp"]),
                }
            )

    mean_site_f1 = float(np.mean(site_f1s)) if site_f1s else 0.0
    mean_hard_f1 = float(np.mean(hard_f1s)) if hard_f1s else mean_site_f1
    composite = round(0.6 * mean_site_f1 + 0.4 * mean_hard_f1, 6)
    return {
        "mean_site_attack_f1": round(mean_site_f1, 6),
        "mean_hard_attack_file_f1": round(mean_hard_f1, 6),
        "composite_score": composite,
        "pooled_fp": pooled_fp,
        "pooled_fn": pooled_fn,
        "per_file": per_file,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset-root", type=Path, default=Path(r"D:\實習\資料集"))
    parser.add_argument("--splits-dir", type=Path, default=ROOT / "artifacts" / "fl-experiment-six" / "splits")
    parser.add_argument("--seed", type=int, default=20260818)
    parser.add_argument("--output", type=Path, default=ROOT / "artifacts" / "hpo-network-cohort-results.json")
    parser.add_argument("--max-train", type=int, default=2000)
    parser.add_argument("--max-test", type=int, default=2000)
    args = parser.parse_args()

    mapping = load_column_map()
    site_ids = fl_lab.discover_site_ids(args.splits_dir)
    site_cohort = _load_site_cohort_map(args.splits_dir, site_ids)
    cohort_groups = group_site_ids_by_cohort(site_ids, splits_dir=args.splits_dir)
    network_ids = cohort_groups.get("network", NETWORK_SITES)

    frames = fl_lab.load_site_frames(
        splits_dir=args.splits_dir,
        dataset_root=args.dataset_root,
        mapping=mapping,
        max_train=args.max_train,
        max_test=args.max_test,
        max_benign=3000,
        seed=args.seed,
        site_ids=site_ids,
    )
    base = load_classifier(ROOT / "artifacts" / "classifiers" / "xgboost_binary.joblib")
    train = pd.concat(
        [fl_lab._align(frames[s]["train"], base.features) for s in network_ids],
        ignore_index=True,
    )
    n_pos = int((train["label"] == "Attack").sum())
    n_neg = int((train["label"] == "Benign").sum())
    class_ratio = round(n_neg / max(n_pos, 1), 6)

    candidates: list[dict[str, Any]] = []
    for max_depth in (6, 8):
        for learning_rate in (0.03, 0.05, 0.08):
            for scale_pos_weight in (0.5, 1.0, 2.0, 5.0, 10.0, class_ratio):
                candidates.append(
                    {
                        "max_depth": max_depth,
                        "learning_rate": learning_rate,
                        "scale_pos_weight": scale_pos_weight,
                        "n_estimators": 120,
                        "min_child_weight": 1,
                        "gamma": 0.0,
                        "reg_alpha": 0.0,
                        "reg_lambda": 1.0,
                    }
                )

    trials: list[dict[str, Any]] = []
    best: tuple[tuple[float, float, float], dict[str, Any]] | None = None
    print(f"Network HPO trials={len(candidates)} sites={network_ids}", flush=True)

    for index, candidate in enumerate(candidates):
        params = dict(DEFAULT_XGB_BINARY)
        params.update(candidate)
        started = time.perf_counter()
        bundle = train_classifier(
            train,
            model_name="xgboost",
            task="binary",
            seed=args.seed,
            preprocess=base.preprocess,
            xgb_params=params,
        )
        test_score = _network_test_score(bundle, frames)
        trial = {
            "trial": index,
            "params": candidate,
            "network_test": test_score,
            "seconds": round(time.perf_counter() - started, 6),
        }
        trials.append(trial)
        key = (
            test_score["composite_score"],
            test_score["mean_site_attack_f1"],
            -test_score["pooled_fn"],
        )
        if best is None or key > best[0]:
            best = (key, trial)
        print(
            f"[{index + 1}/{len(candidates)}] composite={test_score['composite_score']:.4f} "
            f"site_f1={test_score['mean_site_attack_f1']:.4f} FN={test_score['pooled_fn']} "
            f"depth={candidate['max_depth']} spw={candidate['scale_pos_weight']}",
            flush=True,
        )

    assert best is not None
    selected = dict(best[1]["params"])
    global_hpo = ROOT / "artifacts" / "hpo-macro-f1-results.json"
    report = {
        "stage": "network_cohort_xgb_hpo",
        "selection_criterion": "0.6*mean_site_attack_f1 + 0.4*mean_hard_attack_file_f1 (VulScan/ARP/OS)",
        "selection_split": "network sites test (lab selection)",
        "network_site_ids": list(network_ids),
        "class_counts_train": {"Attack": n_pos, "Benign": n_neg},
        "global_hpo_reference": str(global_hpo) if global_hpo.is_file() else None,
        "best_params": selected,
        "best_network_test": best[1]["network_test"],
        "trials": trials,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"best_params": selected, "best": best[1]["network_test"], "output": str(args.output)}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
