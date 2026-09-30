"""Run protocol-cohort federated XGBoost (six virtual sites, multiple global models).

Each site remains an independent FL client, but tree aggregation happens only
within its ``fl_protocol_group`` (wifi / mqtt / network / future cohorts).
At inference time each site uses the global model from its cohort.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import statistics
import sys
import time
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from app.classifier import (
    DEFAULT_XGB_BINARY,
    ClassifierBundle,
    evaluate_classifier,
    load_classifier,
    save_classifier,
    train_classifier,
)
from app.data.columns import load_column_map
from app.fl_protocol_cohorts import (
    FL_COHORT_LABELS,
    cohort_index,
    group_site_ids_by_cohort,
    resolve_fl_protocol_group,
)

import run_three_site_fl_experiment as fl_lab
from scripts.fl_control_plane import default_cp_artifacts_dir, publish_global_model, record_round


def _utc() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def _load_site_cohort_map(splits_dir: Path, site_ids: tuple[str, ...]) -> dict[str, str]:
    mapping: dict[str, str] = {}
    for site_id in site_ids:
        spec = json.loads((splits_dir / f"{site_id}.json").read_text(encoding="utf-8"))
        mapping[site_id] = resolve_fl_protocol_group(spec)
    return mapping


def _metrics_for_cohort_models(
    cohort_models: dict[str, ClassifierBundle],
    site_cohort: dict[str, str],
    frames: dict[str, dict[str, pd.DataFrame]],
) -> dict[str, Any]:
    per_site: dict[str, Any] = {}
    f1s: list[float] = []
    accs: list[float] = []
    balanced_accs: list[float] = []
    for site_id, payload in frames.items():
        cohort = site_cohort[site_id]
        bundle = cohort_models[cohort]
        test = fl_lab._align(payload["test"], bundle.features)
        if test.empty:
            per_site[site_id] = {"error": "empty_test", "fl_protocol_group": cohort}
            continue
        metrics = evaluate_classifier(bundle, test)
        attack = test[test["label"] == "Attack"]
        benign = test[test["label"] == "Benign"]
        extra: dict[str, Any] = {"fl_protocol_group": cohort, "model_cohort": cohort}
        if not attack.empty:
            extra["attack"] = evaluate_classifier(bundle, attack)
        if not benign.empty:
            extra["benign"] = evaluate_classifier(bundle, benign)
            extra["benign_fp_rate"] = round(1.0 - extra["benign"]["per_class"]["Benign"]["recall"], 6)
        per_site[site_id] = {**metrics, **extra, "device_type": payload["device_type"]}
        f1s.append(float(metrics.get("f1") or 0.0))
        accs.append(float(metrics.get("accuracy") or 0.0))
        if metrics.get("balanced_accuracy") is not None:
            balanced_accs.append(float(metrics["balanced_accuracy"]))

    holdout_frames: list[pd.DataFrame] = []
    for site_id, payload in frames.items():
        cohort = site_cohort[site_id]
        bundle = cohort_models[cohort]
        holdout_frames.append(fl_lab._align(payload["test"], bundle.features))
    holdout = pd.concat(holdout_frames, ignore_index=True) if holdout_frames else pd.DataFrame()

    inference: dict[str, Any] = {}
    if not holdout.empty:
        started = time.perf_counter()
        for site_id, payload in frames.items():
            cohort = site_cohort[site_id]
            bundle = cohort_models[cohort]
            part = fl_lab._align(payload["test"], bundle.features)
            if not part.empty:
                bundle.predict_proba(part)
        elapsed = time.perf_counter() - started
        inference = {
            "rows": int(len(holdout)),
            "seconds": round(elapsed, 6),
            "milliseconds_per_row": round(elapsed * 1000.0 / len(holdout), 6),
            "rows_per_second": round(len(holdout) / elapsed, 3) if elapsed else None,
        }

    reference_bundle = next(iter(cohort_models.values()))
    return {
        "per_site": per_site,
        "macro_f1": round(float(np.mean(f1s)) if f1s else 0.0, 6),
        "metric_definition": (
            "macro_f1 is the unweighted mean of per-site Attack-class F1; "
            "each site is scored with its cohort global model"
        ),
        "macro_accuracy": round(float(np.mean(accs)) if accs else 0.0, 6),
        "macro_balanced_accuracy": round(
            float(np.mean(balanced_accs)) if balanced_accs else 0.0, 6
        ),
        "global_holdout": (
            evaluate_classifier(reference_bundle, holdout, include_curves=False)
            if not holdout.empty
            else {}
        ),
        "inference_benchmark": inference,
        "note": "global_holdout uses the first cohort model for a rough combined view only",
    }


def _run_cohort_fl(
    *,
    cohort: str,
    cohort_site_ids: tuple[str, ...],
    frames: dict[str, dict[str, pd.DataFrame]],
    federation_base: ClassifierBundle,
    models_dir: Path,
    rounds: int,
    trees_per_site: int,
    client_weighting: str,
    seed: int,
    xgb_params: dict[str, Any],
    skip_control_plane: bool,
    cp_artifacts_dir: Path | None,
) -> tuple[ClassifierBundle, list[dict[str, Any]], dict[str, Any]]:
    current = deepcopy(federation_base)
    round_metrics: list[dict[str, Any]] = []
    round0_global = deepcopy(federation_base)
    previous_global = deepcopy(federation_base)
    cohort_frames = {site_id: frames[site_id] for site_id in cohort_site_ids}

    for round_no in range(1, rounds + 1):
        round_started = time.perf_counter()
        sample_counts: dict[str, int] = {}
        local_updates: dict[str, ClassifierBundle] = {}
        local_update_meta: dict[str, Any] = {}
        round_train_sizes = {
            site_id: int(len(fl_lab._align(payload["train"], current.features)))
            for site_id, payload in cohort_frames.items()
        }
        median_train = statistics.median(round_train_sizes.values()) if round_train_sizes else 1.0
        site_extra_trees: dict[str, int] = {}

        for site_index, site_id in enumerate(cohort_site_ids):
            payload = cohort_frames[site_id]
            train = fl_lab._align(payload["train"], current.features)
            sample_counts[site_id] = int(len(train))
            if client_weighting == "sample_count":
                ratio = sample_counts[site_id] / max(median_train, 1.0)
                extra_trees = max(1, min(round(trees_per_site * ratio), trees_per_site * 2))
            else:
                extra_trees = trees_per_site
            site_extra_trees[site_id] = extra_trees
            with fl_lab.ProcessResourceMonitor() as monitor:
                local = fl_lab.continue_binary(
                    deepcopy(current),
                    train,
                    extra_trees=extra_trees,
                    seed=seed + round_no * 10 + site_index,
                    xgb_params=xgb_params,
                )
                update_bytes = fl_lab._tree_update_bytes(current, local)
            local_updates[site_id] = local
            local_update_meta[site_id] = {
                "training_resources": monitor.result,
                "sample_count": int(len(train)),
                "new_trees": extra_trees,
                "update_bytes": update_bytes,
                "local_metrics": _metrics_for_cohort_models(
                    {cohort: local},
                    {site_id: cohort for site_id in cohort_site_ids},
                    cohort_frames,
                ),
            }

        aggregate_started = time.perf_counter()
        current, trees_added = fl_lab.aggregate_independent_tree_updates(
            current,
            local_updates,
            site_order=cohort_site_ids,
        )
        reverse, _ = fl_lab.aggregate_independent_tree_updates(
            round0_global if round_no == 1 else previous_global,
            local_updates,
            site_order=tuple(reversed(cohort_site_ids)),
        )
        aggregation_seconds = round(time.perf_counter() - aggregate_started, 6)
        model_path = models_dir / f"cohort-{cohort}-round-{round_no:03d}.joblib"
        save_classifier(current, model_path)
        cohort_site_map = {site_id: cohort for site_id in cohort_site_ids}
        metrics = _metrics_for_cohort_models({cohort: current}, cohort_site_map, cohort_frames)
        reverse_metrics = _metrics_for_cohort_models({cohort: reverse}, cohort_site_map, cohort_frames)
        result_sha = _sha256_file(model_path)
        round_id = f"lab-{cohort}-round-{round_no:03d}"
        artifact_uri, artifact_size = publish_global_model(
            model_path,
            round_id=round_id,
            cp_artifacts_dir=cp_artifacts_dir,
        )
        if not skip_control_plane:
            record_round(
                round_id=round_id,
                base_version=f"0.{round_no}.0",
                sample_counts=sample_counts,
                result_sha256=result_sha,
                epsilon=0.0,
                site_ids=cohort_site_ids,
                model_id=f"ot-xgb-binary-{cohort}",
                created_by="lab-protocol-cohort",
                robust_policy={
                    "method": "independent-equal-tree-append",
                    "minimum_clients": len(cohort_site_ids),
                    "fl_protocol_group": cohort,
                },
                artifact_uri=artifact_uri,
                artifact_size_bytes=artifact_size,
            )
        payload = {
            "fl_protocol_group": cohort,
            "cohort_label": FL_COHORT_LABELS.get(cohort, cohort),
            "round_id": round_id,
            "round": round_no,
            "artifact": str(model_path),
            "artifact_sha256": result_sha,
            "artifact_bytes": model_path.stat().st_size,
            "control_plane_artifact_uri": artifact_uri,
            "control_plane_artifact_bytes": artifact_size,
            "site_ids": list(cohort_site_ids),
            "sample_counts": sample_counts,
            "trees_added_by_site": trees_added,
            "aggregation": {
                "method": "independent_equal_tree_append",
                "client_weighting": client_weighting,
                "median_train_rows": round(float(median_train), 2),
                "site_order": list(cohort_site_ids),
                "reverse_order_macro_f1": reverse_metrics["macro_f1"],
                "order_invariant_macro_f1": reverse_metrics["macro_f1"] == metrics["macro_f1"],
                "aggregation_seconds": aggregation_seconds,
            },
            "local_updates": local_update_meta,
            "round_seconds": round(time.perf_counter() - round_started, 6),
            "metrics": metrics,
        }
        round_metrics.append(payload)
        previous_global = deepcopy(current)
        print(
            f"  [{cohort}] round {round_no} cohort_macro_f1={metrics['macro_f1']} "
            f"sha={result_sha[:12]}",
            flush=True,
        )

    per_cohort_summary = {
        "fl_protocol_group": cohort,
        "cohort_label": FL_COHORT_LABELS.get(cohort, cohort),
        "site_ids": list(cohort_site_ids),
        "rounds": round_metrics,
        "final_macro_f1": round_metrics[-1]["metrics"]["macro_f1"] if round_metrics else None,
        "final_artifact": round_metrics[-1]["artifact"] if round_metrics else None,
    }
    return current, round_metrics, per_cohort_summary


def _run_single_global_fl(
    *,
    site_ids: tuple[str, ...],
    frames: dict[str, dict[str, pd.DataFrame]],
    federation_base: ClassifierBundle,
    models_dir: Path,
    rounds: int,
    trees_per_site: int,
    client_weighting: str,
    seed: int,
    xgb_params: dict[str, Any],
) -> tuple[ClassifierBundle, list[dict[str, Any]], dict[str, Any]]:
    current = deepcopy(federation_base)
    round_metrics: list[dict[str, Any]] = []
    round0_global = deepcopy(federation_base)
    previous_global = deepcopy(federation_base)

    for round_no in range(1, rounds + 1):
        round_started = time.perf_counter()
        sample_counts: dict[str, int] = {}
        local_updates: dict[str, ClassifierBundle] = {}
        round_train_sizes = {
            site_id: int(len(fl_lab._align(payload["train"], current.features)))
            for site_id, payload in frames.items()
        }
        median_train = statistics.median(round_train_sizes.values()) if round_train_sizes else 1.0
        site_extra_trees: dict[str, int] = {}

        for site_index, (site_id, payload) in enumerate(frames.items()):
            train = fl_lab._align(payload["train"], current.features)
            sample_counts[site_id] = int(len(train))
            if client_weighting == "sample_count":
                ratio = sample_counts[site_id] / max(median_train, 1.0)
                extra_trees = max(1, min(round(trees_per_site * ratio), trees_per_site * 2))
            else:
                extra_trees = trees_per_site
            site_extra_trees[site_id] = extra_trees
            local_updates[site_id] = fl_lab.continue_binary(
                deepcopy(current),
                train,
                extra_trees=extra_trees,
                seed=seed + round_no * 10 + site_index,
                xgb_params=xgb_params,
            )

        current, trees_added = fl_lab.aggregate_independent_tree_updates(
            current,
            local_updates,
            site_order=site_ids,
        )
        fl_lab.aggregate_independent_tree_updates(
            round0_global if round_no == 1 else previous_global,
            local_updates,
            site_order=tuple(reversed(site_ids)),
        )
        model_path = models_dir / f"single-global-round-{round_no:03d}.joblib"
        save_classifier(current, model_path)
        metrics = fl_lab._metrics_for(current, frames)
        round_metrics.append(
            {
                "round": round_no,
                "artifact": str(model_path),
                "metrics": metrics,
                "trees_added_by_site": trees_added,
                "round_seconds": round(time.perf_counter() - round_started, 6),
            }
        )
        previous_global = deepcopy(current)
        print(f"  [single-global] round {round_no} macro_f1={metrics['macro_f1']}", flush=True)

    final_metrics = round_metrics[-1]["metrics"] if round_metrics else {}
    return current, round_metrics, final_metrics


def _resolve_xgb_params(
    cohort: str,
    *,
    default_params: dict[str, Any],
    by_cohort: dict[str, dict[str, Any]] | None,
) -> dict[str, Any]:
    resolved = dict(default_params)
    if by_cohort and cohort in by_cohort:
        resolved.update(by_cohort[cohort])
    return resolved


def _run_e3_cohort_centralized(
    *,
    cohort_groups: dict[str, tuple[str, ...]],
    frames: dict[str, dict[str, pd.DataFrame]],
    site_cohort: dict[str, str],
    round0: ClassifierBundle,
    models_dir: Path,
    seed: int,
    xgb_params: dict[str, Any],
    xgb_params_by_cohort: dict[str, dict[str, Any]] | None = None,
) -> tuple[dict[str, ClassifierBundle], dict[str, Any], dict[str, Any]]:
    """Train one centralized XGB per protocol cohort; score each site with its cohort model."""
    cohort_models: dict[str, ClassifierBundle] = {}
    per_cohort: dict[str, Any] = {}

    for cohort in sorted(cohort_groups):
        cohort_site_ids = cohort_groups[cohort]
        cohort_frames = {site_id: frames[site_id] for site_id in cohort_site_ids}
        central_train = pd.concat(
            [fl_lab._align(cohort_frames[s]["train"], round0.features) for s in cohort_site_ids],
            ignore_index=True,
        )
        cohort_xgb = _resolve_xgb_params(
            cohort, default_params=xgb_params, by_cohort=xgb_params_by_cohort
        )
        with fl_lab.ProcessResourceMonitor() as monitor:
            bundle = train_classifier(
                central_train,
                model_name="xgboost",
                task="binary",
                seed=seed,
                preprocess=round0.preprocess,
                xgb_params=cohort_xgb,
            )
        model_path = models_dir / f"centralized-cohort-{cohort}.joblib"
        save_classifier(bundle, model_path)
        cohort_site_map = {site_id: cohort for site_id in cohort_site_ids}
        cohort_metrics = _metrics_for_cohort_models({cohort: bundle}, cohort_site_map, cohort_frames)
        cohort_models[cohort] = bundle
        per_cohort[cohort] = {
            "fl_protocol_group": cohort,
            "cohort_label": FL_COHORT_LABELS.get(cohort, cohort),
            "site_ids": list(cohort_site_ids),
            "training_rows": int(len(central_train)),
            "artifact": str(model_path),
            "artifact_bytes": model_path.stat().st_size,
            "training_resources": monitor.result,
            "macro_f1_within_cohort": cohort_metrics["macro_f1"],
            "per_site": cohort_metrics["per_site"],
        }
        print(
            f"  [E3-cohort {cohort}] train_rows={len(central_train)} "
            f"within_cohort_macro_f1={cohort_metrics['macro_f1']}",
            flush=True,
        )

    combined = _metrics_for_cohort_models(cohort_models, site_cohort, frames)
    payload = {
        "aggregation_mode": "centralized_per_protocol_cohort",
        "note": (
            "Each cohort's train data is merged centrally (no FL rounds). "
            "Each site is evaluated with its cohort centralized model."
        ),
        "macro_f1": combined["macro_f1"],
        "macro_accuracy": combined["macro_accuracy"],
        "macro_balanced_accuracy": combined["macro_balanced_accuracy"],
        "per_site": combined["per_site"],
        "per_cohort": per_cohort,
        "models": {cohort: per_cohort[cohort]["artifact"] for cohort in per_cohort},
    }
    return cohort_models, payload, combined


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset-root", type=Path, default=Path(r"D:\實習\資料集"))
    parser.add_argument("--splits-dir", type=Path, default=ROOT / "artifacts" / "fl-experiment-six" / "splits")
    parser.add_argument("--output-dir", type=Path, default=ROOT / "artifacts" / "fl-experiment-six-cohort")
    parser.add_argument("--experiment-id", type=str, default="")
    parser.add_argument("--seed", type=int, default=20260818)
    parser.add_argument("--max-train-rows-per-file", type=int, default=2000)
    parser.add_argument("--max-test-rows-per-file", type=int, default=2000)
    parser.add_argument("--max-benign-rows", type=int, default=3000)
    parser.add_argument("--rounds", type=int, default=5)
    parser.add_argument("--trees-per-site", type=int, default=8)
    parser.add_argument(
        "--client-weighting",
        choices=("equal_tree_count", "sample_count"),
        default="equal_tree_count",
    )
    parser.add_argument("--skip-control-plane", action="store_true", default=True)
    parser.add_argument(
        "--cp-artifacts-dir",
        type=Path,
        default=None,
        help="Control Plane federation-models directory",
    )
    parser.add_argument("--skip-single-global", action="store_true")
    parser.add_argument("--xgb-params", type=Path)
    parser.add_argument(
        "--xgb-params-by-cohort",
        type=Path,
        help="JSON with per-cohort XGB overrides: {mqtt: {...}, network: {...}}",
    )
    parser.add_argument(
        "--fl-params-by-cohort",
        type=Path,
        help="JSON with per-cohort FL overrides: {mqtt: {rounds, trees_per_site, client_weighting}}",
    )
    args = parser.parse_args()

    site_ids = fl_lab.discover_site_ids(args.splits_dir)
    cp_artifacts_dir = args.cp_artifacts_dir
    if cp_artifacts_dir is None and not args.skip_control_plane:
        cp_artifacts_dir = default_cp_artifacts_dir()
    if cp_artifacts_dir is not None:
        print(f"==> Control Plane federation artifacts: {cp_artifacts_dir}", flush=True)
    site_cohort = _load_site_cohort_map(args.splits_dir, site_ids)
    cohort_groups = group_site_ids_by_cohort(site_ids, splits_dir=args.splits_dir)
    manifest_path = args.splits_dir.parent / "experiment-manifest.json"
    layout = ""
    if manifest_path.is_file():
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        layout = str(manifest.get("layout") or "")
    experiment_id = args.experiment_id or f"fl-{layout or len(site_ids)}-site-cohort-{args.seed}"

    xgb_params = dict(DEFAULT_XGB_BINARY)
    if args.xgb_params and args.xgb_params.is_file():
        loaded = json.loads(args.xgb_params.read_text(encoding="utf-8"))
        xgb_params.update(loaded.get("best_params") or loaded)
    xgb_params_by_cohort: dict[str, dict[str, Any]] | None = None
    if args.xgb_params_by_cohort and args.xgb_params_by_cohort.is_file():
        loaded = json.loads(args.xgb_params_by_cohort.read_text(encoding="utf-8"))
        xgb_params_by_cohort = loaded.get("cohorts") or loaded
    fl_params_by_cohort: dict[str, dict[str, Any]] | None = None
    if args.fl_params_by_cohort and args.fl_params_by_cohort.is_file():
        loaded = json.loads(args.fl_params_by_cohort.read_text(encoding="utf-8"))
        fl_params_by_cohort = loaded.get("cohorts") or loaded

    mapping = load_column_map()
    print(
        f"==> Loading site frames ({len(site_ids)} sites, {len(cohort_groups)} protocol cohorts)",
        flush=True,
    )
    for cohort, ids in cohort_groups.items():
        print(f"    {cohort}: {', '.join(ids)}", flush=True)

    frames = fl_lab.load_site_frames(
        splits_dir=args.splits_dir,
        dataset_root=args.dataset_root,
        mapping=mapping,
        max_train=args.max_train_rows_per_file,
        max_test=args.max_test_rows_per_file,
        max_benign=args.max_benign_rows,
        seed=args.seed,
        site_ids=site_ids,
    )

    round0 = load_classifier(ROOT / "artifacts" / "classifiers" / "xgboost_binary.joblib")
    federation_base = fl_lab._uncalibrated_federation_base(round0)
    args.output_dir.mkdir(parents=True, exist_ok=True)
    models_dir = args.output_dir / "models"
    models_dir.mkdir(parents=True, exist_ok=True)
    experiment_started = time.perf_counter()

    data_profile = fl_lab._data_profile(frames, round0.features)
    protocol_cohorts = cohort_index(site_ids, splits_dir=args.splits_dir)
    for site_id in site_ids:
        data_profile["sites"][site_id]["fl_protocol_group"] = site_cohort[site_id]
    (args.output_dir / "data-profile.json").write_text(
        json.dumps(data_profile, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )

    print("==> E0 federation-compatible Round 0", flush=True)
    with fl_lab.ProcessResourceMonitor() as monitor:
        e0 = fl_lab._metrics_for(federation_base, frames)
    e0["evaluation_resources"] = monitor.result

    print("==> E1 local-only", flush=True)
    local_metrics: dict[str, Any] = {}
    for site_id, payload in frames.items():
        train = fl_lab._align(payload["train"], round0.features)
        with fl_lab.ProcessResourceMonitor() as monitor:
            bundle = train_classifier(
                train,
                model_name="xgboost",
                task="binary",
                seed=args.seed,
                preprocess=round0.preprocess,
                xgb_params=xgb_params,
            )
        local_metrics[site_id] = fl_lab._metrics_for(bundle, frames)
        local_metrics[site_id]["training_resources"] = monitor.result
        local_metrics[site_id]["fl_protocol_group"] = site_cohort[site_id]
        print(f"  {site_id} local macro_f1={local_metrics[site_id]['macro_f1']}", flush=True)
    cross_f1 = [local_metrics[site_id]["macro_f1"] for site_id in site_ids]
    e1 = {
        "per_local_model": local_metrics,
        "cross_site_macro_f1_mean": round(float(np.mean(cross_f1)), 6),
    }

    print("==> E3 centralized oracle", flush=True)
    central_train = pd.concat(
        [fl_lab._align(payload["train"], round0.features) for payload in frames.values()],
        ignore_index=True,
    )
    with fl_lab.ProcessResourceMonitor() as monitor:
        central = train_classifier(
            central_train,
            model_name="xgboost",
            task="binary",
            seed=args.seed,
            preprocess=round0.preprocess,
            xgb_params=xgb_params,
        )
    e3 = fl_lab._metrics_for(central, frames)
    e3["training_resources"] = monitor.result
    print(f"  centralized macro_f1={e3['macro_f1']}", flush=True)

    print("==> E3-cohort centralized oracle (one XGB per protocol cohort)", flush=True)
    e3_cohort_models, e3_cohort, e3_cohort_combined = _run_e3_cohort_centralized(
        cohort_groups=cohort_groups,
        frames=frames,
        site_cohort=site_cohort,
        round0=round0,
        models_dir=models_dir,
        seed=args.seed,
        xgb_params=xgb_params,
        xgb_params_by_cohort=xgb_params_by_cohort,
    )
    print(f"  cohort-aware centralized macro_f1={e3_cohort['macro_f1']}", flush=True)

    single_global: dict[str, Any] = {"skipped": True}
    if not args.skip_single_global:
        print("==> E2 single-global FL (all sites, one model — baseline comparison)", flush=True)
        _, single_rounds, single_final = _run_single_global_fl(
            site_ids=site_ids,
            frames=frames,
            federation_base=federation_base,
            models_dir=models_dir,
            rounds=args.rounds,
            trees_per_site=args.trees_per_site,
            client_weighting=args.client_weighting,
            seed=args.seed,
            xgb_params=xgb_params,
        )
        single_global = {
            "aggregation": "single_global_independent_equal_tree_append",
            "rounds": single_rounds,
            "final_macro_f1": single_final.get("macro_f1"),
        }

    print("==> E2 protocol-cohort FL (one global model per cohort)", flush=True)
    cohort_final_models: dict[str, ClassifierBundle] = {}
    cohort_summaries: dict[str, Any] = {}
    all_cohort_rounds: dict[str, list[dict[str, Any]]] = {}
    for cohort in sorted(cohort_groups):
        cohort_site_ids = cohort_groups[cohort]
        cohort_fl = (fl_params_by_cohort or {}).get(cohort, {})
        cohort_rounds = int(cohort_fl.get("rounds", args.rounds))
        cohort_trees = int(cohort_fl.get("trees_per_site", args.trees_per_site))
        cohort_weighting = str(cohort_fl.get("client_weighting", args.client_weighting))
        cohort_xgb = _resolve_xgb_params(
            cohort, default_params=xgb_params, by_cohort=xgb_params_by_cohort
        )
        final_model, rounds_payload, summary = _run_cohort_fl(
            cohort=cohort,
            cohort_site_ids=cohort_site_ids,
            frames=frames,
            federation_base=federation_base,
            models_dir=models_dir,
            rounds=cohort_rounds,
            trees_per_site=cohort_trees,
            client_weighting=cohort_weighting,
            seed=args.seed,
            xgb_params=cohort_xgb,
            skip_control_plane=args.skip_control_plane,
            cp_artifacts_dir=cp_artifacts_dir,
        )
        cohort_final_models[cohort] = final_model
        cohort_summaries[cohort] = summary
        all_cohort_rounds[cohort] = rounds_payload

    e2_cohort = _metrics_for_cohort_models(cohort_final_models, site_cohort, frames)
    print(f"  cohort-aware final macro_f1={e2_cohort['macro_f1']}", flush=True)

    (args.output_dir / "baselines").mkdir(parents=True, exist_ok=True)
    (args.output_dir / "baselines" / "round-0-trained-eval.json").write_text(
        json.dumps(e0, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    (args.output_dir / "baselines" / "local-only-metrics.json").write_text(
        json.dumps(e1, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    (args.output_dir / "baselines" / "centralized-oracle-metrics.json").write_text(
        json.dumps(e3, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    (args.output_dir / "baselines" / "centralized-cohort-oracle-metrics.json").write_text(
        json.dumps(e3_cohort, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    (args.output_dir / "cohorts").mkdir(parents=True, exist_ok=True)
    for cohort, summary in cohort_summaries.items():
        (args.output_dir / "cohorts" / f"{cohort}-summary.json").write_text(
            json.dumps(summary, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
    (args.output_dir / "cohorts" / "final-cohort-metrics.json").write_text(
        json.dumps(e2_cohort, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )

    summary = {
        "experiment_id": experiment_id,
        "layout": layout or f"{len(site_ids)}-site",
        "aggregation_mode": "protocol_cohort_multi_global",
        "protocol_cohorts": protocol_cohorts,
        "site_cohort_map": site_cohort,
        "site_count": len(site_ids),
        "site_ids": list(site_ids),
        "completed_at": _utc(),
        "booster": "xgboost",
        "task": "binary_attack_vs_benign",
        "dataset": "CICIoMT2024",
        "seed": args.seed,
        "rounds": args.rounds,
        "trees_per_site_per_round": args.trees_per_site,
        "client_weighting": args.client_weighting,
        "E0_round0_macro_f1": e0.get("macro_f1"),
        "E1_local_cross_site_macro_f1_mean": e1.get("cross_site_macro_f1_mean"),
        "E2_cohort_aware_round5_macro_f1": e2_cohort.get("macro_f1"),
        "E2_single_global_round5_macro_f1": single_global.get("final_macro_f1"),
        "E3_centralized_macro_f1": e3.get("macro_f1"),
        "E3_cohort_centralized_macro_f1": e3_cohort.get("macro_f1"),
        "E3_cohort_per_cohort_macro_f1": {
            cohort: per["macro_f1_within_cohort"] for cohort, per in e3_cohort["per_cohort"].items()
        },
        "cohort_final_macro_f1": {
            cohort: cohort_summaries[cohort]["final_macro_f1"] for cohort in sorted(cohort_summaries)
        },
        "deployment_note": (
            "Each Edge scores with the global model for its site's fl_protocol_group "
            "(wifi / mqtt / network). Baseline and IF remain shared."
        ),
        "round0": e0,
        "local_only": e1,
        "single_global_fl": single_global,
        "protocol_cohort_fl": {
            "per_cohort": cohort_summaries,
            "final_cohort_aware_metrics": e2_cohort,
        },
        "centralized": e3,
        "centralized_cohort": e3_cohort,
        "total_experiment_seconds": round(time.perf_counter() - experiment_started, 6),
    }
    (args.output_dir / "summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(
        {
            "E0": summary["E0_round0_macro_f1"],
            "E1": summary["E1_local_cross_site_macro_f1_mean"],
            "E2_cohort": summary["E2_cohort_aware_round5_macro_f1"],
            "E2_single_global": summary["E2_single_global_round5_macro_f1"],
            "E3": summary["E3_centralized_macro_f1"],
            "E3_cohort": summary["E3_cohort_centralized_macro_f1"],
            "E3_cohort_per_cohort": summary["E3_cohort_per_cohort_macro_f1"],
            "cohorts": summary["cohort_final_macro_f1"],
        },
        indent=2,
    ))
    print(f"Wrote {args.output_dir / 'summary.json'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
