"""Run the full three-site federated boosting lab experiment (E0–E3 + FL rounds 1–5).

This is a PC lab runner. Tree updates stay local; only round evidence is written
to Control Plane `federation_rounds`. Isolation Forest and baseline templates
are not aggregated.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import statistics
import sys
import threading
import time
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd
import psutil
import xgboost as xgb
from xgboost import XGBClassifier

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from app.classifier import (
    DEFAULT_LGBM_BINARY,
    DEFAULT_XGB_BINARY,
    ClassifierBundle,
    binary_labels,
    evaluate_classifier,
    load_classifier,
    save_classifier,
    train_classifier,
)
from app.lgbm_federation import continue_binary_lgbm, lgbm_tree_update_bytes
from app.data.ciciomt import discover_ciciomt_csv_dirs
from app.data.columns import apply_column_mapping, load_column_map
from app.data.inventory import infer_attack_family, infer_label_from_filename
from scripts.fl_control_plane import default_cp_artifacts_dir, publish_global_model, record_round


def discover_site_ids(splits_dir: Path) -> tuple[str, ...]:
    site_ids = tuple(sorted(path.stem for path in splits_dir.glob("site-*.json")))
    if not site_ids:
        raise FileNotFoundError(f"No site manifests found in {splits_dir}")
    return site_ids


class ProcessResourceMonitor:
    def __init__(self) -> None:
        self.process = psutil.Process()
        self.started = 0.0
        self.peak_rss = 0
        self.cpu_start = 0.0
        self.io_start = None
        self.result: dict[str, Any] = {}
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def __enter__(self) -> "ProcessResourceMonitor":
        self.started = time.perf_counter()
        cpu = self.process.cpu_times()
        self.cpu_start = float(cpu.user + cpu.system)
        self.io_start = self.process.io_counters()
        self.peak_rss = int(self.process.memory_info().rss)

        def sample() -> None:
            while not self._stop.wait(0.05):
                self.peak_rss = max(self.peak_rss, int(self.process.memory_info().rss))

        self._thread = threading.Thread(target=sample, daemon=True)
        self._thread.start()
        return self

    def __exit__(self, *_: object) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=1)
        elapsed = time.perf_counter() - self.started
        cpu = self.process.cpu_times()
        cpu_seconds = float(cpu.user + cpu.system) - self.cpu_start
        io_end = self.process.io_counters()
        self.result = {
            "wall_seconds": round(elapsed, 6),
            "cpu_seconds": round(cpu_seconds, 6),
            "average_process_cpu_percent": round(
                cpu_seconds / elapsed * 100.0 / max(psutil.cpu_count() or 1, 1), 3
            )
            if elapsed
            else None,
            "peak_rss_mb": round(self.peak_rss / 1024 / 1024, 3),
            "read_bytes": int(io_end.read_bytes - self.io_start.read_bytes),
            "write_bytes": int(io_end.write_bytes - self.io_start.write_bytes),
        }


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


def _load_split_frame(
    names: list[str],
    directory: Path,
    *,
    mapping: dict[str, str],
    max_rows: int,
    default_label: str,
) -> pd.DataFrame:
    frames: list[pd.DataFrame] = []
    for name in names:
        path = directory / name
        if not path.is_file():
            continue
        frame = pd.read_csv(path, nrows=max_rows)
        frame = frame.rename(columns=apply_column_mapping(list(frame.columns), mapping))
        label = infer_label_from_filename(path)
        family = infer_attack_family(label)
        frame["label"] = "Benign" if family == "benign" or default_label == "Benign" else "Attack"
        frame["attack_family"] = "benign" if frame["label"].iloc[0] == "Benign" else family
        frame["source_file"] = name
        frames.append(frame)
    if not frames:
        return pd.DataFrame()
    return pd.concat(frames, ignore_index=True)


def _load_named_csv(path: Path, mapping: dict[str, str], *, max_rows: int, label: str) -> pd.DataFrame:
    if not path.is_file():
        return pd.DataFrame()
    frame = pd.read_csv(path, nrows=max_rows)
    frame = frame.rename(columns=apply_column_mapping(list(frame.columns), mapping))
    frame["label"] = label
    frame["attack_family"] = "benign" if label == "Benign" else infer_attack_family(label)
    frame["source_file"] = path.name
    return frame


def _align(frame: pd.DataFrame, features: list[str]) -> pd.DataFrame:
    out = frame.copy()
    for name in features:
        if name not in out.columns:
            out[name] = np.nan
    return out


def _xgb_estimator(model: Any) -> XGBClassifier:
    """Return the concrete XGB estimator hidden by optional calibration."""
    if isinstance(model, XGBClassifier):
        return model
    calibrated = getattr(model, "calibrated_classifiers_", None)
    if calibrated:
        estimator = getattr(calibrated[0], "estimator", None)
        if isinstance(estimator, XGBClassifier):
            return estimator
    raise TypeError(f"federation requires XGBClassifier, got {type(model).__name__}")


def _uncalibrated_federation_base(bundle: ClassifierBundle) -> ClassifierBundle:
    """Use one fitted XGB fold as the tree-level federation starting model."""
    return ClassifierBundle(
        model_name=bundle.model_name,
        task=bundle.task,
        pipeline=deepcopy(_xgb_estimator(bundle.pipeline)),
        features=bundle.features,
        classes=bundle.classes,
        preprocess=bundle.preprocess,
        metadata={
            **bundle.metadata,
            "calibrated": False,
            "federation_base": "calibrated_classifier_fold_0_estimator",
        },
    )


def _model_document(booster: xgb.Booster) -> dict[str, Any]:
    return json.loads(booster.save_raw(raw_format="json"))


def aggregate_independent_tree_updates(
    global_bundle: ClassifierBundle,
    local_bundles: dict[str, ClassifierBundle],
    *,
    site_order: tuple[str, ...],
) -> tuple[ClassifierBundle, dict[str, int]]:
    """Append only each client's new trees to the common global booster.

    Every client must have started from exactly the same global model. This is
    an equal-tree-count FedXgbBagging laboratory proxy: it does not average
    parameters or weight clients by sample count.
    """
    global_booster = _xgb_estimator(global_bundle.pipeline).get_booster()
    global_rounds = int(global_booster.num_boosted_rounds())
    merged = _model_document(global_booster)
    merged_model = merged["learner"]["gradient_booster"]["model"]
    trees = list(merged_model["trees"])
    tree_info = list(merged_model["tree_info"])
    added: dict[str, int] = {}

    for site_id in site_order:
        local_booster = _xgb_estimator(local_bundles[site_id].pipeline).get_booster()
        local_doc = _model_document(local_booster)
        local_model = local_doc["learner"]["gradient_booster"]["model"]
        local_trees = local_model["trees"][global_rounds:]
        local_info = local_model["tree_info"][global_rounds:]
        added[site_id] = len(local_trees)
        for tree, info in zip(local_trees, local_info):
            copied = deepcopy(tree)
            copied["id"] = len(trees)
            trees.append(copied)
            tree_info.append(info)

    merged_model["trees"] = trees
    merged_model["tree_info"] = tree_info
    merged_model["gbtree_model_param"]["num_trees"] = str(len(trees))
    merged_model["iteration_indptr"] = list(range(len(trees) + 1))

    classifier = XGBClassifier()
    classifier.load_model(bytearray(json.dumps(merged, separators=(",", ":")).encode("utf-8")))
    metadata = {
        **global_bundle.metadata,
        "trained_at": _utc(),
        "aggregation": "independent_equal_tree_append",
        "global_rounds_before": global_rounds,
        "trees_added_by_site": added,
        "global_rounds_after": int(classifier.get_booster().num_boosted_rounds()),
    }
    return (
        ClassifierBundle(
            model_name=global_bundle.model_name,
            task="binary",
            pipeline=classifier,
            features=global_bundle.features,
            classes=global_bundle.classes,
            preprocess=global_bundle.preprocess,
            metadata=metadata,
        ),
        added,
    )


def load_site_frames(
    *,
    splits_dir: Path,
    dataset_root: Path,
    mapping: dict[str, str],
    max_train: int,
    max_test: int,
    max_benign: int,
    seed: int,
    site_ids: tuple[str, ...],
) -> dict[str, dict[str, pd.DataFrame]]:
    dirs = discover_ciciomt_csv_dirs(dataset_root)
    site_count = len(site_ids)
    benign_train_path = dirs["train"] / "Benign_train.pcap.csv"
    benign_all = _load_named_csv(
        benign_train_path,
        mapping,
        max_rows=max_benign * site_count + 100,
        label="Benign",
    )
    if not benign_all.empty:
        benign_all = benign_all.sample(frac=1.0, random_state=seed).reset_index(drop=True)
    official_benign_test = _load_named_csv(
        dirs["test"] / "Benign_test.pcap.csv",
        mapping,
        max_rows=max_benign * site_count + 100,
        label="Benign",
    )
    if not official_benign_test.empty:
        official_benign_test = official_benign_test.sample(frac=1.0, random_state=seed + 1).reset_index(drop=True)
    out: dict[str, dict[str, pd.DataFrame]] = {}
    for index, site_id in enumerate(site_ids):
        spec = json.loads((splits_dir / f"{site_id}.json").read_text(encoding="utf-8"))
        splits = spec["splits"]
        attack_train = _load_split_frame(
            splits.get("train") or [], dirs["train"], mapping=mapping, max_rows=max_train, default_label="Attack"
        )
        attack_test = _load_split_frame(
            splits.get("test") or [], dirs["test"], mapping=mapping, max_rows=max_test, default_label="Attack"
        )
        attack_valid = _load_split_frame(
            splits.get("validation") or [],
            dirs["train"],
            mapping=mapping,
            max_rows=max_train,
            default_label="Attack",
        )
        profiling_benign = pd.DataFrame()
        benign = spec.get("benign") or {}
        if benign.get("kind") == "profiling" and benign.get("file"):
            profiling_benign = _load_named_csv(
                dataset_root / "WiFI_and_MQTTprofilingCSV" / str(benign.get("file")),
                mapping,
                max_rows=max_benign,
                label="Benign",
            )
        if benign_all.empty:
            site_benign_train = pd.DataFrame()
        else:
            chunk = len(benign_all) // site_count if site_count else len(benign_all)
            start = index * chunk
            take = min(max_benign, chunk if chunk else len(benign_all))
            site_benign_train = benign_all.iloc[start : start + take].copy()
        if official_benign_test.empty:
            site_benign_test = pd.DataFrame()
        else:
            chunk = len(official_benign_test) // site_count if site_count else len(official_benign_test)
            start = index * chunk
            take = min(max_benign, chunk if chunk else len(official_benign_test))
            site_benign_test = official_benign_test.iloc[start : start + take].copy()
        site_valid_benign = site_benign_train.sample(
            n=min(len(site_benign_train), max(200, len(site_benign_train) // 5)),
            random_state=seed,
        ) if not site_benign_train.empty else pd.DataFrame()
        train = pd.concat([attack_train, site_benign_train], ignore_index=True)
        test = pd.concat([attack_test, site_benign_test], ignore_index=True)
        validation = pd.concat([attack_valid, site_valid_benign], ignore_index=True)
        out[site_id] = {
            "train": train,
            "test": test,
            "validation": validation,
            "profiling_benign": profiling_benign,
            "device_type": spec["device_type"],
            "attack_family": spec["attack_family"],
            "benign_test_source": "official_Benign_test_partitioned",
            "profiling_file": benign.get("file"),
        }
        print(
            f"{site_id}: train={len(train)} (attack={len(attack_train)} benign={len(site_benign_train)}) "
            f"test={len(test)} (attack={len(attack_test)} benign={len(site_benign_test)}) "
            f"valid={len(validation)}",
            flush=True,
        )
    return out


def _metrics_for(bundle: ClassifierBundle, frames: dict[str, dict[str, pd.DataFrame]]) -> dict[str, Any]:
    per_site: dict[str, Any] = {}
    f1s: list[float] = []
    accs: list[float] = []
    balanced_accs: list[float] = []
    for site_id, payload in frames.items():
        test = _align(payload["test"], bundle.features)
        if test.empty:
            per_site[site_id] = {"error": "empty_test"}
            continue
        metrics = evaluate_classifier(bundle, test)
        attack = test[test["label"] == "Attack"]
        benign = test[test["label"] == "Benign"]
        extra: dict[str, Any] = {}
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
    holdout = pd.concat([_align(payload["test"], bundle.features) for payload in frames.values()], ignore_index=True)
    inference: dict[str, Any] = {}
    if not holdout.empty:
        started = time.perf_counter()
        bundle.predict_proba(holdout)
        elapsed = time.perf_counter() - started
        inference = {
            "rows": int(len(holdout)),
            "seconds": round(elapsed, 6),
            "milliseconds_per_row": round(elapsed * 1000.0 / len(holdout), 6),
            "rows_per_second": round(len(holdout) / elapsed, 3) if elapsed else None,
        }
    return {
        "per_site": per_site,
        "macro_f1": round(float(np.mean(f1s)) if f1s else 0.0, 6),
        "metric_definition": "macro_f1 is the unweighted mean of per-site Attack-class F1",
        "macro_accuracy": round(float(np.mean(accs)) if accs else 0.0, 6),
        "macro_balanced_accuracy": round(
            float(np.mean(balanced_accs)) if balanced_accs else 0.0, 6
        ),
        "global_holdout": (
            evaluate_classifier(bundle, holdout, include_curves=True)
            if not holdout.empty
            else {}
        ),
        "inference_benchmark": inference,
    }


def _data_profile(
    frames: dict[str, dict[str, pd.DataFrame]],
    features: list[str],
) -> dict[str, Any]:
    sites: dict[str, Any] = {}
    for site_id, payload in frames.items():
        site: dict[str, Any] = {
            "device_type": payload["device_type"],
            "attack_family": payload["attack_family"],
        }
        for split in ("train", "test"):
            frame = payload[split]
            counts = frame["label"].value_counts().to_dict()
            schema_by_class: dict[str, Any] = {}
            for class_name, class_frame in frame.groupby("label"):
                aligned = _align(class_frame, features)[features]
                missing_fraction = aligned.isna().mean()
                schema_by_class[str(class_name)] = {
                    "rows": int(len(class_frame)),
                    "all_missing_features": [
                        name for name in features if bool(aligned[name].isna().all())
                    ],
                    "features_with_missing_values": int((missing_fraction > 0).sum()),
                    "mean_missing_fraction": round(float(missing_fraction.mean()), 6),
                }
            site[split] = {
                "rows": int(len(frame)),
                "classes": {str(key): int(value) for key, value in counts.items()},
                "source_files": int(frame["source_file"].nunique()),
                "missing_features": [name for name in features if name not in frame.columns],
                "schema_by_class": schema_by_class,
            }
        sites[site_id] = site
    return {
        "feature_count": len(features),
        "features": features,
        "sites": sites,
    }


def _tree_update_bytes(global_bundle: ClassifierBundle, local_bundle: ClassifierBundle) -> int:
    global_rounds = int(_xgb_estimator(global_bundle.pipeline).get_booster().num_boosted_rounds())
    local_model = _model_document(_xgb_estimator(local_bundle.pipeline).get_booster())[
        "learner"
    ]["gradient_booster"]["model"]
    payload = {
        "trees": local_model["trees"][global_rounds:],
        "tree_info": local_model["tree_info"][global_rounds:],
    }
    return len(json.dumps(payload, separators=(",", ":")).encode("utf-8"))


def continue_binary(
    bundle: ClassifierBundle,
    frame: pd.DataFrame,
    *,
    extra_trees: int,
    seed: int,
    xgb_params: dict[str, Any] | None = None,
) -> ClassifierBundle:
    aligned = _align(frame, bundle.features)
    x = bundle.preprocess.transform(aligned) if bundle.preprocess is not None else aligned[bundle.features].to_numpy()
    y = binary_labels(aligned["label"])
    if len(np.unique(y)) < 2:
        return bundle
    base = _xgb_estimator(bundle.pipeline)
    existing = int(base.get_booster().num_boosted_rounds())
    params = dict(DEFAULT_XGB_BINARY)
    if xgb_params:
        params.update({key: value for key, value in xgb_params.items() if value is not None})
    params["n_estimators"] = extra_trees
    params["random_state"] = seed
    params.pop("early_stopping_rounds", None)
    model = XGBClassifier(**params)
    model.fit(x, y, xgb_model=base.get_booster())
    metadata = dict(bundle.metadata)
    metadata["trained_at"] = _utc()
    metadata["continued_from_rounds"] = existing
    metadata["extra_trees"] = extra_trees
    metadata["training_rows"] = int(len(aligned))
    return ClassifierBundle(
        model_name=bundle.model_name,
        task="binary",
        pipeline=model,
        features=bundle.features,
        classes=bundle.classes,
        preprocess=bundle.preprocess,
        metadata=metadata,
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset-root", type=Path, default=Path(r"D:\實習\資料集"))
    parser.add_argument("--splits-dir", type=Path, default=ROOT / "artifacts" / "fl-experiment" / "splits")
    parser.add_argument("--output-dir", type=Path, default=None)
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
        help="equal_tree_count: each site adds the same number of trees; "
        "sample_count: scale extra trees by train rows vs cross-site median (min 1, max 2x base)",
    )
    parser.add_argument(
        "--booster",
        choices=("xgboost", "lightgbm"),
        default="xgboost",
        help="Boosting backend for the FL experiment run (does not change Edge deployment).",
    )
    parser.add_argument("--skip-control-plane", action="store_true")
    parser.add_argument(
        "--cp-artifacts-dir",
        type=Path,
        default=None,
        help="Control Plane federation-models directory "
        "(default: SENSEL_CP_FEDERATION_ARTIFACTS_DIR or sibling Control Plane checkout)",
    )
    parser.add_argument("--xgb-params", type=Path)
    parser.add_argument("--early-stopping-rounds", type=int, default=0)
    args = parser.parse_args()
    site_ids = discover_site_ids(args.splits_dir)
    cp_artifacts_dir = args.cp_artifacts_dir
    if cp_artifacts_dir is None and not args.skip_control_plane:
        cp_artifacts_dir = default_cp_artifacts_dir()
    if cp_artifacts_dir is not None:
        print(f"==> Control Plane federation artifacts: {cp_artifacts_dir}", flush=True)
    if args.output_dir is None:
        args.output_dir = args.splits_dir.parent
    manifest_path = args.splits_dir.parent / "experiment-manifest.json"
    layout = ""
    if manifest_path.is_file():
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        layout = str(manifest.get("layout") or "")
        experiment_id = args.experiment_id or str(manifest.get("experiment_id") or "")
    else:
        experiment_id = args.experiment_id
    if not experiment_id:
        experiment_id = f"fl-{len(site_ids)}-site-{args.seed}"
    xgb_params = dict(DEFAULT_XGB_BINARY)
    if args.xgb_params and args.xgb_params.is_file():
        loaded = json.loads(args.xgb_params.read_text(encoding="utf-8"))
        xgb_params.update(loaded.get("best_params") or loaded)
    lgbm_params = dict(DEFAULT_LGBM_BINARY)
    booster = args.booster
    model_name = booster

    mapping = load_column_map()
    print(f"==> Loading site frames ({len(site_ids)} sites: {', '.join(site_ids)})", flush=True)
    frames = load_site_frames(
        splits_dir=args.splits_dir,
        dataset_root=args.dataset_root,
        mapping=mapping,
        max_train=args.max_train_rows_per_file,
        max_test=args.max_test_rows_per_file,
        max_benign=args.max_benign_rows,
        seed=args.seed,
        site_ids=site_ids,
    )

    if booster == "lightgbm":
        binary_path = ROOT / "artifacts" / "classifiers" / "lightgbm_binary.joblib"
        xgb_ref = load_classifier(ROOT / "artifacts" / "classifiers" / "xgboost_binary.joblib")
        if binary_path.exists():
            round0 = load_classifier(binary_path)
        else:
            print("==> Training LightGBM Round 0 starter from combined site train data", flush=True)
            starter_train = pd.concat(
                [_align(payload["train"], xgb_ref.features) for payload in frames.values()],
                ignore_index=True,
            )
            round0 = train_classifier(
                starter_train,
                model_name="lightgbm",
                task="binary",
                seed=args.seed,
                preprocess=xgb_ref.preprocess,
                lgbm_params=lgbm_params,
            )
            save_classifier(round0, binary_path)
        federation_base = round0
    else:
        binary_path = ROOT / "artifacts" / "classifiers" / "xgboost_binary.joblib"
        round0 = load_classifier(binary_path)
        federation_base = _uncalibrated_federation_base(round0)
    args.output_dir.mkdir(parents=True, exist_ok=True)
    models_dir = args.output_dir / "models"
    models_dir.mkdir(parents=True, exist_ok=True)
    experiment_started = time.perf_counter()
    data_profile = _data_profile(frames, round0.features)
    (args.output_dir / "data-profile.json").write_text(
        json.dumps(data_profile, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )

    print("==> Existing calibrated reference", flush=True)
    with ProcessResourceMonitor() as monitor:
        existing_reference = _metrics_for(round0, frames)
    existing_reference["evaluation_resources"] = monitor.result

    print("==> E0 federation-compatible Round 0", flush=True)
    with ProcessResourceMonitor() as monitor:
        e0 = _metrics_for(federation_base, frames)
    e0["evaluation_resources"] = monitor.result
    e0["profiling_benign_diagnostic"] = {
        site_id: evaluate_classifier(federation_base, _align(payload["profiling_benign"], federation_base.features))
        if not payload.get("profiling_benign", pd.DataFrame()).empty
        else {"skipped": True}
        for site_id, payload in frames.items()
    }
    (args.output_dir / "baselines").mkdir(parents=True, exist_ok=True)
    (args.output_dir / "baselines" / "round-0-trained-eval.json").write_text(
        json.dumps(e0, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )

    print("==> E1 local-only", flush=True)
    local_metrics: dict[str, Any] = {}
    local_models: dict[str, ClassifierBundle] = {}
    for site_id, payload in frames.items():
        train = _align(payload["train"], round0.features)
        with ProcessResourceMonitor() as monitor:
            bundle = train_classifier(
                train,
                model_name=model_name,
                task="binary",
                seed=args.seed,
                preprocess=round0.preprocess,
                xgb_params=xgb_params if booster == "xgboost" else None,
                lgbm_params=lgbm_params if booster == "lightgbm" else None,
                eval_frame=_align(payload.get("validation", pd.DataFrame()), round0.features)
                if args.early_stopping_rounds
                else None,
                early_stopping_rounds=args.early_stopping_rounds or None,
            )
        local_models[site_id] = bundle
        local_path = models_dir / f"local-{site_id}.joblib"
        save_classifier(bundle, local_path)
        local_metrics[site_id] = _metrics_for(bundle, frames)
        local_metrics[site_id]["training_resources"] = monitor.result
        local_metrics[site_id]["model_bytes"] = local_path.stat().st_size
        print(f"  {site_id} local macro_f1={local_metrics[site_id]['macro_f1']}", flush=True)
    cross_f1 = [local_metrics[site_id]["macro_f1"] for site_id in site_ids]
    e1 = {"per_local_model": local_metrics, "cross_site_macro_f1_mean": round(float(np.mean(cross_f1)), 6)}
    (args.output_dir / "baselines" / "local-only-metrics.json").write_text(
        json.dumps(e1, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )

    print("==> E3 centralized oracle", flush=True)
    central_train = pd.concat(
        [_align(payload["train"], round0.features) for payload in frames.values()],
        ignore_index=True,
    )
    with ProcessResourceMonitor() as monitor:
        central_valid = pd.concat(
            [
                _align(payload.get("validation", pd.DataFrame()), round0.features)
                for payload in frames.values()
                if not payload.get("validation", pd.DataFrame()).empty
            ],
            ignore_index=True,
        ) if args.early_stopping_rounds else pd.DataFrame()
        central = train_classifier(
            central_train,
            model_name=model_name,
            task="binary",
            seed=args.seed,
            preprocess=round0.preprocess,
            xgb_params=xgb_params if booster == "xgboost" else None,
            lgbm_params=lgbm_params if booster == "lightgbm" else None,
            eval_frame=central_valid if not central_valid.empty else None,
            early_stopping_rounds=args.early_stopping_rounds or None,
        )
    central_path = models_dir / "centralized-oracle.joblib"
    save_classifier(central, central_path)
    e3 = _metrics_for(central, frames)
    e3["training_resources"] = monitor.result
    e3["model_bytes"] = central_path.stat().st_size
    (args.output_dir / "baselines" / "centralized-oracle-metrics.json").write_text(
        json.dumps(e3, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    print(f"  centralized macro_f1={e3['macro_f1']}", flush=True)

    weighting_label = (
        "sample_count_scaled_tree_append"
        if args.client_weighting == "sample_count"
        else "equal_tree_count"
    )
    aggregation_method = (
        "independent_equal_tree_append"
        if booster == "xgboost"
        else "sequential_cloud_continuation"
    )
    print(f"==> E2 FL rounds ({booster}, {aggregation_method})", flush=True)
    current = deepcopy(federation_base)
    round_metrics: list[dict[str, Any]] = []
    round0_global = deepcopy(federation_base)
    previous_global = deepcopy(federation_base)
    for round_no in range(1, args.rounds + 1):
        round_started = time.perf_counter()
        sample_counts: dict[str, int] = {}
        local_updates: dict[str, ClassifierBundle] = {}
        local_update_meta: dict[str, Any] = {}
        round_train_sizes = {
            site_id: int(len(_align(payload["train"], current.features)))
            for site_id, payload in frames.items()
        }
        median_train = statistics.median(round_train_sizes.values()) if round_train_sizes else 1.0
        site_extra_trees: dict[str, int] = {}
        for site_index, (site_id, payload) in enumerate(frames.items()):
            train = _align(payload["train"], current.features)
            sample_counts[site_id] = int(len(train))
            if args.client_weighting == "sample_count":
                ratio = sample_counts[site_id] / max(median_train, 1.0)
                extra_trees = max(1, min(round(args.trees_per_site * ratio), args.trees_per_site * 2))
            else:
                extra_trees = args.trees_per_site
            site_extra_trees[site_id] = extra_trees
            with ProcessResourceMonitor() as monitor:
                if booster == "lightgbm":
                    local = continue_binary_lgbm(
                        deepcopy(current),
                        train,
                        extra_trees=extra_trees,
                        seed=args.seed + round_no * 10 + site_index,
                        lgbm_params=lgbm_params,
                    )
                    update_bytes = lgbm_tree_update_bytes(current, local)
                else:
                    local = continue_binary(
                        deepcopy(current),
                        train,
                        extra_trees=extra_trees,
                        seed=args.seed + round_no * 10 + site_index,
                        xgb_params=xgb_params,
                    )
                    update_bytes = _tree_update_bytes(current, local)
            local_updates[site_id] = local
            local_update_meta[site_id] = {
                "training_resources": monitor.result,
                "sample_count": int(len(train)),
                "new_trees": extra_trees,
                "update_bytes": update_bytes,
                "local_metrics": _metrics_for(local, frames),
            }

        aggregate_started = time.perf_counter()
        if booster == "lightgbm":
            merged = deepcopy(current)
            trees_added: dict[str, int] = {}
            for site_id in site_ids:
                train = _align(frames[site_id]["train"], merged.features)
                merged = continue_binary_lgbm(
                    merged,
                    train,
                    extra_trees=site_extra_trees[site_id],
                    seed=args.seed + round_no * 100 + site_ids.index(site_id),
                    lgbm_params=lgbm_params,
                )
                trees_added[site_id] = site_extra_trees[site_id]
            current = merged
            reverse_merged = deepcopy(round0_global if round_no == 1 else previous_global)
            for site_id in reversed(site_ids):
                train = _align(frames[site_id]["train"], reverse_merged.features)
                reverse_merged = continue_binary_lgbm(
                    reverse_merged,
                    train,
                    extra_trees=site_extra_trees[site_id],
                    seed=args.seed + round_no * 200 + site_ids.index(site_id),
                    lgbm_params=lgbm_params,
                )
            reverse = reverse_merged
        else:
            current, trees_added = aggregate_independent_tree_updates(
                current,
                local_updates,
                site_order=site_ids,
            )
            reverse, _ = aggregate_independent_tree_updates(
                round0_global if round_no == 1 else previous_global,
                local_updates,
                site_order=tuple(reversed(site_ids)),
            )
        aggregation_seconds = round(time.perf_counter() - aggregate_started, 6)
        model_path = models_dir / f"fl-round-{round_no:03d}.joblib"
        save_classifier(current, model_path)
        metrics = _metrics_for(current, frames)
        reverse_metrics = _metrics_for(reverse, frames)
        result_sha = _sha256_file(model_path)
        round_id = f"lab-round-{round_no:03d}"
        artifact_uri, artifact_size = publish_global_model(
            model_path,
            round_id=round_id,
            cp_artifacts_dir=cp_artifacts_dir,
        )
        if not args.skip_control_plane:
            record_round(
                round_id=round_id,
                base_version=f"0.{round_no}.0",
                sample_counts=sample_counts,
                result_sha256=result_sha,
                epsilon=0.0,
                site_ids=site_ids,
                artifact_uri=artifact_uri,
                artifact_size_bytes=artifact_size,
            )
        payload = {
            "round_id": round_id,
            "round": round_no,
            "artifact": str(model_path),
            "artifact_sha256": result_sha,
            "artifact_bytes": model_path.stat().st_size,
            "control_plane_artifact_uri": artifact_uri,
            "control_plane_artifact_bytes": artifact_size,
            "sample_counts": sample_counts,
            "trees_added_by_site": trees_added,
            "aggregation": {
                "method": aggregation_method,
                "client_weighting": args.client_weighting,
                "median_train_rows": round(float(median_train), 2),
                "site_order": list(site_ids),
                "reverse_order_macro_f1": reverse_metrics["macro_f1"],
                "order_invariant_macro_f1": reverse_metrics["macro_f1"] == metrics["macro_f1"],
                "aggregation_seconds": aggregation_seconds,
            },
            "local_updates": local_update_meta,
            "round_seconds": round(time.perf_counter() - round_started, 6),
            "metrics": metrics,
        }
        round_dir = args.output_dir / "rounds" / f"round-{round_no:03d}"
        round_dir.mkdir(parents=True, exist_ok=True)
        (round_dir / "metrics.json").write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        round_metrics.append(payload)
        previous_global = deepcopy(current)
        print(f"  round {round_no} macro_f1={metrics['macro_f1']} sha={result_sha[:12]}", flush=True)

    e2_final = round_metrics[-1]["metrics"] if round_metrics else {}
    summary = {
        "experiment_id": experiment_id,
        "layout": layout or f"{len(site_ids)}-site",
        "site_count": len(site_ids),
        "site_ids": list(site_ids),
        "completed_at": _utc(),
        "booster": booster,
        "aggregation": (
            "independent_equal_tree_append_proxy_for_FedXgbBagging"
            if booster == "xgboost"
            else "sequential_cloud_continuation"
        ),
        "note": (
            "Each site independently adds trees from the same round-start global booster; "
            "the server appends only those new trees with equal tree count. No raw CSV leaves the site process. "
            "This is not Flower SuperLink."
            if booster == "xgboost"
            else (
                "LightGBM cannot merge independent tree deltas like XGB; cloud sequentially continues "
                "the global booster on each site's training data in fixed site order. "
                "Local updates are still computed per site for metrics. No raw CSV leaves the site process."
            )
        ),
        "task": "binary_attack_vs_benign",
        "dataset": "CICIoMT2024",
        "seed": args.seed,
        "rounds": args.rounds,
        "trees_per_site_per_round": args.trees_per_site,
        "client_weighting": args.client_weighting,
        "hyperparameter_optimization": "validation_grid_if_xgb_params_supplied",
        "early_stopping_rounds": args.early_stopping_rounds or None,
        "xgboost_parameters": xgb_params if booster == "xgboost" else None,
        "lightgbm_parameters": lgbm_params if booster == "lightgbm" else None,
        "data_profile": data_profile,
        "existing_calibrated_reference": existing_reference,
        "federation_base": e0,
        "E0_round0_macro_f1": e0.get("macro_f1"),
        "E1_local_cross_site_macro_f1_mean": e1.get("cross_site_macro_f1_mean"),
        "E2_round5_macro_f1": e2_final.get("macro_f1"),
        "E3_centralized_macro_f1": e3.get("macro_f1"),
        "round0": e0,
        "local_only": e1,
        "federated_rounds": [
            {
                "round": item["round"],
                "macro_f1": item["metrics"]["macro_f1"],
                "round_seconds": item["round_seconds"],
                "artifact_bytes": item["artifact_bytes"],
                "update_bytes": sum(
                    int(update["update_bytes"]) for update in item["local_updates"].values()
                ),
            }
            for item in round_metrics
        ],
        "centralized": e3,
        "total_experiment_seconds": round(time.perf_counter() - experiment_started, 6),
    }
    (args.output_dir / "summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({k: summary[k] for k in summary if k.endswith("macro_f1") or "macro_f1" in k}, indent=2))
    print(f"Wrote {args.output_dir / 'summary.json'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
