#!/usr/bin/env python3
"""Phase C: measure XGB vs LGBM known-attack + fusion latency (PC in-process + optional Pi HTTP)."""

from __future__ import annotations

import argparse
import json
import platform
import statistics
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import httpx
import numpy as np
import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from app.baseline_scorer import resolve_baseline_profile, score_baseline_features
from app.classifier import load_classifier, score_known_attack
from app.detector import load_bundle
from app.data.columns import load_column_map
from app.fusion import fuse_detections
from scripts.run_three_site_fl_experiment import (
    ProcessResourceMonitor,
    discover_site_ids,
    load_site_frames,
)


def _utc() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _percentile(values: list[float], pct: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    index = min(len(ordered) - 1, max(0, int(round((pct / 100.0) * (len(ordered) - 1)))))
    return round(float(ordered[index]), 3)


def _latency_summary(values: list[float]) -> dict[str, float | None]:
    if not values:
        return {"count": 0, "mean_ms": None, "p50_ms": None, "p95_ms": None, "max_ms": None}
    return {
        "count": len(values),
        "mean_ms": round(float(statistics.mean(values)), 3),
        "p50_ms": _percentile(values, 50),
        "p95_ms": _percentile(values, 95),
        "max_ms": round(float(max(values)), 3),
    }


def _row_features(row: pd.Series, feature_names: list[str]) -> dict[str, float]:
    out: dict[str, float] = {}
    for name in feature_names:
        if name in row.index and pd.notna(row[name]):
            out[name] = float(row[name])
    return out


def _collect_windows(
    *,
    splits_dir: Path,
    dataset_root: Path,
    seed: int,
    max_rows: int,
    feature_names: list[str],
) -> list[dict[str, Any]]:
    mapping = load_column_map()
    site_ids = discover_site_ids(splits_dir)
    frames = load_site_frames(
        splits_dir=splits_dir,
        dataset_root=dataset_root,
        mapping=mapping,
        max_train=500,
        max_test=max(max_rows // max(len(site_ids), 1), 100),
        max_benign=500,
        seed=seed,
        site_ids=site_ids,
    )
    windows: list[dict[str, Any]] = []
    for site_id, payload in frames.items():
        spec = json.loads((splits_dir / f"{site_id}.json").read_text(encoding="utf-8"))
        test = payload["test"]
        if test.empty:
            continue
        sample = test.sample(n=min(len(test), max_rows // len(site_ids) + 1), random_state=seed)
        for _, row in sample.iterrows():
            windows.append(
                {
                    "site_id": site_id,
                    "device_type": str(spec.get("device_type") or payload.get("device_type") or "medical_aiot"),
                    "device_id": f"{site_id}-bench",
                    "operating_state": "idle",
                    "criticality": "high",
                    "features": _row_features(row, feature_names),
                }
            )
    if not windows:
        raise RuntimeError("No feature windows collected for latency benchmark")
    return windows


def _score_fusion_ms(
    *,
    if_model: Any | None,
    booster_bundle: Any,
    window: dict[str, Any],
) -> float:
    started = time.perf_counter()
    features = window["features"]
    if if_model is not None:
        score, anomalous, evidence = if_model.score(features)
        if_payload = {
            "score": round(float(score), 6),
            "threshold": round(float(if_model.threshold), 6),
            "anomalous": bool(anomalous),
            "model_version": if_model.metadata.get("artifact_version", "if-0.1.0"),
            "detector": "isolation_forest",
        }
        feature_evidence = [
            {
                "feature": item["feature"],
                "observed": item.get("observed"),
                "baseline": None,
                "source": "detector:isolation_forest",
            }
            for item in evidence
        ]
    else:
        if_payload = {
            "score": 0.12,
            "threshold": 0.7,
            "anomalous": False,
            "model_version": "if-synthetic-lab",
            "detector": "isolation_forest",
        }
        feature_evidence = []
    known = score_known_attack(booster_bundle, features)
    profile = resolve_baseline_profile(device_type=window["device_type"], baseline_profile=None)
    baseline = score_baseline_features(features, profile)
    fuse_detections(
        device_id=window["device_id"],
        device_type=window["device_type"],
        operating_state=window["operating_state"],
        criticality=window["criticality"],
        baseline=baseline,
        known_attack=known,
        anomalies={"isolation_forest": if_payload, "lstm_autoencoder": None},
        feature_evidence=feature_evidence,
    )
    return (time.perf_counter() - started) * 1000.0


def _bench_booster_only_ms(booster_bundle: Any, window: dict[str, Any]) -> float:
    started = time.perf_counter()
    score_known_attack(booster_bundle, window["features"])
    return (time.perf_counter() - started) * 1000.0


def run_inprocess_benchmark(
    *,
    windows: list[dict[str, Any]],
    xgb_path: Path,
    lgbm_path: Path,
    iterations: int,
    if_model: Any | None,
) -> dict[str, Any]:
    xgb = load_classifier(xgb_path)
    lgbm = load_classifier(lgbm_path)
    cycle = [windows[i % len(windows)] for i in range(iterations)]

    def _run(label: str, bundle: Any, model_path: Path, fusion: bool) -> dict[str, Any]:
        latencies: list[float] = []
        with ProcessResourceMonitor() as monitor:
            for window in cycle:
                if fusion:
                    latencies.append(_score_fusion_ms(if_model=if_model, booster_bundle=bundle, window=window))
                else:
                    latencies.append(_bench_booster_only_ms(bundle, window))
        return {
            "label": label,
            "model_path": str(model_path),
            "model_bytes": model_path.stat().st_size,
            "fusion_path": fusion,
            "latency_ms": _latency_summary(latencies),
            "resources": monitor.result,
        }

    # warm-up
    for window in windows[:5]:
        _score_fusion_ms(if_model=if_model, booster_bundle=xgb, window=window)
        _score_fusion_ms(if_model=if_model, booster_bundle=lgbm, window=window)

    return {
        "host": platform.platform(),
        "machine": platform.machine(),
        "isolation_forest": "loaded" if if_model is not None else "synthetic_stub_for_lab_pc",
        "iterations": iterations,
        "window_count": len(windows),
        "xgboost": {
            "known_attack_only": _run("xgboost_known_attack", xgb, xgb_path, fusion=False),
            "full_fusion": _run("xgboost_full_fusion", xgb, xgb_path, fusion=True),
        },
        "lightgbm": {
            "known_attack_only": _run("lightgbm_known_attack", lgbm, lgbm_path, fusion=False),
            "full_fusion": _run("lightgbm_full_fusion", lgbm, lgbm_path, fusion=True),
        },
    }


def _http_score_body(window: dict[str, Any]) -> dict[str, Any]:
    return {
        "device_id": window["device_id"],
        "device_type": window["device_type"],
        "operating_state": window["operating_state"],
        "criticality": window["criticality"],
        "features": window["features"],
        "fuse": True,
    }


def run_http_benchmark(
    *,
    base_url: str,
    windows: list[dict[str, Any]],
    iterations: int,
    label: str,
) -> dict[str, Any]:
    cycle = [windows[i % len(windows)] for i in range(iterations)]
    latencies: list[float] = []
    errors: list[str] = []
    last_status: int | None = None
    try:
        with httpx.Client(base_url=base_url, timeout=30.0) as client:
            health = client.get("/health")
            if health.status_code >= 400:
                return {
                    "label": label,
                    "base_url": base_url,
                    "status": "unavailable",
                    "error": f"/health status={health.status_code}",
                }
            for window in cycle[:3]:
                client.post("/api/score", json=_http_score_body(window))
            for window in cycle:
                started = time.perf_counter()
                response = client.post("/api/score", json=_http_score_body(window))
                latencies.append((time.perf_counter() - started) * 1000.0)
                last_status = response.status_code
                if response.status_code >= 400:
                    errors.append(f"status={response.status_code}")
    except Exception as exc:
        return {
            "label": label,
            "base_url": base_url,
            "status": "unavailable",
            "error": str(exc),
        }
    model_info: dict[str, Any] = {}
    try:
        with httpx.Client(base_url=base_url, timeout=10.0) as client:
            model_info = client.get("/api/model").json()
    except Exception:
        model_info = {}
    return {
        "label": label,
        "base_url": base_url,
        "status": "ok" if not errors else "degraded",
        "booster_on_host": "xgboost (deployment default)" if label == "pi_http" else "xgboost unless manually swapped",
        "latency_ms": _latency_summary(latencies),
        "http_errors": errors[:5],
        "last_status_code": last_status,
        "api_model_keys": sorted(model_info.keys()) if isinstance(model_info, dict) else [],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Phase C booster latency benchmark")
    parser.add_argument("--dataset-root", type=Path, default=Path(r"D:\實習\資料集"))
    parser.add_argument(
        "--splits-dir",
        type=Path,
        default=ROOT / "artifacts" / "fl-experiment-three" / "splits",
    )
    parser.add_argument(
        "--xgb-model",
        type=Path,
        default=ROOT / "artifacts" / "classifiers" / "xgboost_binary.joblib",
    )
    parser.add_argument(
        "--lgbm-model",
        type=Path,
        default=ROOT / "artifacts" / "fl-experiment-lgbm-three" / "models" / "fl-round-005.joblib",
    )
    parser.add_argument("--iterations", type=int, default=1000)
    parser.add_argument("--max-windows", type=int, default=300)
    parser.add_argument("--seed", type=int, default=20260818)
    parser.add_argument("--pc-base", default="http://127.0.0.1:8000")
    parser.add_argument("--pi-base", default="http://192.168.50.90:8000")
    parser.add_argument("--skip-http", action="store_true")
    parser.add_argument(
        "--output",
        type=Path,
        default=ROOT / "artifacts" / "xgb-lgbm-benchmark" / "phase-c-latency.json",
    )
    args = parser.parse_args()

    if_path = ROOT / "artifacts" / "detector.joblib"
    if_model = load_bundle(if_path) if if_path.is_file() else None

    for path in (args.xgb_model, args.lgbm_model):
        if not path.is_file():
            raise FileNotFoundError(f"Missing required artifact: {path}")

    xgb_bundle = load_classifier(args.xgb_model)
    windows = _collect_windows(
        splits_dir=args.splits_dir,
        dataset_root=args.dataset_root,
        seed=args.seed,
        max_rows=args.max_windows,
        feature_names=xgb_bundle.features,
    )
    report: dict[str, Any] = {
        "phase": "C",
        "recorded_at": _utc(),
        "note": (
            "In-process benchmark compares XGB vs LGBM on identical fusion path without changing EdgeMed deployment. "
            "HTTP probes reflect currently deployed booster (XGB) unless model was manually swapped on the host."
        ),
        "iterations": args.iterations,
        "gates": {
            "detector_p95_le_500ms": None,
            "lgbm_fusion_p95_le_1_5x_xgb": None,
        },
        "models": {
            "xgboost": {"path": str(args.xgb_model), "bytes": args.xgb_model.stat().st_size},
            "lightgbm": {"path": str(args.lgbm_model), "bytes": args.lgbm_model.stat().st_size},
        },
        "inprocess": run_inprocess_benchmark(
            windows=windows,
            xgb_path=args.xgb_model,
            lgbm_path=args.lgbm_model,
            iterations=args.iterations,
            if_model=if_model,
        ),
        "http": {},
    }

    xgb_p95 = report["inprocess"]["xgboost"]["full_fusion"]["latency_ms"]["p95_ms"]
    lgbm_p95 = report["inprocess"]["lightgbm"]["full_fusion"]["latency_ms"]["p95_ms"]
    if xgb_p95 is not None:
        report["gates"]["detector_p95_le_500ms"] = bool(lgbm_p95 is not None and lgbm_p95 <= 500.0)
    if xgb_p95 and lgbm_p95:
        report["gates"]["lgbm_fusion_p95_le_1_5x_xgb"] = bool(lgbm_p95 <= xgb_p95 * 1.5)

    if not args.skip_http:
        report["http"]["pc_localhost"] = run_http_benchmark(
            base_url=args.pc_base,
            windows=windows,
            iterations=min(args.iterations, 200),
            label="pc_http",
        )
        report["http"]["pi_edge"] = run_http_benchmark(
            base_url=args.pi_base,
            windows=windows,
            iterations=min(args.iterations, 200),
            label="pi_http",
        )

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(
        {
            "output": str(args.output),
            "inprocess_xgb_fusion_p95_ms": xgb_p95,
            "inprocess_lgbm_fusion_p95_ms": lgbm_p95,
            "gates": report["gates"],
            "http_pi_status": (report.get("http") or {}).get("pi_edge", {}).get("status"),
        },
        ensure_ascii=False,
        indent=2,
    ))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
