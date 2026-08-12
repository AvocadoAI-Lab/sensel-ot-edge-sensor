"""CLI benchmark for a batch-one ONNX sequence model on Edge hardware."""

from __future__ import annotations

import argparse
import json
import platform
import resource
import statistics
import sys
from pathlib import Path

from src.inference.onnx_sequence import OnnxSequenceRuntime


def _percentile(values: list[float], percentile: float) -> float:
    ordered = sorted(values)
    index = max(0, min(len(ordered) - 1, int(round((len(ordered) - 1) * percentile))))
    return ordered[index]


def _max_rss_mb() -> float:
    value = float(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss)
    if sys.platform == "darwin":
        return value / (1024 * 1024)
    return value / 1024


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    parser.add_argument("--model", type=Path, required=True)
    parser.add_argument("--model-version", default="p0-smoke")
    parser.add_argument("--feature-contract-id", default="sequence-risk-smoke-v1")
    parser.add_argument("--sequence-length", type=int, default=8)
    parser.add_argument("--feature-count", type=int, default=4)
    parser.add_argument("--warmup", type=int, default=10)
    parser.add_argument("--iterations", type=int, default=100)
    parser.add_argument("--max-p95-ms", type=float, default=25.0)
    parser.add_argument("--max-rss-mb", type=float, default=256.0)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.iterations < 1 or args.warmup < 0:
        raise SystemExit("iterations must be positive and warmup cannot be negative")

    runtime = OnnxSequenceRuntime(
        args.model,
        model_version=args.model_version,
        feature_contract_id=args.feature_contract_id,
    )
    if runtime.state.status != "ready":
        print(json.dumps({"passed": False, "model_state": runtime.state.to_dict()}))
        return 2

    import numpy as np

    generator = np.random.default_rng(seed=42)
    features = generator.random(
        (1, args.sequence_length, args.feature_count),
        dtype=np.float32,
    )

    for _ in range(args.warmup):
        result = runtime.predict(features)
        if not result.available:
            print(json.dumps({"passed": False, "inference": result.to_dict()}))
            return 2

    latencies: list[float] = []
    for _ in range(args.iterations):
        result = runtime.predict(features)
        if not result.available:
            print(json.dumps({"passed": False, "inference": result.to_dict()}))
            return 2
        latencies.append(result.latency_ms)

    mean_ms = statistics.fmean(latencies)
    p95_ms = _percentile(latencies, 0.95)
    rss_mb = _max_rss_mb()
    passed = p95_ms <= args.max_p95_ms and rss_mb <= args.max_rss_mb
    summary = {
        "passed": passed,
        "architecture": platform.machine(),
        "python": platform.python_version(),
        "model": str(args.model),
        "model_version": args.model_version,
        "feature_contract_id": args.feature_contract_id,
        "shape": [1, args.sequence_length, args.feature_count],
        "warmup": args.warmup,
        "iterations": args.iterations,
        "mean_ms": round(mean_ms, 4),
        "p50_ms": round(_percentile(latencies, 0.50), 4),
        "p95_ms": round(p95_ms, 4),
        "inferences_per_second": round(1000 / mean_ms, 2) if mean_ms > 0 else None,
        "max_rss_mb": round(rss_mb, 2),
        "budgets": {
            "max_p95_ms": args.max_p95_ms,
            "max_rss_mb": args.max_rss_mb,
        },
    }
    print(json.dumps(summary, sort_keys=True))
    return 0 if passed else 3


if __name__ == "__main__":
    raise SystemExit(main())
