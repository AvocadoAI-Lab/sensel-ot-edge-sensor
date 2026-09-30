"""One-shot model manager commands for controlled rollout orchestration."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

from src.model_rollout.manager import ModelRolloutManager, RolloutConfig


def _scoped_file(value: str, *, root_env: str, default_root: str, must_exist: bool) -> Path:
    root = Path(os.getenv(root_env, default_root)).resolve(strict=True)
    target = Path(value)
    resolved = target.resolve(strict=must_exist)
    if resolved == root or root not in resolved.parents:
        raise ValueError(f"path must be a file below {root}")
    if target.is_symlink() or (must_exist and not target.is_file()):
        raise ValueError("rollout input/output path is invalid")
    return resolved


def _write_report(path: Path, payload: bytes) -> None:
    flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags, 0o640)
    try:
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError("failed to write rollout report")
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _manager() -> ModelRolloutManager:
    required = (
        "SENSEL_SITE_TENANT_ID",
        "SENSEL_SITE_ID",
        "SENSEL_SENSOR_ID",
        "SENSEL_DISTRIBUTION_SIGNING_KEY_ID",
        "SENSEL_RELEASE_SIGNING_KEY_ID",
        "SENSEL_EDGE_REPORT_SIGNING_KEY_ID",
    )
    values = {name: os.environ.get(name, "").strip() for name in required}
    if any(not value for value in values.values()):
        raise ValueError("model manager scope/key identities are required")
    return ModelRolloutManager(
        RolloutConfig(
            tenant_id=values["SENSEL_SITE_TENANT_ID"],
            site_id=values["SENSEL_SITE_ID"],
            sensor_id=values["SENSEL_SENSOR_ID"],
            model_root=Path(os.getenv("SENSEL_MODEL_ROOT", "/models/xgboost")),
            distribution_public_key_path=Path(
                os.getenv("SENSEL_DISTRIBUTION_PUBLIC_KEY_PATH", "/run/keys/distribution.pub.pem")
            ),
            distribution_key_id=values["SENSEL_DISTRIBUTION_SIGNING_KEY_ID"],
            release_public_key_path=Path(
                os.getenv("SENSEL_RELEASE_PUBLIC_KEY_PATH", "/run/keys/release.pub.pem")
            ),
            release_key_id=values["SENSEL_RELEASE_SIGNING_KEY_ID"],
            edge_report_private_key_path=Path(
                os.getenv("SENSEL_EDGE_REPORT_SIGNING_KEY_PATH", "/run/secrets/edge-report.pem")
            ),
            edge_report_key_id=values["SENSEL_EDGE_REPORT_SIGNING_KEY_ID"],
        )
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(dest="command", required=True)
    stage = commands.add_parser("stage")
    stage.add_argument("--bundle", required=True)
    activate = commands.add_parser("activate-canary")
    activate.add_argument("--distribution-id", required=True)
    evaluate = commands.add_parser("evaluate")
    evaluate.add_argument("--distribution-id", required=True)
    evaluate.add_argument("--inference-count", required=True, type=int)
    evaluate.add_argument("--inference-errors", required=True, type=int)
    evaluate.add_argument("--p95-latency-ms", required=True, type=float)
    evaluate.add_argument("--report-out", required=True)
    args = parser.parse_args()
    manager = _manager()
    if args.command == "stage":
        bundle_path = _scoped_file(
            args.bundle,
            root_env="SENSEL_MODEL_BUNDLE_ROOT",
            default_root="/input",
            must_exist=True,
        )
        result = manager.stage(bundle_path.read_bytes())
    elif args.command == "activate-canary":
        result = manager.activate_canary(args.distribution_id)
    else:
        result, report = manager.evaluate(
            args.distribution_id,
            inference_count=args.inference_count,
            inference_errors=args.inference_errors,
            p95_latency_ms=args.p95_latency_ms,
        )
        report_path = _scoped_file(
            args.report_out,
            root_env="SENSEL_MODEL_REPORT_ROOT",
            default_root="/output",
            must_exist=False,
        )
        _write_report(report_path, report)
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
