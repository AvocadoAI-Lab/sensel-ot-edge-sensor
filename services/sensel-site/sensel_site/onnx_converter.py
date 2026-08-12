"""Offline UBJSON-to-ONNX conversion, parity, and ARM technical gate."""

from __future__ import annotations

import json
import os
import platform
import resource
import shutil
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from sensel_site.candidate_contract import verify_candidate_package
from sensel_site.feature_contracts import FeatureContractRegistry
from sensel_site.lineage import canonical_json, load_public_key, sha256_bytes
from sensel_site.signed_documents import read_regular_file, write_exclusive
from sensel_site.training_data import verify_training_input
from sensel_site.training_policy import XGBoostTrainingPolicy, load_xgboost_policy
from sensel_site.worker_config import ConverterWorkerConfig

CONVERSION_SCHEMA = "sensel.site.onnx-conversion-validation.v1"
APPROVAL_BUNDLE_SCHEMA = "sensel.site.release-approval-bundle.v1"


def _validated_decision(config: ConverterWorkerConfig) -> tuple[Path, dict[str, Any], str]:
    root = config.validation_root / "validated" / config.job_id
    if root.is_symlink() or not root.is_dir():
        raise ValueError("validated candidate decision is required")
    payload = read_regular_file(root / "validation.json", maximum_bytes=1_048_576)
    audit = json.loads(
        read_regular_file(root / "validation.sha256", maximum_bytes=4096)
    )
    digest = sha256_bytes(payload)
    if audit != {"algorithm": "SHA-256", "sha256": digest}:
        raise ValueError("candidate validation audit digest mismatch")
    decision = json.loads(payload)
    activation = decision.get("activation", {})
    if any(
        (
            decision.get("schema_version") != "sensel.site.candidate-validation.v1",
            decision.get("job_id") != config.job_id,
            decision.get("status") != "validated",
            (decision.get("tenant_id"), decision.get("site_id"))
            != (config.tenant_id, config.site_id),
            activation.get("performed") is not False,
            activation.get("automatic_activation_allowed") is not False,
        )
    ):
        raise ValueError("candidate validation decision is not release-eligible")
    return root, decision, digest


def _positive_probability(outputs: list[Any]) -> Any:
    import numpy as np

    if len(outputs) < 2:
        raise ValueError("converted ONNX classifier probability output is missing")
    probabilities = np.asarray(outputs[1], dtype=np.float64)
    if probabilities.ndim != 2 or probabilities.shape[1] != 2:
        raise ValueError("converted ONNX probability output must have shape [N,2]")
    return probabilities[:, 1]


def _runtime_session(model_bytes: bytes) -> Any:
    import onnxruntime as ort

    options = ort.SessionOptions()
    options.execution_mode = ort.ExecutionMode.ORT_SEQUENTIAL
    options.intra_op_num_threads = 1
    options.inter_op_num_threads = 1
    options.enable_mem_pattern = False
    return ort.InferenceSession(
        model_bytes,
        sess_options=options,
        providers=["CPUExecutionProvider"],
    )


def _benchmark(session: Any, features: Any, policy: XGBoostTrainingPolicy) -> dict[str, Any]:
    import numpy as np

    input_name = session.get_inputs()[0].name
    samples = np.asarray(features, dtype=np.float32)
    for index in range(policy.benchmark_warmup):
        sample = samples[index % len(samples) : index % len(samples) + 1]
        session.run(None, {input_name: sample})
    latencies: list[float] = []
    for index in range(policy.benchmark_iterations):
        sample = samples[index % len(samples) : index % len(samples) + 1]
        started = time.perf_counter_ns()
        session.run(None, {input_name: sample})
        latencies.append((time.perf_counter_ns() - started) / 1_000_000)
    rss_mb = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024
    architecture = platform.machine().strip().lower()
    result = {
        "architecture": architecture,
        "provider": "CPUExecutionProvider",
        "input_batch_size": 1,
        "warmup_iterations": policy.benchmark_warmup,
        "measured_iterations": policy.benchmark_iterations,
        "latency_ms": {
            "mean": round(float(np.mean(latencies)), 6),
            "p50": round(float(np.percentile(latencies, 50)), 6),
            "p95": round(float(np.percentile(latencies, 95)), 6),
            "maximum": round(max(latencies), 6),
        },
        "process_max_rss_mb": round(rss_mb, 3),
        "gates": {
            "required_release_architectures": sorted(
                policy.required_release_architectures
            ),
            "maximum_p95_latency_ms": policy.maximum_p95_latency_ms,
            "maximum_rss_mb": policy.maximum_rss_mb,
        },
    }
    if architecture not in policy.required_release_architectures:
        raise ValueError("benchmark architecture is not release-approved")
    if result["latency_ms"]["p95"] > policy.maximum_p95_latency_ms:
        raise ValueError("ONNX p95 latency exceeds release gate")
    if rss_mb > policy.maximum_rss_mb:
        raise ValueError("ONNX process RSS exceeds release gate")
    return result


def _write_directory(root: Path, job_id: str, files: dict[str, bytes]) -> Path:
    final = root / job_id
    if final.exists():
        raise ValueError(f"immutable output already exists: {root.name}/{job_id}")
    staging = root / ".staging" / f"{job_id}-{uuid.uuid4()}"
    staging.mkdir(parents=True, mode=0o750)
    try:
        for name, payload in files.items():
            write_exclusive(staging / name, payload)
        final.parent.mkdir(parents=True, exist_ok=True)
        os.replace(staging, final)
        os.chmod(final, 0o555)
        return final
    except Exception:
        shutil.rmtree(staging, ignore_errors=True)
        raise


def convert_validate_and_benchmark(config: ConverterWorkerConfig) -> dict[str, Any]:
    policy = load_xgboost_policy(config.policy_path)
    validated_root, validation, validation_digest = _validated_decision(config)
    site_public_key = load_public_key(config.site_public_key_path)
    trainer_public_key = load_public_key(config.trainer_public_key_path)
    candidate = verify_candidate_package(
        validated_root,
        trainer_public_key=trainer_public_key,
        trainer_key_id=config.trainer_key_id,
        policy=policy,
        expected_job_id=config.job_id,
        expected_tenant_id=config.tenant_id,
        expected_site_id=config.site_id,
    )
    if validation.get("candidate_id") != candidate.manifest["candidate_id"]:
        raise ValueError("validation decision candidate identity mismatch")
    if validation.get("candidate_manifest_sha256") != candidate.manifest_digest:
        raise ValueError("validation decision candidate digest mismatch")
    data = verify_training_input(
        inbox_root=config.inbox_root,
        job_id=config.job_id,
        site_public_key=site_public_key,
        site_key_id=config.site_key_id,
        expected_tenant_id=config.tenant_id,
        expected_site_id=config.site_id,
        feature_contract_registry=FeatureContractRegistry(config.feature_contract_dir),
        policy=policy,
    )
    if data.split_manifest != candidate.manifest["training"]["split"]:
        raise ValueError("converter holdout lineage mismatch")
    train_assets = set(data.split_manifest["train_asset_ids"])
    validation_assets = set(data.split_manifest["validation_asset_ids"])
    if not train_assets or not validation_assets or train_assets & validation_assets:
        raise ValueError("converter requires an asset-disjoint holdout")

    import numpy as np
    import onnx
    import onnxruntime as ort
    import onnxmltools
    import xgboost as xgb
    from onnxmltools.convert.common.data_types import FloatTensorType

    booster = xgb.Booster()
    booster.load_model(bytearray(candidate.artifact_bytes))
    if booster.feature_names != list(data.feature_names):
        raise ValueError("source XGBoost feature names do not match feature contract")
    holdout = np.asarray(data.validation_features, dtype=np.float32)
    source = np.asarray(
        booster.predict(
            xgb.DMatrix(holdout, feature_names=list(data.feature_names))
        ),
        dtype=np.float64,
    )
    conversion_booster = xgb.Booster()
    conversion_booster.load_model(bytearray(candidate.artifact_bytes))
    # onnxmltools requires positional f0..fN split names. The signed semantic
    # ordering was checked above and is retained in the ONNX metadata contract.
    conversion_booster.feature_names = None
    model = onnxmltools.convert_xgboost(
        conversion_booster,
        initial_types=[("features", FloatTensorType([None, data.feature_count]))],
        target_opset=policy.target_opset,
    )
    metadata = {
        "feature_contract_id": candidate.manifest["feature_contract_id"],
        "sensel.candidate_id": candidate.manifest["candidate_id"],
        "sensel.candidate_version": candidate.manifest["candidate_version"],
        "sensel.feature_contract_id": candidate.manifest["feature_contract_id"],
        "sensel.feature_contract_definition_sha256": candidate.manifest[
            "feature_contract_definition_sha256"
        ],
        "sensel.source_ubjson_sha256": candidate.manifest["artifact"]["sha256"],
        "sensel.training_policy_definition_sha256": policy.definition_sha256,
    }
    del model.metadata_props[:]
    for key, value in sorted(metadata.items()):
        item = model.metadata_props.add()
        item.key = key
        item.value = str(value)
    onnx.checker.check_model(model, full_check=True)
    onnx_bytes = model.SerializeToString(deterministic=True)
    if not onnx_bytes or len(onnx_bytes) > policy.maximum_onnx_bytes:
        raise ValueError("converted ONNX artifact size is outside policy")

    session = _runtime_session(onnx_bytes)
    inputs = session.get_inputs()
    outputs = session.get_outputs()
    if len(inputs) != 1 or inputs[0].name != "features" or inputs[0].shape != [None, data.feature_count]:
        raise ValueError("converted ONNX input contract is incompatible")
    converted = _positive_probability(session.run(None, {"features": holdout}))
    absolute = np.abs(source - converted)
    relative = absolute / np.maximum(np.abs(source), 1e-12)
    parity = {
        "holdout_sample_count": len(data.validation_labels),
        "source_runtime": {"name": "xgboost", "version": xgb.__version__},
        "target_runtime": {"name": "onnxruntime", "version": ort.__version__},
        "maximum_absolute_probability_error": round(float(np.max(absolute)), 12),
        "maximum_relative_probability_error": round(float(np.max(relative)), 12),
        "gates": {
            "maximum_absolute_probability_error": policy.maximum_absolute_probability_error,
            "maximum_relative_probability_error": policy.maximum_relative_probability_error,
        },
    }
    if np.max(absolute) > policy.maximum_absolute_probability_error:
        raise ValueError("ONNX prediction absolute parity gate failed")
    if np.max(relative) > policy.maximum_relative_probability_error:
        raise ValueError("ONNX prediction relative parity gate failed")
    benchmark = _benchmark(session, holdout, policy)

    onnx_digest = sha256_bytes(onnx_bytes)
    identity = {
        "job_id": config.job_id,
        "candidate_id": candidate.manifest["candidate_id"],
        "candidate_manifest_sha256": candidate.manifest_digest,
        "validation_sha256": validation_digest,
        "onnx_sha256": onnx_digest,
        "policy_definition_sha256": policy.definition_sha256,
        "architecture": benchmark["architecture"],
    }
    conversion_id = "conversion-" + sha256_bytes(canonical_json(identity)).removeprefix(
        "sha256:"
    )
    manifest: dict[str, Any] = {
        "schema_version": CONVERSION_SCHEMA,
        "conversion_id": conversion_id,
        "job_id": config.job_id,
        "candidate_id": candidate.manifest["candidate_id"],
        "tenant_id": config.tenant_id,
        "site_id": config.site_id,
        "status": "technically_validated",
        "source": {
            "format": "ubj",
            "candidate_manifest_sha256": candidate.manifest_digest,
            "artifact_sha256": candidate.manifest["artifact"]["sha256"],
            "validation_decision_sha256": validation_digest,
        },
        "artifact": {
            "path": "model.onnx",
            "media_type": "application/onnx",
            "sha256": onnx_digest,
            "size_bytes": len(onnx_bytes),
            "opset": policy.target_opset,
        },
        "interface": {
            "input_name": "features",
            "input_shape": [None, data.feature_count],
            "input_element_type": "float32",
            "output_index": 1,
            "output_name": outputs[1].name,
            "output_shape": [None, 2],
            "positive_class_index": 1,
        },
        "feature_contract": {
            "id": candidate.manifest["feature_contract_id"],
            "definition_sha256": candidate.manifest[
                "feature_contract_definition_sha256"
            ],
        },
        "holdout": data.split_manifest,
        "prediction_parity": parity,
        "arm_benchmark": benchmark,
        "conversion_runtime": {
            "onnxmltools": onnxmltools.__version__,
            "onnx": onnx.__version__,
        },
        "release": {
            "approved": False,
            "signed": False,
            "automatic_release_allowed": False,
            "requires_manual_approval": True,
        },
        "activation": {"performed": False, "automatic_activation_allowed": False},
        "converted_at": datetime.now(timezone.utc).isoformat(),
    }
    manifest_bytes = canonical_json(manifest) + b"\n"
    manifest_digest = sha256_bytes(manifest_bytes)
    audit_bytes = canonical_json(
        {"algorithm": "SHA-256", "sha256": manifest_digest}
    ) + b"\n"
    _write_directory(
        config.conversion_root,
        config.job_id,
        {
            "model.onnx": onnx_bytes,
            "conversion.json": manifest_bytes,
            "conversion.sha256": audit_bytes,
        },
    )
    approval_bundle = {
        "schema_version": APPROVAL_BUNDLE_SCHEMA,
        "job_id": config.job_id,
        "candidate_id": candidate.manifest["candidate_id"],
        "conversion_id": conversion_id,
        "tenant_id": config.tenant_id,
        "site_id": config.site_id,
        "technical_status": "technically_validated",
        "conversion_manifest_sha256": manifest_digest,
        "onnx_artifact_sha256": onnx_digest,
        "architecture": benchmark["architecture"],
        "candidate_version": candidate.manifest["candidate_version"],
        "feature_contract_id": candidate.manifest["feature_contract_id"],
        "model_bytes_in_bundle": False,
        "activation_performed": False,
    }
    bundle_bytes = canonical_json(approval_bundle) + b"\n"
    _write_directory(
        config.approval_bundle_root,
        config.job_id,
        {
            "approval-bundle.json": bundle_bytes,
            "approval-bundle.sha256": canonical_json(
                {"algorithm": "SHA-256", "sha256": sha256_bytes(bundle_bytes)}
            )
            + b"\n",
        },
    )
    return manifest


def main() -> None:
    result = convert_validate_and_benchmark(ConverterWorkerConfig.from_env())
    print(
        json.dumps(
            {
                "conversion_id": result["conversion_id"],
                "candidate_id": result["candidate_id"],
                "status": result["status"],
                "architecture": result["arm_benchmark"]["architecture"],
                "release_signed": False,
                "activation_performed": False,
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
