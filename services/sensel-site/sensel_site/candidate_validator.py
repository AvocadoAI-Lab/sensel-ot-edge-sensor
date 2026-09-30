"""Independent offline validator with durable validated/quarantine decisions."""

from __future__ import annotations

import json
import math
import os
import re
import shutil
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from sensel_site.candidate_contract import VerifiedCandidate, verify_candidate_package
from sensel_site.feature_contracts import FeatureContractRegistry
from sensel_site.lineage import (
    canonical_json,
    load_public_key,
    sha256_bytes,
)
from sensel_site.model_metrics import binary_metrics
from sensel_site.signed_documents import (
    read_regular_file,
    write_exclusive,
)
from sensel_site.training_data import PreparedTrainingData, verify_training_input
from sensel_site.training_policy import XGBoostTrainingPolicy, load_xgboost_policy
from sensel_site.worker_config import ValidatorWorkerConfig

DECISION_SCHEMA = "sensel.site.candidate-validation.v1"
_JOB_ID = re.compile(r"^trainer-[0-9a-f]{64}$")


def _metrics_match(expected: dict[str, Any], actual: dict[str, Any], tolerance: float) -> None:
    if expected.get("sample_count") != actual.get("sample_count"):
        raise ValueError("candidate metric sample count mismatch")
    if expected.get("confusion_matrix") != actual.get("confusion_matrix"):
        raise ValueError("candidate confusion matrix mismatch")
    for name in ("accuracy", "balanced_accuracy", "logloss"):
        expected_value = expected.get(name)
        actual_value = actual.get(name)
        if not isinstance(expected_value, (int, float)) or not math.isfinite(
            float(expected_value)
        ):
            raise ValueError(f"candidate metric is invalid: {name}")
        if abs(float(expected_value) - float(actual_value)) > tolerance:
            raise ValueError(f"candidate metric recomputation mismatch: {name}")


def _validate_model(
    candidate: VerifiedCandidate,
    data: PreparedTrainingData,
    policy: XGBoostTrainingPolicy,
) -> dict[str, Any]:
    manifest = candidate.manifest
    request = data.request
    comparisons = {
        "model_id": request["model_id"],
        "base_model_version": request["base_model_version"],
        "feature_contract_id": request["feature_contract_id"],
        "feature_contract_definition_sha256": request[
            "feature_contract_definition_sha256"
        ],
    }
    for name, expected in comparisons.items():
        if manifest.get(name) != expected:
            raise ValueError(f"candidate provenance mismatch: {name}")
    dataset = manifest.get("dataset")
    if not isinstance(dataset, dict) or dataset != {
        "dataset_id": request["dataset_id"],
        "samples_sha256": request["dataset_samples_sha256"],
        "request_sha256": data.request_digest,
    }:
        raise ValueError("candidate dataset provenance mismatch")
    if manifest.get("feature_count") != data.feature_count:
        raise ValueError("candidate feature count mismatch")

    import numpy as np
    import xgboost as xgb

    training = manifest.get("training")
    if not isinstance(training, dict) or any(
        (
            training.get("runtime") != "xgboost",
            training.get("runtime_version") != xgb.__version__,
            training.get("class_counts") != data.class_counts,
            training.get("seed") != int(policy.parameters["seed"]),
            training.get("split") != data.split_manifest,
        )
    ):
        raise ValueError("candidate XGBoost training metadata is not validator-approved")
    booster = xgb.Booster()
    booster.load_model(bytearray(candidate.artifact_bytes))
    if booster.num_features() != data.feature_count:
        raise ValueError("candidate model feature count mismatch")
    if booster.num_boosted_rounds() > policy.maximum_boost_rounds:
        raise ValueError("candidate model exceeds maximum boost rounds")
    if training.get("num_boost_round") != booster.num_boosted_rounds():
        raise ValueError("candidate boost round metadata mismatch")

    dtrain = xgb.DMatrix(
        np.asarray(data.train_features, dtype=np.float32),
        label=np.asarray(data.train_labels, dtype=np.float32),
        feature_names=list(data.feature_names),
    )
    dvalidation = xgb.DMatrix(
        np.asarray(data.validation_features, dtype=np.float32),
        label=np.asarray(data.validation_labels, dtype=np.float32),
        feature_names=list(data.feature_names),
    )
    actual = {
        "train": binary_metrics(
            data.train_labels,
            tuple(float(value) for value in booster.predict(dtrain)),
        ),
        "validation": binary_metrics(
            data.validation_labels,
            tuple(float(value) for value in booster.predict(dvalidation)),
        ),
    }
    expected_metrics = manifest.get("metrics")
    if not isinstance(expected_metrics, dict):
        raise ValueError("candidate metrics are missing")
    _metrics_match(expected_metrics.get("train", {}), actual["train"], policy.metric_tolerance)
    _metrics_match(
        expected_metrics.get("validation", {}),
        actual["validation"],
        policy.metric_tolerance,
    )
    validation = actual["validation"]
    if validation["balanced_accuracy"] < policy.minimum_balanced_accuracy:
        raise ValueError("candidate balanced accuracy is below validation gate")
    if validation["logloss"] > policy.maximum_logloss:
        raise ValueError("candidate logloss exceeds validation gate")
    return actual


def _observed_candidate_digests(root: Path, policy: XGBoostTrainingPolicy) -> dict[str, str]:
    limits = {
        "candidate.json": 1_048_576,
        "candidate.sig": 16_384,
        "model.ubj": policy.maximum_model_bytes,
    }
    observed: dict[str, str] = {}
    for filename, limit in limits.items():
        try:
            observed[filename] = sha256_bytes(
                read_regular_file(root / filename, maximum_bytes=limit)
            )
        except (FileNotFoundError, OSError, ValueError):
            observed[filename] = "unavailable"
    return observed


def _safe_reason(exc: Exception, config: ValidatorWorkerConfig) -> str:
    reason = " ".join(str(exc).split()) or exc.__class__.__name__
    for path in (
        config.inbox_root,
        config.candidate_root,
        config.results_root,
    ):
        reason = reason.replace(str(path), "<boundary>")
    return reason[:512]


def _existing_decision(config: ValidatorWorkerConfig) -> dict[str, Any] | None:
    found: list[dict[str, Any]] = []
    for state in ("validated", "quarantine"):
        root = config.results_root / state / config.job_id
        if root.is_dir():
            payload = read_regular_file(
                root / "validation.json", maximum_bytes=1_048_576
            )
            digest_document = json.loads(
                read_regular_file(root / "validation.sha256", maximum_bytes=4096)
            )
            if digest_document != {
                "algorithm": "SHA-256",
                "sha256": sha256_bytes(payload),
            }:
                raise ValueError("validator decision audit digest mismatch")
            decision = json.loads(payload)
            if (
                not isinstance(decision, dict)
                or decision.get("schema_version") != DECISION_SCHEMA
                or decision.get("job_id") != config.job_id
                or decision.get("status") != state
                or (decision.get("tenant_id"), decision.get("site_id"))
                != (config.tenant_id, config.site_id)
                or decision.get("activation", {}).get("performed") is not False
            ):
                raise ValueError("existing validator decision contract is invalid")
            found.append(decision)
    if len(found) > 1:
        raise ValueError("conflicting validator decisions exist for trainer job")
    return found[0] if found else None


def _write_decision(
    *,
    config: ValidatorWorkerConfig,
    policy: XGBoostTrainingPolicy,
    status: str,
    candidate_id: str,
    candidate_manifest_digest: str,
    observed: dict[str, str],
    metrics: dict[str, Any] | None,
    reason: str,
) -> dict[str, Any]:
    identity = {
        "job_id": config.job_id,
        "candidate_id": candidate_id,
        "status": status,
        "candidate_manifest_sha256": candidate_manifest_digest,
        "observed": observed,
        "policy_definition_sha256": policy.definition_sha256,
    }
    decision_id = "validation-" + sha256_bytes(canonical_json(identity)).removeprefix(
        "sha256:"
    )
    decision: dict[str, Any] = {
        "schema_version": DECISION_SCHEMA,
        "decision_id": decision_id,
        "job_id": config.job_id,
        "candidate_id": candidate_id,
        "tenant_id": config.tenant_id,
        "site_id": config.site_id,
        "status": status,
        "reason": reason,
        "candidate_manifest_sha256": candidate_manifest_digest,
        "observed_artifacts": observed,
        "validation_policy": {
            "policy_id": policy.policy_id,
            "version": policy.version,
            "definition_sha256": policy.definition_sha256,
        },
        "metrics": metrics,
        "activation": {
            "performed": False,
            "automatic_activation_allowed": False,
            "requires_separate_approval_and_distribution": True,
        },
        "validated_at": datetime.now(timezone.utc).isoformat(),
    }
    document_bytes = canonical_json(decision) + b"\n"
    audit_bytes = (
        canonical_json(
            {
                "algorithm": "SHA-256",
                "sha256": sha256_bytes(document_bytes),
            }
        )
        + b"\n"
    )
    staging = config.results_root / ".staging" / f"{config.job_id}-{uuid.uuid4()}"
    staging.mkdir(parents=True, mode=0o750)
    candidate_root = config.candidate_root / config.job_id
    for filename, maximum in (
        ("candidate.json", 1_048_576),
        ("candidate.sig", 16_384),
        ("model.ubj", policy.maximum_model_bytes),
    ):
        try:
            payload = read_regular_file(candidate_root / filename, maximum_bytes=maximum)
        except (FileNotFoundError, OSError, ValueError):
            continue
        write_exclusive(staging / filename, payload)
    write_exclusive(staging / "validation.json", document_bytes)
    write_exclusive(staging / "validation.sha256", audit_bytes)
    final = config.results_root / status / config.job_id
    final.parent.mkdir(parents=True, exist_ok=True)
    try:
        os.replace(staging, final)
    except OSError:
        shutil.rmtree(staging, ignore_errors=True)
        if not final.is_dir():
            raise
    os.chmod(final, 0o555)
    return decision


def validate_or_quarantine(config: ValidatorWorkerConfig) -> dict[str, Any]:
    if not _JOB_ID.fullmatch(config.job_id):
        raise ValueError("validator trainer job identity is invalid")
    policy = load_xgboost_policy(config.policy_path)
    existing = _existing_decision(config)
    if existing:
        return existing
    candidate_root = config.candidate_root / config.job_id
    observed = _observed_candidate_digests(candidate_root, policy)
    candidate_id = ""
    manifest_digest = observed.get("candidate.json", "unavailable")
    try:
        data = verify_training_input(
            inbox_root=config.inbox_root,
            job_id=config.job_id,
            site_public_key=load_public_key(config.site_public_key_path),
            site_key_id=config.site_key_id,
            expected_tenant_id=config.tenant_id,
            expected_site_id=config.site_id,
            feature_contract_registry=FeatureContractRegistry(
                config.feature_contract_dir
            ),
            policy=policy,
        )
        candidate = verify_candidate_package(
            candidate_root,
            trainer_public_key=load_public_key(config.trainer_public_key_path),
            trainer_key_id=config.trainer_key_id,
            policy=policy,
            expected_job_id=config.job_id,
            expected_tenant_id=config.tenant_id,
            expected_site_id=config.site_id,
        )
        candidate_id = candidate.manifest["candidate_id"]
        manifest_digest = candidate.manifest_digest
        metrics = _validate_model(candidate, data, policy)
        return _write_decision(
            config=config,
            policy=policy,
            status="validated",
            candidate_id=candidate_id,
            candidate_manifest_digest=manifest_digest,
            observed=observed,
            metrics=metrics,
            reason="all independent validation gates passed",
        )
    except Exception as exc:  # noqa: BLE001 - failures must become durable quarantine
        return _write_decision(
            config=config,
            policy=policy,
            status="quarantine",
            candidate_id=candidate_id,
            candidate_manifest_digest=manifest_digest,
            observed=observed,
            metrics=None,
            reason=_safe_reason(exc, config),
        )


def main() -> None:
    result = validate_or_quarantine(ValidatorWorkerConfig.from_env())
    print(
        json.dumps(
            {
                "decision_id": result["decision_id"],
                "candidate_id": result["candidate_id"],
                "status": result["status"],
                "activation_performed": False,
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
