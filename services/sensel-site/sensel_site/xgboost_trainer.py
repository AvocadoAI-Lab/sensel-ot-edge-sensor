"""Offline XGBoost trainer that emits a signed, non-activatable candidate."""

from __future__ import annotations

import json
import os
import shutil
import uuid
from datetime import datetime, timezone
from typing import Any

from sensel_site.candidate_contract import (
    CANDIDATE_MEDIA_TYPE,
    CANDIDATE_SCHEMA,
    verify_candidate_package,
)
from sensel_site.feature_contracts import FeatureContractRegistry
from sensel_site.lineage import (
    canonical_json,
    load_private_key,
    load_public_key,
    sha256_bytes,
)
from sensel_site.model_metrics import binary_metrics
from sensel_site.signed_documents import (
    encode_embedded_signed_document,
    write_exclusive,
)
from sensel_site.training_data import verify_training_input
from sensel_site.training_policy import load_xgboost_policy
from sensel_site.worker_config import TrainerWorkerConfig


def train_signed_candidate(config: TrainerWorkerConfig) -> dict[str, Any]:
    policy = load_xgboost_policy(config.policy_path)
    site_public_key = load_public_key(config.site_public_key_path)
    trainer_private_key = load_private_key(config.trainer_private_key_path)
    final = config.candidate_root / config.job_id
    if final.is_dir():
        return verify_candidate_package(
            final,
            trainer_public_key=trainer_private_key.public_key(),
            trainer_key_id=config.trainer_key_id,
            policy=policy,
            expected_job_id=config.job_id,
            expected_tenant_id=config.tenant_id,
            expected_site_id=config.site_id,
        ).manifest

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
    import numpy as np
    import xgboost as xgb

    train_features = np.asarray(data.train_features, dtype=np.float32)
    train_labels = np.asarray(data.train_labels, dtype=np.float32)
    validation_features = np.asarray(data.validation_features, dtype=np.float32)
    validation_labels = np.asarray(data.validation_labels, dtype=np.float32)
    dtrain = xgb.DMatrix(
        train_features,
        label=train_labels,
        feature_names=list(data.feature_names),
    )
    dvalidation = xgb.DMatrix(
        validation_features,
        label=validation_labels,
        feature_names=list(data.feature_names),
    )
    booster = xgb.train(
        dict(policy.parameters),
        dtrain,
        num_boost_round=policy.num_boost_round,
        evals=[(dtrain, "train"), (dvalidation, "validation")],
        verbose_eval=False,
    )
    if booster.num_features() != data.feature_count:
        raise ValueError("trained model feature count mismatch")
    if booster.num_boosted_rounds() > policy.maximum_boost_rounds:
        raise ValueError("trained model exceeds maximum boost rounds")
    metrics = {
        "train": binary_metrics(
            data.train_labels,
            tuple(float(value) for value in booster.predict(dtrain)),
        ),
        "validation": binary_metrics(
            data.validation_labels,
            tuple(float(value) for value in booster.predict(dvalidation)),
        ),
    }

    staging = config.candidate_root / ".staging" / f"{config.job_id}-{uuid.uuid4()}"
    staging.mkdir(parents=True, mode=0o750)
    model_path = staging / "model.ubj"
    booster.save_model(model_path)
    os.chmod(model_path, 0o444)
    artifact_bytes = model_path.read_bytes()
    if not artifact_bytes or len(artifact_bytes) > policy.maximum_model_bytes:
        raise ValueError("trained model artifact size is invalid")
    artifact_digest = sha256_bytes(artifact_bytes)
    identity = {
        "job_id": config.job_id,
        "request_sha256": data.request_digest,
        "dataset_id": data.request["dataset_id"],
        "dataset_samples_sha256": data.request["dataset_samples_sha256"],
        "artifact_sha256": artifact_digest,
        "metrics": metrics,
        "split": data.split_manifest,
        "training_policy_definition_sha256": policy.definition_sha256,
    }
    candidate_id = "candidate-" + sha256_bytes(canonical_json(identity)).removeprefix(
        "sha256:"
    )
    candidate_version = (
        f"{data.request['base_model_version']}+site.{candidate_id.removeprefix('candidate-')[:12]}"
    )
    manifest: dict[str, Any] = {
        "schema_version": CANDIDATE_SCHEMA,
        "candidate_id": candidate_id,
        "job_id": config.job_id,
        "tenant_id": config.tenant_id,
        "site_id": config.site_id,
        "algorithm": "xgboost",
        "model_id": data.request["model_id"],
        "base_model_version": data.request["base_model_version"],
        "candidate_version": candidate_version,
        "feature_contract_id": data.request["feature_contract_id"],
        "feature_contract_definition_sha256": data.request[
            "feature_contract_definition_sha256"
        ],
        "feature_count": data.feature_count,
        "dataset": {
            "dataset_id": data.request["dataset_id"],
            "samples_sha256": data.request["dataset_samples_sha256"],
            "request_sha256": data.request_digest,
        },
        "training_policy": {
            "policy_id": policy.policy_id,
            "version": policy.version,
            "definition_sha256": policy.definition_sha256,
        },
        "training": {
            "runtime": "xgboost",
            "runtime_version": xgb.__version__,
            "num_boost_round": booster.num_boosted_rounds(),
            "class_counts": data.class_counts,
            "seed": int(policy.parameters["seed"]),
            "split": data.split_manifest,
        },
        "metrics": metrics,
        "artifact": {
            "path": "model.ubj",
            "media_type": CANDIDATE_MEDIA_TYPE,
            "sha256": artifact_digest,
            "size_bytes": len(artifact_bytes),
        },
        "lifecycle": {
            "state": "candidate",
            "automatic_activation_allowed": False,
            "activation_performed": False,
            "requires_independent_validation": True,
        },
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    document_bytes, signature_bytes, _ = encode_embedded_signed_document(
        manifest,
        private_key=trainer_private_key,
        key_id=config.trainer_key_id,
    )
    write_exclusive(staging / "candidate.json", document_bytes)
    write_exclusive(staging / "candidate.sig", signature_bytes)
    final.parent.mkdir(parents=True, exist_ok=True)
    try:
        os.replace(staging, final)
    except OSError:
        shutil.rmtree(staging, ignore_errors=True)
        if not final.is_dir():
            raise
    os.chmod(final, 0o555)
    return verify_candidate_package(
        final,
        trainer_public_key=trainer_private_key.public_key(),
        trainer_key_id=config.trainer_key_id,
        policy=policy,
        expected_job_id=config.job_id,
        expected_tenant_id=config.tenant_id,
        expected_site_id=config.site_id,
    ).manifest


def main() -> None:
    result = train_signed_candidate(TrainerWorkerConfig.from_env())
    print(
        json.dumps(
            {
                "candidate_id": result["candidate_id"],
                "job_id": result["job_id"],
                "state": result["lifecycle"]["state"],
                "automatic_activation_allowed": False,
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
