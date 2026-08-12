"""Verification and deterministic split of a signed Site trainer job."""

from __future__ import annotations

import hashlib
import json
import math
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from sensel_site.feature_contracts import FeatureContractRegistry
from sensel_site.lineage import verify_dataset_export
from sensel_site.signed_documents import read_regular_file, verify_detached_document
from sensel_site.training_policy import XGBoostTrainingPolicy

_JOB_ID = re.compile(r"^trainer-[0-9a-f]{64}$")
_SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")


@dataclass(frozen=True)
class PreparedTrainingData:
    request: dict[str, Any]
    request_digest: str
    dataset_manifest: dict[str, Any]
    feature_count: int
    feature_names: tuple[str, ...]
    train_features: tuple[tuple[float, ...], ...]
    train_labels: tuple[int, ...]
    validation_features: tuple[tuple[float, ...], ...]
    validation_labels: tuple[int, ...]
    class_counts: dict[str, int]


def _require_job_directory(root: str | Path, job_id: str) -> Path:
    if not _JOB_ID.fullmatch(job_id):
        raise ValueError("trainer job identity is invalid")
    job = Path(root) / job_id
    if job.is_symlink() or not job.is_dir():
        raise ValueError("trainer job input is not a regular directory")
    return job


def _split_indices(
    records: list[dict[str, Any]],
    labels: list[int],
    policy: XGBoostTrainingPolicy,
) -> tuple[list[int], list[int]]:
    seed = int(policy.parameters["seed"])
    train: list[int] = []
    validation: list[int] = []
    for label in (0, 1):
        members = [index for index, value in enumerate(labels) if value == label]
        if len(members) < policy.minimum_per_class:
            raise ValueError("dataset does not meet minimum samples per class")
        ranked = sorted(
            members,
            key=lambda index: hashlib.sha256(
                (
                    f"{seed}:{records[index]['sensor_id']}:"
                    f"{records[index]['episode_id']}"
                ).encode("utf-8")
            ).digest(),
        )
        validation_count = max(
            policy.minimum_validation_per_class,
            round(len(ranked) * policy.validation_fraction),
        )
        validation_count = min(validation_count, len(ranked) - 1)
        validation.extend(ranked[:validation_count])
        train.extend(ranked[validation_count:])
    return sorted(train), sorted(validation)


def verify_training_input(
    *,
    inbox_root: str | Path,
    job_id: str,
    site_public_key: Ed25519PublicKey,
    site_key_id: str,
    expected_tenant_id: str,
    expected_site_id: str,
    feature_contract_registry: FeatureContractRegistry,
    policy: XGBoostTrainingPolicy,
) -> PreparedTrainingData:
    job = _require_job_directory(inbox_root, job_id)
    request, request_digest = verify_detached_document(
        job / "request.json",
        job / "request.sig",
        public_key=site_public_key,
        expected_key_id=site_key_id,
    )
    if request.get("schema_version") != "sensel.site.trainer-request.v1":
        raise ValueError("trainer request schema is unsupported")
    if request.get("job_id") != job_id or request.get("algorithm") != "xgboost":
        raise ValueError("trainer request identity/algorithm mismatch")
    if (request.get("tenant_id"), request.get("site_id")) != (
        expected_tenant_id,
        expected_site_id,
    ):
        raise ValueError("trainer request Site scope mismatch")
    if request.get("input") != {
        "manifest": "dataset/manifest.json",
        "samples": "dataset/samples.jsonl",
        "signature": "dataset/manifest.sig",
        "read_only": True,
    }:
        raise ValueError("trainer request input boundary is invalid")
    output = request.get("output")
    if not isinstance(output, dict) or any(
        (
            output.get("channel") != "signed-candidate-outbox",
            output.get("job_relative_path") != job_id,
            output.get("network_access_required") is not False,
            output.get("candidate_requires_separate_validation") is not True,
            output.get("automatic_activation_allowed") is not False,
        )
    ):
        raise ValueError("trainer request violates candidate isolation policy")
    request_policy = request.get("training_policy")
    expected_policy = {
        "policy_id": policy.policy_id,
        "version": policy.version,
        "definition_sha256": policy.definition_sha256,
    }
    if request_policy != expected_policy:
        raise ValueError("trainer request training policy mismatch")

    dataset_root = job / "dataset"
    if dataset_root.is_symlink() or not dataset_root.is_dir():
        raise ValueError("trainer dataset input is not a regular directory")
    samples_path = dataset_root / "samples.jsonl"
    samples_bytes = read_regular_file(
        samples_path,
        maximum_bytes=policy.maximum_dataset_bytes,
    )
    manifest = verify_dataset_export(
        dataset_root,
        public_key=site_public_key,
        expected_tenant_id=expected_tenant_id,
        expected_site_id=expected_site_id,
        expected_key_id=site_key_id,
    )
    if manifest.get("dataset_id") != request.get("dataset_id"):
        raise ValueError("trainer dataset identity mismatch")
    if manifest["samples"].get("sha256") != request.get("dataset_samples_sha256"):
        raise ValueError("trainer dataset sample digest mismatch")
    if manifest.get("feature_contract_id") != request.get("feature_contract_id"):
        raise ValueError("trainer dataset feature contract mismatch")
    if manifest.get("feature_contract_definition_sha256") != request.get(
        "feature_contract_definition_sha256"
    ):
        raise ValueError("trainer dataset feature definition mismatch")
    if manifest.get("label_source") == "unlabeled":
        raise ValueError("unlabeled datasets cannot be trained")
    if (
        manifest.get("samples", {}).get("contains_raw_packets") is not False
        or manifest.get("samples", {}).get("sequence_materialization")
        != "latest-vector-with-sequence-reference"
    ):
        raise ValueError("dataset materialization is outside trainer boundary")
    contract = feature_contract_registry.require(str(request["feature_contract_id"]))
    if contract.definition_sha256 != manifest["feature_contract_definition_sha256"]:
        raise ValueError("local feature contract definition mismatch")
    if contract.feature_count > policy.maximum_features:
        raise ValueError("feature count exceeds training policy")

    records: list[dict[str, Any]] = []
    features: list[tuple[float, ...]] = []
    labels: list[int] = []
    identities: set[tuple[str, str]] = set()
    for raw_line in samples_bytes.splitlines():
        if not raw_line:
            continue
        try:
            record = json.loads(raw_line)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError("training sample is not valid NDJSON") from exc
        if not isinstance(record, dict):
            raise ValueError("training sample must be an object")
        identity = (str(record.get("sensor_id") or ""), str(record.get("episode_id") or ""))
        if not all(identity) or identity in identities:
            raise ValueError("training sample identity is missing or duplicated")
        identities.add(identity)
        if record.get("feature_contract_id") != contract.contract_id:
            raise ValueError("training sample feature contract mismatch")
        if record.get("label_source") != manifest.get("label_source"):
            raise ValueError("training sample label source mismatch")
        if not _SHA256.fullmatch(str(record.get("episode_payload_sha256") or "")):
            raise ValueError("training sample episode digest is invalid")
        if not _SHA256.fullmatch(str(record.get("sequence_ref") or "")):
            raise ValueError("training sample sequence reference is invalid")
        values = record.get("features")
        if not isinstance(values, list) or len(values) != contract.feature_count:
            raise ValueError("training sample feature vector length mismatch")
        if any(
            isinstance(value, bool)
            or not isinstance(value, (int, float))
            or not math.isfinite(float(value))
            for value in values
        ):
            raise ValueError("training sample feature vector must be finite numeric data")
        records.append(record)
        features.append(tuple(float(value) for value in values))
        labels.append(policy.encode_label(record.get("label")))

    if len(records) != int(manifest.get("sample_count", -1)):
        raise ValueError("training sample count does not match signed manifest")
    if not policy.minimum_samples <= len(records) <= policy.maximum_samples:
        raise ValueError("dataset sample count is outside training policy")
    train_indices, validation_indices = _split_indices(records, labels, policy)
    return PreparedTrainingData(
        request=request,
        request_digest=request_digest,
        dataset_manifest=manifest,
        feature_count=contract.feature_count,
        feature_names=contract.feature_names,
        train_features=tuple(features[index] for index in train_indices),
        train_labels=tuple(labels[index] for index in train_indices),
        validation_features=tuple(features[index] for index in validation_indices),
        validation_labels=tuple(labels[index] for index in validation_indices),
        class_counts={
            "negative": labels.count(0),
            "positive": labels.count(1),
            "train": len(train_indices),
            "validation": len(validation_indices),
        },
    )
