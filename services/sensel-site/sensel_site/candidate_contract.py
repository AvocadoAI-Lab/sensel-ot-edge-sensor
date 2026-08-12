"""Signed XGBoost candidate artifact contract; candidates are never activated here."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from sensel_site.lineage import canonical_json, sha256_bytes
from sensel_site.signed_documents import (
    read_regular_file,
    verify_embedded_signed_document,
)
from sensel_site.training_policy import XGBoostTrainingPolicy

CANDIDATE_SCHEMA = "sensel.site.xgboost-candidate.v1"
CANDIDATE_MEDIA_TYPE = "application/x-xgboost-ubj"
_IDENTITY = re.compile(r"^[A-Za-z0-9._:+-]{1,160}$")


@dataclass(frozen=True)
class VerifiedCandidate:
    manifest: dict[str, Any]
    manifest_digest: str
    artifact_path: Path
    artifact_bytes: bytes


def verify_candidate_package(
    candidate_dir: str | Path,
    *,
    trainer_public_key: Ed25519PublicKey,
    trainer_key_id: str,
    policy: XGBoostTrainingPolicy,
    expected_job_id: str,
    expected_tenant_id: str,
    expected_site_id: str,
) -> VerifiedCandidate:
    root = Path(candidate_dir)
    if root.is_symlink() or not root.is_dir():
        raise ValueError("candidate package is not a regular directory")
    manifest, manifest_digest = verify_embedded_signed_document(
        root / "candidate.json",
        root / "candidate.sig",
        public_key=trainer_public_key,
        expected_key_id=trainer_key_id,
    )
    candidate_id = str(manifest.get("candidate_id") or "")
    if (
        manifest.get("schema_version") != CANDIDATE_SCHEMA
        or not candidate_id.startswith("candidate-")
        or len(candidate_id) != 74
    ):
        raise ValueError("candidate schema/identity is invalid")
    if manifest.get("job_id") != expected_job_id or manifest.get("algorithm") != "xgboost":
        raise ValueError("candidate job/algorithm mismatch")
    if not all(
        _IDENTITY.fullmatch(str(manifest.get(name) or ""))
        for name in ("model_id", "base_model_version", "candidate_version")
    ):
        raise ValueError("candidate model identity/version is invalid")
    if (manifest.get("tenant_id"), manifest.get("site_id")) != (
        expected_tenant_id,
        expected_site_id,
    ):
        raise ValueError("candidate Site scope mismatch")
    expected_policy = {
        "policy_id": policy.policy_id,
        "version": policy.version,
        "definition_sha256": policy.definition_sha256,
    }
    if manifest.get("training_policy") != expected_policy:
        raise ValueError("candidate training policy mismatch")
    lifecycle = manifest.get("lifecycle")
    if not isinstance(lifecycle, dict) or any(
        (
            lifecycle.get("state") != "candidate",
            lifecycle.get("automatic_activation_allowed") is not False,
            lifecycle.get("activation_performed") is not False,
            lifecycle.get("requires_independent_validation") is not True,
        )
    ):
        raise ValueError("candidate lifecycle violates no-activation policy")
    artifact = manifest.get("artifact")
    if (
        not isinstance(artifact, dict)
        or artifact.get("path") != "model.ubj"
        or artifact.get("media_type") != CANDIDATE_MEDIA_TYPE
    ):
        raise ValueError("candidate artifact contract is invalid")
    artifact_bytes = read_regular_file(
        root / "model.ubj",
        maximum_bytes=policy.maximum_model_bytes,
    )
    if len(artifact_bytes) != int(artifact.get("size_bytes", -1)):
        raise ValueError("candidate artifact size mismatch")
    if sha256_bytes(artifact_bytes) != artifact.get("sha256"):
        raise ValueError("candidate artifact digest mismatch")
    dataset = manifest.get("dataset")
    if not isinstance(dataset, dict) or not isinstance(manifest.get("metrics"), dict):
        raise ValueError("candidate lineage/metrics contract is invalid")
    identity = {
        "job_id": expected_job_id,
        "request_sha256": dataset.get("request_sha256"),
        "dataset_id": dataset.get("dataset_id"),
        "dataset_samples_sha256": dataset.get("samples_sha256"),
        "artifact_sha256": artifact.get("sha256"),
        "metrics": manifest["metrics"],
        "split": manifest.get("training", {}).get("split"),
        "training_policy_definition_sha256": policy.definition_sha256,
    }
    expected_candidate_id = "candidate-" + sha256_bytes(
        canonical_json(identity)
    ).removeprefix("sha256:")
    if candidate_id != expected_candidate_id:
        raise ValueError("candidate identity does not match signed lineage")
    expected_version = (
        f"{manifest.get('base_model_version')}+site."
        f"{candidate_id.removeprefix('candidate-')[:12]}"
    )
    if manifest.get("candidate_version") != expected_version:
        raise ValueError("candidate version does not match signed identity")
    return VerifiedCandidate(
        manifest=manifest,
        manifest_digest=manifest_digest,
        artifact_path=root / "model.ubj",
        artifact_bytes=artifact_bytes,
    )
