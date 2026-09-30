"""Signed-file trainer boundary; trainers never receive the Site database."""

from __future__ import annotations

import os
import re
import shutil
import uuid
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from sensel_site.lineage import canonical_json, sha256_bytes, verify_dataset_export
from sensel_site.signed_documents import detached_signature, verify_detached_document
from sensel_site.store import SiteStore
from sensel_site.training_policy import XGBoostTrainingPolicy

ALGORITHMS = {"xgboost"}
LOCAL_ONLY_ALGORITHMS = {"isolation-forest"}
_MODEL_IDENTITY = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")


def _write(path: Path, payload: bytes) -> None:
    descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o444)
    try:
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


class TrainerBoundary:
    def __init__(
        self,
        store: SiteStore,
        *,
        tenant_id: str,
        site_id: str,
        inbox_root: str | Path,
        public_key,
        signing_key: Ed25519PrivateKey,
        signing_key_id: str,
        training_policy: XGBoostTrainingPolicy,
    ) -> None:
        self.store = store
        self.tenant_id = tenant_id
        self.site_id = site_id
        self.inbox_root = Path(inbox_root)
        self.public_key = public_key
        self.signing_key = signing_key
        self.signing_key_id = signing_key_id
        self.training_policy = training_policy

    def prepare_job(
        self,
        *,
        dataset_id: str,
        algorithm: str,
        model_id: str,
        base_model_version: str,
        expected_feature_contract_id: str,
    ) -> tuple[dict[str, Any], bool]:
        normalized_algorithm = algorithm.strip().lower()
        if normalized_algorithm in LOCAL_ONLY_ALGORITHMS:
            raise ValueError("Isolation Forest remains a local baseline and is not federated")
        if normalized_algorithm == "tiny-lstm":
            raise ValueError(
                "Tiny LSTM trainer is blocked until full sequence materialization is available"
            )
        if normalized_algorithm not in ALGORITHMS:
            raise ValueError("unsupported Site trainer algorithm")
        if not all(
            _MODEL_IDENTITY.fullmatch(value.strip())
            for value in (model_id, base_model_version, expected_feature_contract_id)
        ):
            raise ValueError("model, base version or feature contract identity is invalid")
        dataset = self.store.get_dataset(dataset_id)
        export_path = dataset.get("export_path")
        if not export_path:
            raise ValueError("dataset must be signed/exported before trainer handoff")
        manifest = verify_dataset_export(
            export_path,
            public_key=self.public_key,
            expected_tenant_id=self.tenant_id,
            expected_site_id=self.site_id,
            expected_key_id=self.signing_key_id,
        )
        if manifest["feature_contract_id"] != expected_feature_contract_id:
            raise ValueError("trainer feature contract mismatch")
        if manifest["samples"]["contains_raw_packets"]:
            raise ValueError("raw packet datasets cannot cross the trainer boundary")

        identity = {
            "dataset_id": dataset_id,
            "algorithm": normalized_algorithm,
            "model_id": model_id.strip(),
            "base_model_version": base_model_version.strip(),
            "feature_contract_id": expected_feature_contract_id.strip(),
            "feature_contract_definition_sha256": manifest[
                "feature_contract_definition_sha256"
            ],
            "dataset_samples_sha256": manifest["samples"]["sha256"],
            "training_policy_id": self.training_policy.policy_id,
            "training_policy_version": self.training_policy.version,
            "training_policy_definition_sha256": (
                self.training_policy.definition_sha256
            ),
        }
        job_id = "trainer-" + sha256_bytes(canonical_json(identity)).removeprefix(
            "sha256:"
        )
        existing_path = self.inbox_root / job_id
        if existing_path.is_dir():
            if existing_path.is_symlink():
                raise ValueError("existing trainer job must not be a symlink")
            request, request_digest = verify_detached_document(
                existing_path / "request.json",
                existing_path / "request.sig",
                public_key=self.public_key,
                expected_key_id=self.signing_key_id,
            )
            if request.get("job_id") != job_id or any(
                request.get(name) != value for name, value in identity.items()
            ):
                raise ValueError("existing trainer job request conflicts with lineage")
            copied_manifest = verify_dataset_export(
                existing_path / "dataset",
                public_key=self.public_key,
                expected_tenant_id=self.tenant_id,
                expected_site_id=self.site_id,
                expected_key_id=self.signing_key_id,
            )
            if (
                copied_manifest.get("dataset_id") != dataset_id
                or copied_manifest["samples"].get("sha256")
                != manifest["samples"]["sha256"]
            ):
                raise ValueError("existing trainer job dataset conflicts with lineage")
            self.store.save_trainer_job(
                request,
                request_digest=request_digest,
                inbox_path=str(existing_path),
            )
            return request, False

        # Deterministic for crash recovery and idempotent inbox reconstruction.
        created_at = str(manifest["created_at"])
        request: dict[str, Any] = {
            "schema_version": "sensel.site.trainer-request.v1",
            "job_id": job_id,
            "tenant_id": self.tenant_id,
            "site_id": self.site_id,
            **identity,
            "input": {
                "manifest": "dataset/manifest.json",
                "samples": "dataset/samples.jsonl",
                "signature": "dataset/manifest.sig",
                "read_only": True,
            },
            "output": {
                "channel": "signed-candidate-outbox",
                "job_relative_path": job_id,
                "network_access_required": False,
                "candidate_requires_separate_validation": True,
                "automatic_activation_allowed": False,
            },
            "created_at": created_at,
            "training_policy": {
                "policy_id": self.training_policy.policy_id,
                "version": self.training_policy.version,
                "definition_sha256": self.training_policy.definition_sha256,
            },
        }
        request_bytes = canonical_json(request)
        signed = detached_signature(
            request_bytes,
            private_key=self.signing_key,
            key_id=self.signing_key_id,
        )
        staging = self.inbox_root / ".staging" / f"{job_id}-{uuid.uuid4()}"
        staging.mkdir(parents=True, mode=0o750)
        dataset_target = staging / "dataset"
        dataset_target.mkdir(mode=0o750)
        source = Path(export_path)
        for filename in ("manifest.json", "manifest.sig", "samples.jsonl"):
            shutil.copyfile(source / filename, dataset_target / filename)
            os.chmod(dataset_target / filename, 0o444)
        _write(staging / "request.json", request_bytes + b"\n")
        _write(staging / "request.sig", canonical_json(signed) + b"\n")
        os.chmod(dataset_target, 0o555)
        final = self.inbox_root / job_id
        final.parent.mkdir(parents=True, exist_ok=True)
        os.replace(staging, final)
        os.chmod(final, 0o555)
        request_digest = sha256_bytes(request_bytes)
        created = self.store.save_trainer_job(
            request,
            request_digest=request_digest,
            inbox_path=str(final),
        )
        return request, created
