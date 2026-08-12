"""Signed-file trainer boundary; trainers never receive the Site database."""

from __future__ import annotations

import base64
import json
import os
import shutil
import uuid
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from sensel_site.lineage import canonical_json, sha256_bytes, verify_dataset_export
from sensel_site.store import SiteStore

ALGORITHMS = {"xgboost"}
LOCAL_ONLY_ALGORITHMS = {"isolation-forest"}


def _write(path: Path, payload: bytes) -> None:
    descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o640)
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
    ) -> None:
        self.store = store
        self.tenant_id = tenant_id
        self.site_id = site_id
        self.inbox_root = Path(inbox_root)
        self.public_key = public_key
        self.signing_key = signing_key
        self.signing_key_id = signing_key_id

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
            value.strip()
            for value in (model_id, base_model_version, expected_feature_contract_id)
        ):
            raise ValueError("model, base version and feature contract are required")
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
        }
        job_id = "trainer-" + sha256_bytes(canonical_json(identity)).removeprefix(
            "sha256:"
        )
        existing_path = self.inbox_root / job_id
        if existing_path.is_dir():
            request = json.loads(
                (existing_path / "request.json").read_text(encoding="utf-8")
            )
            self.store.save_trainer_job(
                request,
                request_digest=sha256_bytes(canonical_json(request)),
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
                "directory": "candidate-outbox",
                "network_access_required": False,
                "candidate_requires_separate_validation": True,
            },
            "created_at": created_at,
        }
        request_bytes = canonical_json(request)
        signature = self.signing_key.sign(request_bytes)
        signed = {
            "algorithm": "Ed25519",
            "key_id": self.signing_key_id,
            "signed_sha256": sha256_bytes(request_bytes),
            "signature": base64.b64encode(signature).decode("ascii"),
        }
        staging = self.inbox_root / ".staging" / f"{job_id}-{uuid.uuid4()}"
        dataset_target = staging / "dataset"
        dataset_target.mkdir(parents=True, mode=0o750)
        source = Path(export_path)
        for filename in ("manifest.json", "manifest.sig", "samples.jsonl"):
            shutil.copyfile(source / filename, dataset_target / filename)
            os.chmod(dataset_target / filename, 0o440)
        (staging / "candidate-outbox").mkdir(mode=0o750)
        _write(staging / "request.json", request_bytes + b"\n")
        _write(staging / "request.sig", canonical_json(signed) + b"\n")
        final = self.inbox_root / job_id
        final.parent.mkdir(parents=True, exist_ok=True)
        os.replace(staging, final)
        request_digest = sha256_bytes(request_bytes)
        created = self.store.save_trainer_job(
            request,
            request_digest=request_digest,
            inbox_path=str(final),
        )
        return request, created
