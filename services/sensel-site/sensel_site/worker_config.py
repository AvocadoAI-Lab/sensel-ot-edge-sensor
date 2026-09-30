"""Fail-closed environment configuration for isolated trainer and validator."""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from pathlib import Path

_IDENTITY = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")


def _required(name: str) -> str:
    value = os.getenv(name, "").strip()
    if not value:
        raise ValueError(f"{name} is required")
    return value


def _scope() -> tuple[str, str]:
    tenant_id = _required("SENSEL_SITE_TENANT_ID")
    site_id = _required("SENSEL_SITE_ID")
    if not _IDENTITY.fullmatch(tenant_id) or not _IDENTITY.fullmatch(site_id):
        raise ValueError("trainer/validator Site scope contains invalid characters")
    return tenant_id, site_id


def _key_id(name: str) -> str:
    value = _required(name)
    if not _IDENTITY.fullmatch(value):
        raise ValueError(f"{name} contains invalid characters")
    return value


@dataclass(frozen=True)
class TrainerWorkerConfig:
    tenant_id: str
    site_id: str
    job_id: str
    inbox_root: Path
    candidate_root: Path
    feature_contract_dir: Path
    policy_path: Path
    site_public_key_path: Path
    site_key_id: str
    trainer_private_key_path: Path
    trainer_key_id: str

    @classmethod
    def from_env(cls) -> TrainerWorkerConfig:
        tenant_id, site_id = _scope()
        return cls(
            tenant_id=tenant_id,
            site_id=site_id,
            job_id=_required("SENSEL_SITE_TRAINER_JOB_ID"),
            inbox_root=Path(
                os.getenv("SENSEL_SITE_TRAINER_INBOX_DIR", "/input/trainer-inbox")
            ),
            candidate_root=Path(
                os.getenv("SENSEL_SITE_CANDIDATE_OUTBOX_DIR", "/output/candidates")
            ),
            feature_contract_dir=Path(
                os.getenv("SENSEL_SITE_FEATURE_CONTRACT_DIR", "/app/contracts")
            ),
            policy_path=Path(
                os.getenv(
                    "SENSEL_SITE_TRAINER_POLICY_PATH",
                    "/app/policies/trainer-policy.xgboost-site-v1.json",
                )
            ),
            site_public_key_path=Path(
                os.getenv("SENSEL_SITE_PUBLIC_KEY_PATH", "/run/keys/site-signing.pub.pem")
            ),
            site_key_id=_key_id("SENSEL_SITE_SIGNING_KEY_ID"),
            trainer_private_key_path=Path(
                os.getenv(
                    "SENSEL_SITE_TRAINER_SIGNING_KEY_PATH",
                    "/run/secrets/trainer-signing/signing-key.pem",
                )
            ),
            trainer_key_id=_key_id("SENSEL_SITE_TRAINER_SIGNING_KEY_ID"),
        )


@dataclass(frozen=True)
class ValidatorWorkerConfig:
    tenant_id: str
    site_id: str
    job_id: str
    inbox_root: Path
    candidate_root: Path
    results_root: Path
    feature_contract_dir: Path
    policy_path: Path
    site_public_key_path: Path
    site_key_id: str
    trainer_public_key_path: Path
    trainer_key_id: str

    @classmethod
    def from_env(cls) -> ValidatorWorkerConfig:
        tenant_id, site_id = _scope()
        return cls(
            tenant_id=tenant_id,
            site_id=site_id,
            job_id=_required("SENSEL_SITE_VALIDATOR_JOB_ID"),
            inbox_root=Path(
                os.getenv("SENSEL_SITE_TRAINER_INBOX_DIR", "/input/trainer-inbox")
            ),
            candidate_root=Path(
                os.getenv("SENSEL_SITE_CANDIDATE_OUTBOX_DIR", "/input/candidates")
            ),
            results_root=Path(
                os.getenv("SENSEL_SITE_VALIDATION_RESULTS_DIR", "/output/validation")
            ),
            feature_contract_dir=Path(
                os.getenv("SENSEL_SITE_FEATURE_CONTRACT_DIR", "/app/contracts")
            ),
            policy_path=Path(
                os.getenv(
                    "SENSEL_SITE_TRAINER_POLICY_PATH",
                    "/app/policies/trainer-policy.xgboost-site-v1.json",
                )
            ),
            site_public_key_path=Path(
                os.getenv("SENSEL_SITE_PUBLIC_KEY_PATH", "/run/keys/site-signing.pub.pem")
            ),
            site_key_id=_key_id("SENSEL_SITE_SIGNING_KEY_ID"),
            trainer_public_key_path=Path(
                os.getenv(
                    "SENSEL_SITE_TRAINER_PUBLIC_KEY_PATH",
                    "/run/keys/trainer-signing.pub.pem",
                )
            ),
            trainer_key_id=_key_id("SENSEL_SITE_TRAINER_SIGNING_KEY_ID"),
        )


@dataclass(frozen=True)
class ConverterWorkerConfig:
    tenant_id: str
    site_id: str
    job_id: str
    inbox_root: Path
    validation_root: Path
    conversion_root: Path
    approval_bundle_root: Path
    feature_contract_dir: Path
    policy_path: Path
    site_public_key_path: Path
    site_key_id: str
    trainer_public_key_path: Path
    trainer_key_id: str

    @classmethod
    def from_env(cls) -> ConverterWorkerConfig:
        tenant_id, site_id = _scope()
        return cls(
            tenant_id=tenant_id,
            site_id=site_id,
            job_id=_required("SENSEL_SITE_CONVERTER_JOB_ID"),
            inbox_root=Path(os.getenv("SENSEL_SITE_TRAINER_INBOX_DIR", "/input/trainer-inbox")),
            validation_root=Path(
                os.getenv("SENSEL_SITE_VALIDATION_RESULTS_DIR", "/input/validation")
            ),
            conversion_root=Path(
                os.getenv("SENSEL_SITE_CONVERSION_RESULTS_DIR", "/output/conversion")
            ),
            approval_bundle_root=Path(
                os.getenv("SENSEL_SITE_APPROVAL_BUNDLE_DIR", "/output/approval-bundles")
            ),
            feature_contract_dir=Path(
                os.getenv("SENSEL_SITE_FEATURE_CONTRACT_DIR", "/app/contracts")
            ),
            policy_path=Path(
                os.getenv(
                    "SENSEL_SITE_TRAINER_POLICY_PATH",
                    "/app/policies/trainer-policy.xgboost-site-v1.json",
                )
            ),
            site_public_key_path=Path(
                os.getenv("SENSEL_SITE_PUBLIC_KEY_PATH", "/run/keys/site-signing.pub.pem")
            ),
            site_key_id=_key_id("SENSEL_SITE_SIGNING_KEY_ID"),
            trainer_public_key_path=Path(
                os.getenv(
                    "SENSEL_SITE_TRAINER_PUBLIC_KEY_PATH",
                    "/run/keys/trainer-signing.pub.pem",
                )
            ),
            trainer_key_id=_key_id("SENSEL_SITE_TRAINER_SIGNING_KEY_ID"),
        )


@dataclass(frozen=True)
class ReleaseSignerConfig:
    tenant_id: str
    site_id: str
    job_id: str
    approval_bundle_root: Path
    manual_approval_path: Path
    release_root: Path
    release_private_key_path: Path
    release_key_id: str

    @classmethod
    def from_env(cls) -> ReleaseSignerConfig:
        tenant_id, site_id = _scope()
        return cls(
            tenant_id=tenant_id,
            site_id=site_id,
            job_id=_required("SENSEL_SITE_RELEASE_JOB_ID"),
            approval_bundle_root=Path(
                os.getenv("SENSEL_SITE_APPROVAL_BUNDLE_DIR", "/input/approval-bundles")
            ),
            manual_approval_path=Path(
                os.getenv("SENSEL_SITE_MANUAL_APPROVAL_PATH", "/input/manual/approval.json")
            ),
            release_root=Path(
                os.getenv("SENSEL_SITE_RELEASE_RESULTS_DIR", "/output/releases")
            ),
            release_private_key_path=Path(
                os.getenv(
                    "SENSEL_SITE_RELEASE_SIGNING_KEY_PATH",
                    "/run/secrets/release-signing/signing-key.pem",
                )
            ),
            release_key_id=_key_id("SENSEL_SITE_RELEASE_SIGNING_KEY_ID"),
        )
