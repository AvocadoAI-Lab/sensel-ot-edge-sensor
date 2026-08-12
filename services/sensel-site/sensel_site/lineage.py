"""Immutable dataset lineage creation, export, signing, and verification."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import shutil
import stat
import uuid
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

if TYPE_CHECKING:
    from sensel_site.feature_contracts import FeatureContractRegistry
    from sensel_site.store import SiteStore

RETENTION_POLICIES = {
    "training-short": 30,
    "research": 180,
    "regulated": 365,
}


def canonical_json(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def sha256_bytes(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _write_exclusive(path: Path, value: bytes, mode: int = 0o640) -> None:
    descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, mode)
    try:
        view = memoryview(value)
        while view:
            written = os.write(descriptor, view)
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _write_idempotent(path: Path, value: bytes, mode: int = 0o640) -> None:
    try:
        _write_exclusive(path, value, mode)
    except FileExistsError:
        if path.is_symlink() or not path.is_file() or path.read_bytes() != value:
            raise ValueError(f"immutable export file conflict: {path.name}") from None


def _normalize_timestamp(value: str | None, field: str) -> str | None:
    if value is None:
        return None
    try:
        parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except (AttributeError, ValueError) as exc:
        raise ValueError(f"{field} must be an ISO-8601 timestamp") from exc
    if parsed.tzinfo is None:
        raise ValueError(f"{field} must include a timezone")
    return parsed.astimezone(timezone.utc).isoformat()


def load_private_key(path: Path) -> Ed25519PrivateKey:
    if path.is_symlink():
        raise ValueError("Site signing key must not be a symlink")
    if stat.S_IMODE(path.stat().st_mode) & 0o077:
        raise ValueError("Site signing key permissions must be 0600 or stricter")
    key = serialization.load_pem_private_key(path.read_bytes(), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError("Site signing key must be Ed25519")
    return key


def load_public_key(path: Path) -> Ed25519PublicKey:
    key = serialization.load_pem_public_key(path.read_bytes())
    if not isinstance(key, Ed25519PublicKey):
        raise ValueError("Site verification key must be Ed25519")
    return key


@dataclass(frozen=True)
class DatasetBuildResult:
    dataset_id: str
    manifest: dict[str, Any]
    created: bool


class DatasetLineageService:
    def __init__(
        self,
        store: SiteStore,
        *,
        tenant_id: str,
        site_id: str,
        node_id: str,
        export_root: str | Path,
        signing_key_path: str | Path,
        signing_key_id: str,
        feature_contract_registry: FeatureContractRegistry,
    ) -> None:
        self.store = store
        self.tenant_id = tenant_id
        self.site_id = site_id
        self.node_id = node_id
        self.export_root = Path(export_root)
        self.signing_key_path = Path(signing_key_path)
        self.signing_key_id = signing_key_id.strip()
        self.feature_contract_registry = feature_contract_registry

    def _stage_samples(self, dataset_id: str, samples_bytes: bytes) -> Path:
        pending = self.export_root / ".pending" / dataset_id
        final = self.export_root / dataset_id
        if pending.is_dir() or final.is_dir():
            return pending if pending.is_dir() else final
        staging = self.export_root / ".staging" / f"{dataset_id}-{uuid.uuid4()}"
        staging.mkdir(parents=True, mode=0o750)
        _write_exclusive(staging / "samples.jsonl", samples_bytes)
        self.export_root.mkdir(parents=True, exist_ok=True)
        pending.parent.mkdir(parents=True, exist_ok=True)
        try:
            os.replace(staging, pending)
        except OSError:
            shutil.rmtree(staging, ignore_errors=True)
            if not pending.is_dir() and not final.is_dir():
                raise
        return pending if pending.is_dir() else final

    def create_dataset(
        self,
        *,
        feature_contract_id: str,
        label_source: str,
        retention_class: str,
        started_at: str | None = None,
        ended_at: str | None = None,
        limit: int = 100_000,
    ) -> DatasetBuildResult:
        contract = feature_contract_id.strip()
        if not contract:
            raise ValueError("feature_contract_id is required")
        contract_definition = self.feature_contract_registry.require(contract)
        if retention_class not in RETENTION_POLICIES:
            raise ValueError("unsupported dataset retention class")
        if not 1 <= limit <= 1_000_000:
            raise ValueError("dataset limit must be between 1 and 1000000")
        normalized_started_at = _normalize_timestamp(started_at, "started_at")
        normalized_ended_at = _normalize_timestamp(ended_at, "ended_at")
        if (
            normalized_started_at
            and normalized_ended_at
            and normalized_started_at > normalized_ended_at
        ):
            raise ValueError("dataset time window is inverted")
        rows = self.store.select_dataset_rows(
            tenant_id=self.tenant_id,
            site_id=self.site_id,
            feature_contract_id=contract,
            label_source=label_source,
            started_at=normalized_started_at,
            ended_at=normalized_ended_at,
            limit=limit,
        )
        if not rows:
            raise ValueError("no eligible Site samples for dataset")

        record_refs: list[dict[str, Any]] = []
        encoded_records: list[bytes] = []
        for row in rows:
            exported = {
                key: value for key, value in row.items() if key != "episode_pk"
            }
            encoded = canonical_json(exported)
            encoded_records.append(encoded)
            record_refs.append(
                {
                    "episode_id": row["episode_id"],
                    "sensor_id": row["sensor_id"],
                    "asset_id": row["asset_id"],
                    "ended_at": row["ended_at"],
                    "sequence_ref": row["sequence_ref"],
                    "label_ref": row["label_ref"],
                    "episode_payload_sha256": row["episode_payload_sha256"],
                    "record_sha256": sha256_bytes(encoded),
                }
            )
        samples_bytes = b"\n".join(encoded_records) + b"\n"
        samples_digest = sha256_bytes(samples_bytes)
        identity = {
            "schema_version": "sensel.site.dataset-lineage.v1",
            "tenant_id": self.tenant_id,
            "site_id": self.site_id,
            "feature_contract_id": contract,
            "feature_contract_version": contract_definition.version,
            "feature_contract_definition_sha256": (
                contract_definition.definition_sha256
            ),
            "label_source": label_source,
            "retention_class": retention_class,
            "started_at": normalized_started_at,
            "ended_at": normalized_ended_at,
            "records": record_refs,
            "samples_sha256": samples_digest,
        }
        dataset_id = "dataset-" + hashlib.sha256(canonical_json(identity)).hexdigest()
        try:
            existing = self.store.get_dataset(dataset_id)
            self._stage_samples(dataset_id, samples_bytes)
            return DatasetBuildResult(dataset_id, existing["manifest"], False)
        except LookupError:
            pass

        created_at = datetime.now(timezone.utc)
        retention_days = RETENTION_POLICIES[retention_class]
        manifest = {
            "schema_version": "sensel.site.dataset-lineage.v1",
            "dataset_id": dataset_id,
            "tenant_id": self.tenant_id,
            "site_id": self.site_id,
            "site_node_id": self.node_id,
            "feature_contract_id": contract,
            "feature_contract_version": contract_definition.version,
            "feature_contract_definition_sha256": (
                contract_definition.definition_sha256
            ),
            "label_source": label_source,
            "window": {
                "started_at": normalized_started_at,
                "ended_at": normalized_ended_at,
            },
            "sample_count": len(rows),
            "samples": {
                "path": "samples.jsonl",
                "sha256": samples_digest,
                "media_type": "application/x-ndjson",
                "contains_raw_packets": False,
                "sequence_materialization": "latest-vector-with-sequence-reference",
            },
            "records": record_refs,
            "retention": {
                "class": retention_class,
                "days": retention_days,
                "expires_at": (created_at + timedelta(days=retention_days)).isoformat(),
            },
            "created_at": created_at.isoformat(),
        }
        manifest_digest = sha256_bytes(canonical_json(manifest))
        created = self.store.save_dataset_manifest(
            manifest,
            sample_digest=samples_digest,
            manifest_digest=manifest_digest,
        )
        # Samples are staged at creation and only become trainer-visible after
        # explicit signature/export.
        self._stage_samples(dataset_id, samples_bytes)
        return DatasetBuildResult(dataset_id, manifest, created)

    def export_signed(self, dataset_id: str) -> Path:
        if not self.signing_key_id:
            raise ValueError("SENSEL_SITE_SIGNING_KEY_ID is required for export")
        dataset = self.store.get_dataset(dataset_id)
        manifest = dict(dataset["manifest"])
        pending = self.export_root / ".pending" / dataset_id
        samples_path = pending / "samples.jsonl"
        if not samples_path.is_file():
            final = self.export_root / dataset_id
            if final.is_dir():
                private_key = load_private_key(self.signing_key_path)
                verify_dataset_export(
                    final,
                    public_key=private_key.public_key(),
                    expected_tenant_id=self.tenant_id,
                    expected_site_id=self.site_id,
                    expected_key_id=self.signing_key_id,
                )
                signature_document = json.loads(
                    (final / "manifest.sig").read_text(encoding="utf-8")
                )
                self.store.mark_dataset_exported(
                    dataset_id=dataset_id,
                    export_path=str(final),
                    key_id=self.signing_key_id,
                    signature_b64=str(signature_document["signature"]),
                )
                return final
            raise FileNotFoundError("dataset samples are not staged")
        samples_bytes = samples_path.read_bytes()
        if sha256_bytes(samples_bytes) != manifest["samples"]["sha256"]:
            raise ValueError("staged dataset sample digest mismatch")

        signed_manifest = {
            **manifest,
            "signature": {
                "algorithm": "Ed25519",
                "key_id": self.signing_key_id,
                "signed_fields": "canonical-manifest-without-signature",
            },
        }
        unsigned = canonical_json(manifest)
        signature = load_private_key(self.signing_key_path).sign(unsigned)
        signature_b64 = base64.b64encode(signature).decode("ascii")
        manifest_bytes = canonical_json(signed_manifest) + b"\n"
        signature_bytes = (
            canonical_json(
                {
                    "algorithm": "Ed25519",
                    "key_id": self.signing_key_id,
                    "signature": signature_b64,
                    "signed_sha256": sha256_bytes(unsigned),
                }
            )
            + b"\n"
        )
        _write_idempotent(
            pending / "manifest.json",
            manifest_bytes,
        )
        _write_idempotent(
            pending / "manifest.sig",
            signature_bytes,
        )
        final = self.export_root / dataset_id
        if final.exists():
            raise FileExistsError(f"dataset export already exists: {dataset_id}")
        os.replace(pending, final)
        self.store.mark_dataset_exported(
            dataset_id=dataset_id,
            export_path=str(final),
            key_id=self.signing_key_id,
            signature_b64=signature_b64,
        )
        return final


def verify_dataset_export(
    export_path: str | Path,
    *,
    public_key: Ed25519PublicKey,
    expected_tenant_id: str | None = None,
    expected_site_id: str | None = None,
    expected_key_id: str | None = None,
) -> dict[str, Any]:
    root = Path(export_path)
    manifest_document = json.loads((root / "manifest.json").read_text(encoding="utf-8"))
    signature_document = json.loads((root / "manifest.sig").read_text(encoding="utf-8"))
    signature_meta = manifest_document.pop("signature", None)
    if (
        not isinstance(signature_meta, Mapping)
        or signature_meta.get("algorithm") != "Ed25519"
        or signature_meta.get("signed_fields")
        != "canonical-manifest-without-signature"
        or signature_document.get("algorithm") != "Ed25519"
    ):
        raise ValueError("dataset signature metadata is invalid")
    unsigned = canonical_json(manifest_document)
    if signature_document.get("signed_sha256") != sha256_bytes(unsigned):
        raise ValueError("dataset signed manifest digest mismatch")
    try:
        public_key.verify(
            base64.b64decode(signature_document["signature"], validate=True),
            unsigned,
        )
    except (InvalidSignature, ValueError, KeyError) as exc:
        raise ValueError("dataset signature verification failed") from exc
    if signature_document.get("key_id") != signature_meta.get("key_id"):
        raise ValueError("dataset signature key identity mismatch")
    if expected_key_id and signature_document.get("key_id") != expected_key_id:
        raise ValueError("dataset signature key is not trusted for this boundary")
    if manifest_document.get("schema_version") != "sensel.site.dataset-lineage.v1":
        raise ValueError("dataset lineage schema is unsupported")
    expires_at = datetime.fromisoformat(
        str(manifest_document["retention"]["expires_at"]).replace("Z", "+00:00")
    )
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    if expires_at.astimezone(timezone.utc) < datetime.now(timezone.utc):
        raise ValueError("dataset retention has expired")
    if manifest_document["samples"].get("path") != "samples.jsonl":
        raise ValueError("dataset sample path is unsupported")
    samples_path = root / "samples.jsonl"
    if sha256_bytes(samples_path.read_bytes()) != manifest_document["samples"]["sha256"]:
        raise ValueError("dataset samples digest mismatch")
    if expected_tenant_id and manifest_document["tenant_id"] != expected_tenant_id:
        raise ValueError("dataset tenant scope mismatch")
    if expected_site_id and manifest_document["site_id"] != expected_site_id:
        raise ValueError("dataset site scope mismatch")
    return manifest_document
