"""Framework-neutral boundary and signed P4-A Site update adapter."""

from __future__ import annotations

import hashlib
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Protocol

from cryptography.exceptions import InvalidSignature

from sensel.federation.v1 import federation_pb2
from sensel_site.lineage import load_private_key, load_public_key, sha256_bytes

_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9@._:+-]{0,159}$")


class FederatedClient(Protocol):
    """P3/P4 adapter seam; P3-A deliberately provides no network implementation."""

    def receive_round(self) -> dict[str, Any] | None: ...

    def submit_candidate(self, manifest: dict[str, Any], artifact: bytes) -> str: ...


def verify_round_spec(
    wire: bytes,
    *,
    coordinator_public_key_path: str | Path,
    coordinator_key_id: str,
    tenant_id: str,
    site_id: str,
    now: datetime | None = None,
) -> federation_pb2.FederationRoundSpec:
    spec = federation_pb2.FederationRoundSpec.FromString(wire)
    signature = bytes(spec.coordinator_signature)
    spec.coordinator_signature = b""
    if spec.coordinator_key_id != coordinator_key_id:
        raise ValueError("FL coordinator key is not trusted")
    try:
        load_public_key(coordinator_public_key_path).verify(
            signature, spec.SerializeToString(deterministic=True)
        )
    except InvalidSignature as exc:
        raise ValueError("FL round signature verification failed") from exc
    current = now or datetime.now(timezone.utc)
    if any(
        (
            spec.tenant_id != tenant_id,
            site_id not in spec.allowed_site_ids,
            spec.strategy != federation_pb2.AGGREGATION_STRATEGY_FEDXGB_BAGGING,
            spec.minimum_clients < 3,
            len(set(spec.allowed_site_ids)) != len(spec.allowed_site_ids),
            spec.starts_at.ToDatetime(tzinfo=timezone.utc) > current,
            spec.deadline_at.ToDatetime(tzinfo=timezone.utc) <= current,
            not all(
                _ID.fullmatch(value)
                for value in (
                    spec.tenant_id,
                    spec.model_id,
                    spec.base_model_version,
                    spec.feature_contract_id,
                    site_id,
                )
            ),
        )
    ):
        raise ValueError("FL round policy is invalid for this Site")
    return spec


def build_signed_site_update(
    spec: federation_pb2.FederationRoundSpec,
    *,
    site_id: str,
    client_id: str,
    dataset_id: str,
    candidate_id: str,
    sample_count: int,
    artifact: bytes,
    site_private_key_path: str | Path,
    site_key_id: str,
    submitted_at: datetime | None = None,
) -> bytes:
    if any(
        (
            site_id not in spec.allowed_site_ids,
            not _ID.fullmatch(client_id),
            not dataset_id.startswith("dataset-") or len(dataset_id) != 72,
            not candidate_id.startswith("candidate-") or len(candidate_id) != 74,
            sample_count < 1,
            not artifact,
            len(artifact) > 8 * 1024 * 1024,
        )
    ):
        raise ValueError("FL Site update input is invalid")
    digest = sha256_bytes(artifact)
    update = federation_pb2.ClientUpdateManifest(
        round_id=spec.round_id,
        site_id=site_id,
        client_id=client_id,
        sample_count=sample_count,
        update=federation_pb2.ArtifactRef(
            uri=f"sensel://sites/{site_id}/federation/{candidate_id}/model.json",
            sha256=digest,
            size_bytes=len(artifact),
            media_type="application/x-xgboost-json",
        ),
        tenant_id=spec.tenant_id,
        feature_contract_id=spec.feature_contract_id,
        base_model_version=spec.base_model_version,
        dataset_id=dataset_id,
        candidate_id=candidate_id,
        client_key_id=site_key_id,
        update_artifact=artifact,
    )
    update.submitted_at.FromDatetime(submitted_at or datetime.now(timezone.utc))
    update.client_signature = load_private_key(site_private_key_path).sign(
        update.SerializeToString(deterministic=True)
    )
    return update.SerializeToString(deterministic=True)


def deterministic_partition_seed(round_id: str, site_id: str) -> int:
    """Stable sandbox seed; no Python hash randomization or global RNG state."""
    return int.from_bytes(hashlib.sha256(f"{round_id}:{site_id}".encode()).digest()[:4], "big")
