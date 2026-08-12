from __future__ import annotations

import hashlib
from datetime import datetime, timedelta, timezone

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from sensel.federation.v1 import federation_pb2
from sensel_site.federation import (
    build_signed_site_update,
    deterministic_partition_seed,
    verify_round_spec,
)


def _private(path, key) -> None:
    path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    path.chmod(0o600)


def _public(path, key) -> None:
    path.write_bytes(
        key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        )
    )


def _spec(key, now: datetime) -> bytes:
    spec = federation_pb2.FederationRoundSpec(
        round_id="round-" + "1" * 64,
        tenant_id="tenant-a",
        model_id="ot-xgb",
        base_model_version="0.1.0",
        feature_contract_id="ot-window-v1",
        strategy=federation_pb2.AGGREGATION_STRATEGY_FEDXGB_BAGGING,
        minimum_clients=3,
        allowed_site_ids=["site-1", "site-2", "site-3"],
        coordinator_key_id="coordinator-key-1",
    )
    spec.starts_at.FromDatetime(now - timedelta(seconds=1))
    spec.deadline_at.FromDatetime(now + timedelta(hours=1))
    spec.coordinator_signature = key.sign(spec.SerializeToString(deterministic=True))
    return spec.SerializeToString(deterministic=True)


def test_signed_round_and_site_update_are_scope_bound(tmp_path) -> None:
    now = datetime(2026, 8, 13, tzinfo=timezone.utc)
    coordinator = Ed25519PrivateKey.generate()
    site = Ed25519PrivateKey.generate()
    coordinator_public = tmp_path / "coordinator.pub.pem"
    site_private = tmp_path / "site.pem"
    _public(coordinator_public, coordinator)
    _private(site_private, site)
    spec = verify_round_spec(
        _spec(coordinator, now),
        coordinator_public_key_path=coordinator_public,
        coordinator_key_id="coordinator-key-1",
        tenant_id="tenant-a",
        site_id="site-2",
        now=now,
    )
    artifact = b'{"xgboost":"site tree"}'
    wire = build_signed_site_update(
        spec,
        site_id="site-2",
        client_id="site-2-client",
        dataset_id="dataset-" + hashlib.sha256(b"dataset").hexdigest(),
        candidate_id="candidate-" + hashlib.sha256(b"candidate").hexdigest(),
        sample_count=120,
        artifact=artifact,
        site_private_key_path=site_private,
        site_key_id="site-2-key-1",
        submitted_at=now,
    )
    update = federation_pb2.ClientUpdateManifest.FromString(wire)
    signature = bytes(update.client_signature)
    update.client_signature = b""
    site.public_key().verify(signature, update.SerializeToString(deterministic=True))
    assert update.tenant_id == "tenant-a"
    assert update.feature_contract_id == "ot-window-v1"
    assert update.update_artifact == artifact

    with pytest.raises(ValueError, match="policy is invalid"):
        verify_round_spec(
            _spec(coordinator, now),
            coordinator_public_key_path=coordinator_public,
            coordinator_key_id="coordinator-key-1",
            tenant_id="tenant-b",
            site_id="site-2",
            now=now,
        )


def test_partition_seed_is_reproducible_and_site_specific() -> None:
    first = deterministic_partition_seed("round-a", "site-1")
    assert first == deterministic_partition_seed("round-a", "site-1")
    assert first != deterministic_partition_seed("round-a", "site-2")
