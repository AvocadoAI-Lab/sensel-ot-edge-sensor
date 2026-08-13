from __future__ import annotations

import hashlib
import json
import math
from datetime import datetime, timedelta, timezone

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from sensel.federation.v1 import federation_pb2
from sensel_site.federation import (
    build_signed_site_update,
    deterministic_partition_seed,
    prepare_safe_xgboost_update,
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


def test_xgboost_update_is_structurally_clipped_and_leaf_noise_is_attested() -> None:
    tree = {
        "parents": [2147483647, 0, 0],
        "left_children": [1, -1, -1],
        "base_weights": [0.0, 3.0, 4.0],
        "split_conditions": [0.5, 3.0, 4.0],
    }
    artifact = json.dumps(
        {"learner": {"gradient_booster": {"model": {"trees": [tree]}}}}
    ).encode()
    clip = federation_pb2.UpdateClipPolicy(
        maximum_trees=2,
        maximum_tree_depth=2,
        maximum_total_nodes=8,
        maximum_leaf_l2_norm=1.0,
        maximum_artifact_bytes=4096,
    )
    privacy = federation_pb2.PrivacyBudgetPolicy(
        mechanism_id="leaf_vector_gaussian_v1",
        epsilon=2.0,
        delta=1e-5,
        maximum_cumulative_epsilon=8.0,
        privacy_scope="leaf_values_only_fixed_topology",
        formal_full_model_dp_claim_allowed=False,
        accountant_id="rdp_gaussian_v1",
        rdp_orders=[2.0, 4.0, 8.0, 16.0, 32.0],
        noise_multiplier=math.sqrt(2.0 * math.log(1.25 / 1e-5)) / 2.0,
        adjacency_definition="add_remove_one_window",
    )
    output, evidence = prepare_safe_xgboost_update(
        artifact,
        clip_policy=clip,
        privacy_policy=privacy,
        noise_source=lambda _mean, _sigma: 0.0,
    )
    document = json.loads(output)
    safe_tree = document["learner"]["gradient_booster"]["model"]["trees"][0]

    assert safe_tree["split_conditions"][1:] == pytest.approx([0.6, 0.8])
    assert evidence.clipping_applied is True
    assert evidence.original_leaf_l2_norm == pytest.approx(5.0)
    assert evidence.output_leaf_l2_norm == pytest.approx(1.0)
    assert evidence.noise_stddev > 0
    assert evidence.formal_full_model_dp_claim is False
    assert math.isfinite(evidence.noise_stddev)


def test_xgboost_update_exceeding_structural_policy_is_rejected() -> None:
    artifact = json.dumps(
        {
            "learner": {
                "gradient_booster": {
                    "model": {
                        "trees": [
                            {
                                "parents": [2147483647, 0, 1],
                                "left_children": [1, 2, -1],
                                "base_weights": [0.0, 0.0, 1.0],
                                "split_conditions": [0.5, 0.5, 1.0],
                            }
                        ]
                    }
                }
            }
        }
    ).encode()
    with pytest.raises(ValueError, match="exceeds"):
        prepare_safe_xgboost_update(
            artifact,
            clip_policy=federation_pb2.UpdateClipPolicy(
                maximum_trees=1,
                maximum_tree_depth=1,
                maximum_total_nodes=8,
                maximum_leaf_l2_norm=1.0,
                maximum_artifact_bytes=4096,
            ),
            privacy_policy=federation_pb2.PrivacyBudgetPolicy(mechanism_id="none"),
        )


def test_site_update_attests_signed_identity_and_rate_policy(tmp_path) -> None:
    key = Ed25519PrivateKey.generate()
    private = tmp_path / "site.pem"
    _private(private, key)
    spec = federation_pb2.FederationRoundSpec(
        round_id="round-" + "1" * 64,
        tenant_id="tenant-a",
        model_id="ot-xgb",
        base_model_version="0.1.0",
        feature_contract_id="ot-window-v1",
        strategy=federation_pb2.AGGREGATION_STRATEGY_FEDXGB_BAGGING,
        minimum_clients=3,
        allowed_site_ids=["site-1", "site-2", "site-3"],
        site_identity=federation_pb2.SiteIdentityPolicy(
            registry_sha256="sha256:" + "a" * 64,
            rate_policy_id="site-rate-v1",
            maximum_updates_per_window=2,
            rate_window_seconds=3600,
            require_unique_trust_domains_for_quorum=True,
        ),
    )
    wire = build_signed_site_update(
        spec,
        site_id="site-1",
        client_id="client-1",
        dataset_id="dataset-" + "2" * 64,
        candidate_id="candidate-" + "3" * 64,
        sample_count=12,
        artifact=b'{"learner":"sandbox"}',
        site_private_key_path=private,
        site_key_id="site-1-key-1",
        site_identity_id="device-1",
        trust_domain_id="operator-1",
    )
    update = federation_pb2.ClientUpdateManifest.FromString(wire)
    assert update.site_identity_id == "device-1"
    assert update.trust_domain_id == "operator-1"
    assert update.rate_policy_id == "site-rate-v1"


def test_managed_enrollment_is_signed_into_site_update(tmp_path) -> None:
    key = Ed25519PrivateKey.generate()
    private = tmp_path / "site.pem"
    _private(private, key)
    spec = federation_pb2.FederationRoundSpec(
        round_id="round-" + "4" * 64,
        tenant_id="tenant-a",
        model_id="ot-xgb",
        base_model_version="0.1.0",
        feature_contract_id="ot-window-v1",
        strategy=federation_pb2.AGGREGATION_STRATEGY_FEDXGB_BAGGING,
        minimum_clients=3,
        allowed_site_ids=["site-1", "site-2", "site-3"],
        site_identity=federation_pb2.SiteIdentityPolicy(
            registry_sha256="sha256:" + "a" * 64,
            rate_policy_id="site-rate-v1",
            maximum_updates_per_window=2,
            rate_window_seconds=3600,
            require_managed_enrollment=True,
            maximum_key_age_seconds=86400,
            enrollment_snapshot_sha256="sha256:" + "b" * 64,
        ),
    )
    wire = build_signed_site_update(
        spec,
        site_id="site-1",
        client_id="client-1",
        dataset_id="dataset-" + "5" * 64,
        candidate_id="candidate-" + "6" * 64,
        sample_count=12,
        artifact=b'{"learner":"sandbox"}',
        site_private_key_path=private,
        site_key_id="site-1-key-2",
        site_identity_id="device-1",
        trust_domain_id="operator-1",
        enrollment_id="enrollment-" + "7" * 64,
        key_generation=2,
    )
    update = federation_pb2.ClientUpdateManifest.FromString(wire)
    assert update.enrollment_id == "enrollment-" + "7" * 64
    assert update.key_generation == 2


def test_site_rejects_unavailable_secure_aggregation_round(tmp_path) -> None:
    now = datetime(2026, 8, 13, tzinfo=timezone.utc)
    coordinator = Ed25519PrivateKey.generate()
    public = tmp_path / "coordinator.pub.pem"
    _public(public, coordinator)
    spec = federation_pb2.FederationRoundSpec.FromString(_spec(coordinator, now))
    spec.coordinator_signature = b""
    spec.secure_aggregation.protocol_id = "flower-secaggplus"
    spec.secure_aggregation.production_ready = False
    spec.coordinator_signature = coordinator.sign(spec.SerializeToString(deterministic=True))
    with pytest.raises(ValueError, match="policy is invalid"):
        verify_round_spec(
            spec.SerializeToString(deterministic=True),
            coordinator_public_key_path=public,
            coordinator_key_id="coordinator-key-1",
            tenant_id="tenant-a",
            site_id="site-1",
            now=now,
        )
