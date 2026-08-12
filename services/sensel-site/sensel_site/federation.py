"""Framework-neutral boundary and signed P4-A Site update adapter."""

from __future__ import annotations

import hashlib
import json
import math
import random
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
    noise_source: Any | None = None,
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
    safety = None
    if spec.update_clip.maximum_trees or spec.privacy_budget.mechanism_id:
        artifact, safety = prepare_safe_xgboost_update(
            artifact,
            clip_policy=spec.update_clip,
            privacy_policy=spec.privacy_budget,
            noise_source=noise_source,
        )
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
    if safety is not None:
        update.safety.CopyFrom(safety)
    update.submitted_at.FromDatetime(submitted_at or datetime.now(timezone.utc))
    update.client_signature = load_private_key(site_private_key_path).sign(
        update.SerializeToString(deterministic=True)
    )
    return update.SerializeToString(deterministic=True)


def deterministic_partition_seed(round_id: str, site_id: str) -> int:
    """Stable sandbox seed; no Python hash randomization or global RNG state."""
    return int.from_bytes(hashlib.sha256(f"{round_id}:{site_id}".encode()).digest()[:4], "big")


def _tree_depth(parents: list[int], node: int) -> int:
    depth = 0
    seen: set[int] = set()
    while 0 <= parents[node] < len(parents):
        if node in seen:
            raise ValueError("XGBoost tree contains a parent cycle")
        seen.add(node)
        node = parents[node]
        depth += 1
    return depth


def prepare_safe_xgboost_update(
    artifact: bytes,
    *,
    clip_policy: federation_pb2.UpdateClipPolicy,
    privacy_policy: federation_pb2.PrivacyBudgetPolicy,
    noise_source: Any | None = None,
) -> tuple[bytes, federation_pb2.UpdateSafetyEvidence]:
    """Clip a tree update and optionally perturb its fixed-topology leaf vector."""
    try:
        document = json.loads(artifact)
        trees = document["learner"]["gradient_booster"]["model"]["trees"]
    except (KeyError, TypeError, json.JSONDecodeError) as exc:
        raise ValueError("FL update is not a supported XGBoost JSON model") from exc
    if not isinstance(trees, list) or not trees:
        raise ValueError("FL update must contain at least one XGBoost tree")
    leaf_locations: list[tuple[dict[str, Any], int]] = []
    maximum_depth = 0
    total_nodes = 0
    for tree in trees:
        if not isinstance(tree, dict):
            raise ValueError("XGBoost tree entry is malformed")
        parents = tree.get("parents")
        left = tree.get("left_children")
        weights = tree.get("base_weights")
        conditions = tree.get("split_conditions")
        if not all(isinstance(value, list) for value in (parents, left, weights, conditions)):
            raise ValueError("XGBoost tree arrays are malformed")
        node_count = len(parents)
        if not node_count or any(len(value) != node_count for value in (left, weights, conditions)):
            raise ValueError("XGBoost tree arrays have inconsistent lengths")
        if (
            any(isinstance(value, bool) or not isinstance(value, int) for value in parents)
            or any(isinstance(value, bool) or not isinstance(value, int) for value in left)
            or any(
                isinstance(value, bool) or not isinstance(value, (int, float))
                for values in (weights, conditions)
                for value in values
            )
        ):
            raise ValueError("XGBoost tree arrays contain invalid scalar types")
        total_nodes += node_count
        maximum_depth = max(maximum_depth, *(_tree_depth(parents, node) for node in range(node_count)))
        leaf_locations.extend((tree, node) for node, child in enumerate(left) if child == -1)
    if any(
        (
            clip_policy.maximum_trees < 1,
            len(trees) > clip_policy.maximum_trees,
            maximum_depth > clip_policy.maximum_tree_depth,
            total_nodes > clip_policy.maximum_total_nodes,
            clip_policy.maximum_leaf_l2_norm <= 0,
            len(artifact) > clip_policy.maximum_artifact_bytes,
        )
    ):
        raise ValueError("XGBoost update exceeds the signed clipping policy")
    leaves = [float(tree["split_conditions"][node]) for tree, node in leaf_locations]
    if not leaves or not all(math.isfinite(value) for value in leaves):
        raise ValueError("XGBoost leaf vector is empty or non-finite")
    original_norm = math.sqrt(sum(value * value for value in leaves))
    scale = min(1.0, clip_policy.maximum_leaf_l2_norm / max(original_norm, 1e-15))
    clipped = [value * scale for value in leaves]
    mechanism = privacy_policy.mechanism_id or "none"
    sigma = 0.0
    if mechanism == "leaf_vector_gaussian_v1":
        if any(
            (
                privacy_policy.epsilon <= 0,
                not 0 < privacy_policy.delta < 1,
                privacy_policy.privacy_scope != "leaf_values_only_fixed_topology",
                privacy_policy.formal_full_model_dp_claim_allowed,
            )
        ):
            raise ValueError("leaf-vector privacy policy is unsafe or unsupported")
        sensitivity = 2.0 * clip_policy.maximum_leaf_l2_norm
        sigma = sensitivity * math.sqrt(2.0 * math.log(1.25 / privacy_policy.delta))
        sigma /= privacy_policy.epsilon
        generator = noise_source or random.SystemRandom().gauss
        clipped = [value + float(generator(0.0, sigma)) for value in clipped]
    elif mechanism != "none":
        raise ValueError("privacy mechanism is not implemented by this Site")
    if not all(math.isfinite(value) for value in clipped):
        raise ValueError("privacy mechanism produced a non-finite leaf vector")
    for (tree, node), value in zip(leaf_locations, clipped, strict=True):
        tree["base_weights"][node] = value
        tree["split_conditions"][node] = value
    output = json.dumps(document, sort_keys=True, separators=(",", ":")).encode()
    if len(output) > clip_policy.maximum_artifact_bytes:
        raise ValueError("safe XGBoost update exceeds artifact size policy")
    output_norm = math.sqrt(sum(value * value for value in clipped))
    evidence = federation_pb2.UpdateSafetyEvidence(
        original_artifact_sha256=sha256_bytes(artifact),
        output_artifact_sha256=sha256_bytes(output),
        tree_count=len(trees),
        maximum_observed_depth=maximum_depth,
        total_nodes=total_nodes,
        original_leaf_l2_norm=original_norm,
        output_leaf_l2_norm=output_norm,
        clipping_applied=scale < 1.0,
        privacy_mechanism_id=mechanism,
        epsilon_spent=(privacy_policy.epsilon if mechanism != "none" else 0.0),
        delta_spent=(privacy_policy.delta if mechanism != "none" else 0.0),
        noise_stddev=sigma,
        privacy_scope=(privacy_policy.privacy_scope if mechanism != "none" else "none"),
        formal_full_model_dp_claim=False,
    )
    return output, evidence
