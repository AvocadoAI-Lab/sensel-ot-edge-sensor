from __future__ import annotations

import base64
import hashlib
import json
from datetime import datetime, timedelta, timezone

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from sensel.federation.v1 import federation_pb2
from src.model_rollout.cli import _scoped_file, _write_report
from src.model_rollout.manager import ModelRolloutManager, RolloutConfig


def _canonical(value) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def _sha(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _public(path, key) -> None:
    path.write_bytes(
        key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        )
    )


def _bundle(distribution_key, release_key, *, now: datetime, artifact: bytes = b"onnx-new") -> bytes:
    release_id = "release-" + "1" * 64
    unsigned_release = {
        "schema_version": "sensel.site.model-release-authorization.v1",
        "release_id": release_id,
        "candidate_id": "candidate-" + "2" * 64,
        "tenant_id": "tenant-a",
        "site_id": "site-a",
        "candidate_version": "0.1.0+site.222222222222",
        "feature_contract_id": "ot-window-v1",
        "artifact": {
            "media_type": "application/onnx",
            "sha256": _sha(artifact),
            "embedded_in_release": False,
        },
        "authorization": {
            "state": "release_signed",
            "manual_approval_required": True,
            "automatic_release_allowed": False,
            "distribution_performed": False,
            "activation_performed": False,
        },
    }
    release_payload = _canonical(unsigned_release)
    release_document = _canonical(
        {
            **unsigned_release,
            "signature": {
                "algorithm": "Ed25519",
                "key_id": "release-key-1",
                "signed_fields": "canonical-document-without-signature",
            },
        }
    )
    release_signature = _canonical(
        {
            "algorithm": "Ed25519",
            "key_id": "release-key-1",
            "signed_sha256": _sha(release_payload),
            "signature": base64.b64encode(release_key.sign(release_payload)).decode(),
        }
    )
    entry_hash = _sha(b"release-log-entry")
    checkpoint = _sha(
        _canonical({"log_id": "sensel-models:tenant-a", "sequence": 1, "entry_hash": entry_hash})
    )
    bundle = federation_pb2.ModelDistributionBundle(
        distribution_id="distribution-" + "3" * 64,
        tenant_id="tenant-a",
        site_id="site-a",
        sensor_id="edge-a",
        release_id=release_id,
        candidate_id=unsigned_release["candidate_id"],
        model_id="ot-xgb",
        model_version=unsigned_release["candidate_version"],
        feature_contract_id="ot-window-v1",
        artifact=federation_pb2.ArtifactRef(
            uri="sensel://model-releases/release/model.onnx",
            sha256=_sha(artifact),
            size_bytes=len(artifact),
            media_type="application/onnx",
        ),
        artifact_bytes=artifact,
        release_document=release_document,
        release_signature=release_signature,
        transparency=federation_pb2.TransparencyProof(
            log_id="sensel-models:tenant-a",
            sequence=1,
            entry_hash=entry_hash,
            previous_hash="sha256:" + "0" * 64,
            checkpoint_hash=checkpoint,
        ),
        canary_observation_seconds=60,
        maximum_inference_errors=0,
        maximum_p95_latency_ms=10,
        distribution_key_id="distribution-key-1",
    )
    bundle.issued_at.FromDatetime(now - timedelta(seconds=1))
    bundle.expires_at.FromDatetime(now + timedelta(hours=1))
    bundle.distribution_signature = distribution_key.sign(
        bundle.SerializeToString(deterministic=True)
    )
    return bundle.SerializeToString(deterministic=True)


def _manager(tmp_path):
    distribution = Ed25519PrivateKey.generate()
    release = Ed25519PrivateKey.generate()
    distribution_public = tmp_path / "distribution.pub.pem"
    release_public = tmp_path / "release.pub.pem"
    edge_report_private = tmp_path / "edge-report.pem"
    _public(distribution_public, distribution)
    _public(release_public, release)
    edge_report = Ed25519PrivateKey.generate()
    edge_report_private.write_bytes(
        edge_report.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    edge_report_private.chmod(0o600)
    manager = ModelRolloutManager(
        RolloutConfig(
            tenant_id="tenant-a",
            site_id="site-a",
            sensor_id="edge-a",
            model_root=tmp_path / "models",
            distribution_public_key_path=distribution_public,
            distribution_key_id="distribution-key-1",
            release_public_key_path=release_public,
            release_key_id="release-key-1",
            edge_report_private_key_path=edge_report_private,
            edge_report_key_id="edge-a-report-key-1",
        )
    )
    return manager, distribution, release


def test_staged_canary_failure_atomically_rolls_back_to_last_known_good(tmp_path) -> None:
    now = datetime(2026, 8, 13, tzinfo=timezone.utc)
    manager, distribution, release = _manager(tmp_path)
    previous = manager.config.model_root / "releases" / "release-previous"
    previous.mkdir()
    (previous / "model.onnx").write_bytes(b"onnx-previous")
    (manager.config.model_root / "current").symlink_to("releases/release-previous")
    wire = _bundle(distribution, release, now=now)

    staged = manager.stage(wire, now=now)
    assert staged["state"] == "staged"
    assert (manager.config.model_root / "current").resolve() == previous.resolve()
    deployment = json.loads(
        (
            manager.config.model_root
            / "releases"
            / staged["release_id"]
            / "deployment.json"
        ).read_text()
    )
    assert deployment["adapter"] == "xgboost"
    assert deployment["model_id"] == "ot-xgb"
    active = manager.activate_canary(staged["distribution_id"], now=now)
    assert active["state"] == "canary_active"
    assert (manager.config.model_root / "current" / "model.onnx").read_bytes() == b"onnx-new"
    rolled_back, report_wire = manager.evaluate(
        staged["distribution_id"],
        inference_count=4,
        inference_errors=1,
        p95_latency_ms=2,
        now=now + timedelta(seconds=5),
    )
    report = federation_pb2.ModelRolloutReport.FromString(report_wire)
    assert rolled_back["state"] == "rolled_back"
    assert report.state == federation_pb2.MODEL_ROLLOUT_STATE_ROLLED_BACK
    assert (manager.config.model_root / "current" / "model.onnx").read_bytes() == b"onnx-previous"
    assert report.rollback_artifact_sha256 == staged["artifact_sha256"]
    assert report.edge_key_id == "edge-a-report-key-1"
    assert report.edge_signature


def test_canary_only_becomes_healthy_after_observation_deadline(tmp_path) -> None:
    now = datetime(2026, 8, 13, tzinfo=timezone.utc)
    manager, distribution, release = _manager(tmp_path)
    wire = _bundle(distribution, release, now=now)
    staged = manager.stage(wire, now=now)
    manager.activate_canary(staged["distribution_id"], now=now)
    state, report_wire = manager.evaluate(
        staged["distribution_id"],
        inference_count=100,
        inference_errors=0,
        p95_latency_ms=3,
        now=now + timedelta(seconds=61),
    )
    report = federation_pb2.ModelRolloutReport.FromString(report_wire)
    assert state["state"] == "canary_healthy"
    assert report.state == federation_pb2.MODEL_ROLLOUT_STATE_CANARY_HEALTHY
    assert "fleet" not in state and "promoted" not in state


def test_tampered_distribution_bundle_is_rejected_before_staging(tmp_path) -> None:
    now = datetime(2026, 8, 13, tzinfo=timezone.utc)
    manager, distribution, release = _manager(tmp_path)
    bundle = federation_pb2.ModelDistributionBundle.FromString(
        _bundle(distribution, release, now=now)
    )
    bundle.maximum_inference_errors = 99
    with pytest.raises(ValueError, match="distribution signature"):
        manager.stage(bundle.SerializeToString(deterministic=True), now=now)
    assert not list((manager.config.model_root / "releases").iterdir())


def test_signed_distribution_path_traversal_identity_is_rejected(tmp_path) -> None:
    now = datetime(2026, 8, 13, tzinfo=timezone.utc)
    manager, distribution, release = _manager(tmp_path)
    bundle = federation_pb2.ModelDistributionBundle.FromString(
        _bundle(distribution, release, now=now)
    )
    bundle.distribution_id = "../../outside"
    bundle.distribution_signature = b""
    bundle.distribution_signature = distribution.sign(
        bundle.SerializeToString(deterministic=True)
    )

    with pytest.raises(ValueError, match="artifact/canary contract"):
        manager.stage(bundle.SerializeToString(deterministic=True), now=now)
    assert not list((manager.config.model_root / "releases").iterdir())


def test_report_output_is_confined_and_cannot_overwrite(tmp_path, monkeypatch) -> None:
    output = tmp_path / "output"
    output.mkdir()
    monkeypatch.setenv("TEST_REPORT_ROOT", str(output))
    target = _scoped_file(
        str(output / "report.pb"),
        root_env="TEST_REPORT_ROOT",
        default_root="/output",
        must_exist=False,
    )
    _write_report(target, b"report")
    with pytest.raises(FileExistsError):
        _write_report(target, b"replacement")
    with pytest.raises(ValueError, match="below"):
        _scoped_file(
            str(tmp_path / "outside.pb"),
            root_env="TEST_REPORT_ROOT",
            default_root="/output",
            must_exist=False,
        )
