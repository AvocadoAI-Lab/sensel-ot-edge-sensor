from __future__ import annotations

import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from sensel.episode.v1 import trust_episode_pb2

from sensel_site.candidate_validator import validate_or_quarantine
from sensel_site.config import SiteConfig
from sensel_site.contracts import TRUST_EPISODE_CONTENT_TYPE
from sensel_site.feature_contracts import FeatureContractRegistry
from sensel_site.lineage import (
    DatasetLineageService,
    canonical_json,
    load_private_key,
    sha256_bytes,
)
from sensel_site.mqtt_ingress import SiteEpisodeIngress
from sensel_site.signed_documents import encode_embedded_signed_document
from sensel_site.store import SiteStore
from sensel_site.trainer import TrainerBoundary
from sensel_site.training_policy import load_xgboost_policy
from sensel_site.worker_config import TrainerWorkerConfig, ValidatorWorkerConfig
from sensel_site.xgboost_trainer import train_signed_candidate

EDGE_AGENT_ROOT = Path(__file__).resolve().parents[2] / "sensel-edge-agent"
REPO_ROOT = Path(__file__).resolve().parents[3]
CONTRACT_DIR = REPO_ROOT / "config" / "model"
POLICY_PATH = CONTRACT_DIR / "trainer-policy.xgboost-site-v1.json"
GOLDEN = EDGE_AGENT_ROOT / "tests" / "fixtures" / "trust_episode.v1.bin"


def _site_config(tmp_path: Path) -> SiteConfig:
    return SiteConfig(
        tenant_id="tenant-a",
        site_id="site-a",
        node_id="site-node-a",
        data_dir=tmp_path / "site",
        mqtt_enabled=False,
        mqtt_host="",
        mqtt_port=8883,
        mqtt_username="",
        mqtt_password="",
        mqtt_tls=True,
        mqtt_ca_path="",
        mqtt_cert_path="",
        mqtt_key_path="",
        mqtt_tls_insecure=False,
        mqtt_session_expiry_sec=86400,
        signing_key_path=tmp_path / "keys" / "site.pem",
        signing_key_id="site-key-1",
        max_episode_bytes=1_048_576,
        episode_retention_days=30,
        feature_contract_dir=CONTRACT_DIR,
        trainer_inbox_dir=tmp_path / "trainer-inbox",
        trainer_policy_path=POLICY_PATH,
    )


def _write_keypair(root: Path, name: str) -> tuple[Path, Path, Ed25519PrivateKey]:
    root.mkdir(parents=True, exist_ok=True)
    private_path = root / f"{name}.pem"
    public_path = root / f"{name}.pub.pem"
    key = Ed25519PrivateKey.generate()
    private_path.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    private_path.chmod(0o600)
    public_path.write_bytes(
        key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    return private_path, public_path, key


def _episode(index: int, *, positive: bool) -> bytes:
    message = trust_episode_pb2.TrustEpisode.FromString(GOLDEN.read_bytes())
    episode_id = f"episode-p3b-{index:04d}"
    message.episode_id = episode_id
    message.meta.event_id = episode_id
    message.meta.tenant_id = "tenant-a"
    message.meta.site_id = "site-a"
    message.meta.sensor_id = f"edge-{index % 4}"
    message.meta.trace_id = f"trace-{episode_id}"
    message.asset_id = f"asset-{index % 6}"
    message.features.feature_contract_id = "ot-window-v1"
    message.features.sequence_ref = f"sha256:{index:064x}"
    del message.features.latest_values[:]
    base = 100.0 if positive else 1.0
    message.features.latest_values.extend(base + offset for offset in range(11))
    message.fusion.decision = "alert" if positive else "normal"
    message.fusion.severity = "high" if positive else "low"
    message.fusion.score = 0.95 if positive else 0.05
    for detection in message.detections:
        if detection.available:
            detection.score = message.fusion.score
    return message.SerializeToString(deterministic=True)


def _prepare_job(
    tmp_path: Path,
    *,
    model_id: str,
) -> tuple[
    SiteConfig,
    SiteStore,
    dict,
    TrainerWorkerConfig,
    ValidatorWorkerConfig,
]:
    config = _site_config(tmp_path)
    site_private_path, site_public_path, site_key = _write_keypair(
        tmp_path / "keys", "site"
    )
    trainer_private_path, trainer_public_path, trainer_key = _write_keypair(
        tmp_path / "keys", "trainer"
    )
    assert site_private_path == config.signing_key_path
    store = SiteStore(config.db_path)
    ingress = SiteEpisodeIngress(config, store)
    for index in range(24):
        sensor_id = f"edge-{index % 4}"
        result = ingress.handle(
            topic=f"sensel/tenant-a/site-a/{sensor_id}/episode/v1",
            payload=_episode(index, positive=index >= 12),
            content_type=TRUST_EPISODE_CONTENT_TYPE,
            payload_format_indicator=0,
        )
        assert result.status == "stored"
    lineage = DatasetLineageService(
        store,
        tenant_id=config.tenant_id,
        site_id=config.site_id,
        node_id=config.node_id,
        export_root=config.export_dir,
        signing_key_path=config.signing_key_path,
        signing_key_id=config.signing_key_id,
        feature_contract_registry=FeatureContractRegistry(CONTRACT_DIR),
    )
    dataset = lineage.create_dataset(
        feature_contract_id="ot-window-v1",
        label_source="fusion_decision",
        retention_class="training-short",
    )
    lineage.export_signed(dataset.dataset_id)
    request, created = TrainerBoundary(
        store,
        tenant_id="tenant-a",
        site_id="site-a",
        inbox_root=config.trainer_inbox_dir,
        public_key=site_key.public_key(),
        signing_key=site_key,
        signing_key_id=config.signing_key_id,
        training_policy=load_xgboost_policy(POLICY_PATH),
    ).prepare_job(
        dataset_id=dataset.dataset_id,
        algorithm="xgboost",
        model_id=model_id,
        base_model_version="0.1.0",
        expected_feature_contract_id="ot-window-v1",
    )
    assert created is True
    candidate_root = tmp_path / "candidates"
    validation_root = tmp_path / "validation"
    trainer = TrainerWorkerConfig(
        tenant_id="tenant-a",
        site_id="site-a",
        job_id=request["job_id"],
        inbox_root=config.trainer_inbox_dir,
        candidate_root=candidate_root,
        feature_contract_dir=CONTRACT_DIR,
        policy_path=POLICY_PATH,
        site_public_key_path=site_public_path,
        site_key_id=config.signing_key_id,
        trainer_private_key_path=trainer_private_path,
        trainer_key_id="trainer-key-1",
    )
    validator = ValidatorWorkerConfig(
        tenant_id="tenant-a",
        site_id="site-a",
        job_id=request["job_id"],
        inbox_root=config.trainer_inbox_dir,
        candidate_root=candidate_root,
        results_root=validation_root,
        feature_contract_dir=CONTRACT_DIR,
        policy_path=POLICY_PATH,
        site_public_key_path=site_public_path,
        site_key_id=config.signing_key_id,
        trainer_public_key_path=trainer_public_path,
        trainer_key_id="trainer-key-1",
    )
    assert trainer_key.public_key()
    return config, store, request, trainer, validator


def _verified_audit_decision(root: Path) -> dict:
    payload = (root / "validation.json").read_bytes()
    assert json.loads((root / "validation.sha256").read_bytes()) == {
        "algorithm": "SHA-256",
        "sha256": sha256_bytes(payload),
    }
    return json.loads(payload)


def test_training_policy_digest_rejects_gate_tampering(tmp_path: Path) -> None:
    document = json.loads(POLICY_PATH.read_text(encoding="utf-8"))
    document["validation_gates"]["minimum_balanced_accuracy"] = 0.0
    tampered = tmp_path / "trainer-policy.json"
    tampered.write_text(json.dumps(document), encoding="utf-8")
    with pytest.raises(ValueError, match="definition digest mismatch"):
        load_xgboost_policy(tampered)


def test_offline_xgboost_candidate_is_signed_validated_and_never_activated(
    tmp_path: Path,
) -> None:
    config, store, request, trainer, validator = _prepare_job(
        tmp_path,
        model_id="ot-xgb-p3b",
    )
    try:
        candidate = train_signed_candidate(trainer)
        duplicate = train_signed_candidate(trainer)
        decision = validate_or_quarantine(validator)
        repeated_decision = validate_or_quarantine(validator)

        assert duplicate["candidate_id"] == candidate["candidate_id"]
        assert candidate["lifecycle"] == {
            "state": "candidate",
            "automatic_activation_allowed": False,
            "activation_performed": False,
            "requires_independent_validation": True,
        }
        assert decision["status"] == repeated_decision["status"] == "validated"
        assert decision["activation"]["performed"] is False
        assert decision["activation"]["automatic_activation_allowed"] is False
        result_root = config.data_dir.parent / "validation" / "validated" / request["job_id"]
        verified = _verified_audit_decision(result_root)
        assert verified["status"] == "validated"
        assert not list(tmp_path.rglob("active*"))
        assert store.counts()["trainer_jobs"] == 1
    finally:
        store.close()


def test_tampered_candidate_artifact_is_durably_quarantined(tmp_path: Path) -> None:
    _, store, request, trainer, validator = _prepare_job(
        tmp_path,
        model_id="ot-xgb-tamper",
    )
    try:
        train_signed_candidate(trainer)
        model = trainer.candidate_root / request["job_id"] / "model.ubj"
        model.chmod(0o644)
        payload = bytearray(model.read_bytes())
        payload[-1] ^= 0x01
        model.write_bytes(payload)
        model.chmod(0o444)

        decision = validate_or_quarantine(validator)
        assert decision["status"] == "quarantine"
        assert "digest mismatch" in decision["reason"]
        quarantine = validator.results_root / "quarantine" / request["job_id"]
        verified = _verified_audit_decision(quarantine)
        assert verified["activation"]["performed"] is False
        assert (quarantine / "model.ubj").read_bytes() == bytes(payload)
        assert not (validator.results_root / "validated" / request["job_id"]).exists()
    finally:
        store.close()


def test_validly_resigned_false_metrics_are_recomputed_and_quarantined(
    tmp_path: Path,
) -> None:
    _, store, request, trainer, validator = _prepare_job(
        tmp_path,
        model_id="ot-xgb-false-metrics",
    )
    try:
        train_signed_candidate(trainer)
        candidate_root = trainer.candidate_root / request["job_id"]
        manifest_path = candidate_root / "candidate.json"
        signature_path = candidate_root / "candidate.sig"
        manifest = json.loads(manifest_path.read_bytes())
        manifest.pop("signature")
        manifest["metrics"]["validation"]["logloss"] = round(
            manifest["metrics"]["validation"]["logloss"] + 0.25,
            12,
        )
        identity = {
            "job_id": request["job_id"],
            "request_sha256": manifest["dataset"]["request_sha256"],
            "dataset_id": manifest["dataset"]["dataset_id"],
            "dataset_samples_sha256": manifest["dataset"]["samples_sha256"],
            "artifact_sha256": manifest["artifact"]["sha256"],
            "metrics": manifest["metrics"],
            "training_policy_definition_sha256": manifest["training_policy"][
                "definition_sha256"
            ],
        }
        manifest["candidate_id"] = "candidate-" + sha256_bytes(
            canonical_json(identity)
        ).removeprefix("sha256:")
        manifest["candidate_version"] = (
            f"{manifest['base_model_version']}+site."
            f"{manifest['candidate_id'].removeprefix('candidate-')[:12]}"
        )
        document, signature, _ = encode_embedded_signed_document(
            manifest,
            private_key=load_private_key(trainer.trainer_private_key_path),
            key_id=trainer.trainer_key_id,
        )
        candidate_root.chmod(0o755)
        manifest_path.chmod(0o644)
        signature_path.chmod(0o644)
        manifest_path.write_bytes(document)
        signature_path.write_bytes(signature)
        manifest_path.chmod(0o444)
        signature_path.chmod(0o444)
        candidate_root.chmod(0o555)

        decision = validate_or_quarantine(validator)
        assert decision["status"] == "quarantine"
        assert "metric recomputation mismatch: logloss" in decision["reason"]
        assert decision["activation"]["performed"] is False
    finally:
        store.close()
