from __future__ import annotations

import hashlib
import json
import shutil
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from sensel.episode.v1 import trust_episode_pb2

from sensel_site.artifacts import ArtifactCache
from sensel_site.config import SiteConfig
from sensel_site.contracts import (
    TRUST_EPISODE_CONTENT_TYPE,
    InvalidSitePublish,
    decode_episode_publish,
)
from sensel_site.feature_contracts import FeatureContractRegistry
from sensel_site.lineage import (
    DatasetLineageService,
    load_public_key,
    verify_dataset_export,
)
from sensel_site.mqtt_ingress import SiteEpisodeIngress, SiteMqttSubscriber
from sensel_site.store import SiteStore
from sensel_site.trainer import TrainerBoundary
from sensel_site.training_policy import load_xgboost_policy

EDGE_AGENT_ROOT = Path(__file__).resolve().parents[2] / "sensel-edge-agent"
REPO_ROOT = Path(__file__).resolve().parents[3]
CONTRACT_DIR = REPO_ROOT / "config" / "model"
TRAINER_POLICY = CONTRACT_DIR / "trainer-policy.xgboost-site-v1.json"
GOLDEN = EDGE_AGENT_ROOT / "tests" / "fixtures" / "trust_episode.v1.bin"


def _config(tmp_path: Path) -> SiteConfig:
    return SiteConfig(
        tenant_id="tenant-a",
        site_id="site-a",
        node_id="site-node-a",
        data_dir=tmp_path,
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
        signing_key_path=tmp_path / "signing-key.pem",
        signing_key_id="site-a-key-1",
        max_episode_bytes=1_048_576,
        episode_retention_days=30,
        feature_contract_dir=CONTRACT_DIR,
        trainer_inbox_dir=tmp_path / "trainer-inbox",
        trainer_policy_path=TRAINER_POLICY,
    )


def _episode(
    *,
    sensor_id: str = "edge-a",
    episode_id: str = "episode-a",
    sequence_ref: str = "sha256:" + ("a" * 64),
) -> bytes:
    message = trust_episode_pb2.TrustEpisode.FromString(GOLDEN.read_bytes())
    message.episode_id = episode_id
    message.asset_id = "asset-plc-1"
    message.meta.event_id = episode_id
    message.meta.tenant_id = "tenant-a"
    message.meta.site_id = "site-a"
    message.meta.sensor_id = sensor_id
    message.meta.trace_id = f"trace-{episode_id}"
    message.features.feature_contract_id = "ot-window-v1"
    message.features.sequence_ref = sequence_ref
    return message.SerializeToString(deterministic=True)


def _ingest(
    ingress: SiteEpisodeIngress,
    payload: bytes,
    *,
    sensor_id: str = "edge-a",
):
    return ingress.handle(
        topic=f"sensel/tenant-a/site-a/{sensor_id}/episode/v1",
        payload=payload,
        content_type=TRUST_EPISODE_CONTENT_TYPE,
        payload_format_indicator=0,
    )


def _keys(config: SiteConfig) -> tuple[Ed25519PrivateKey, Path]:
    private = Ed25519PrivateKey.generate()
    config.signing_key_path.write_bytes(
        private.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    config.signing_key_path.chmod(0o600)
    public_path = config.data_dir / "signing-key.pub.pem"
    public_path.write_bytes(
        private.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    return private, public_path


def test_protobuf_ingress_enforces_topic_scope_and_wire_metadata(tmp_path: Path) -> None:
    payload = _episode()
    receipt = decode_episode_publish(
        topic="sensel/tenant-a/site-a/edge-a/episode/v1",
        payload=payload,
        content_type=TRUST_EPISODE_CONTENT_TYPE,
        payload_format_indicator=0,
        expected_tenant_id="tenant-a",
        expected_site_id="site-a",
        max_payload_bytes=1_048_576,
    )
    assert receipt.feature_contract_id == "ot-window-v1"
    assert receipt.payload_sha256 == "sha256:" + hashlib.sha256(payload).hexdigest()

    with pytest.raises(InvalidSitePublish, match="outside this Site scope"):
        decode_episode_publish(
            topic="sensel/tenant-a/site-b/edge-a/episode/v1",
            payload=payload,
            content_type=TRUST_EPISODE_CONTENT_TYPE,
            payload_format_indicator=0,
            expected_tenant_id="tenant-a",
            expected_site_id="site-a",
            max_payload_bytes=1_048_576,
        )
    with pytest.raises(InvalidSitePublish, match="Content Type"):
        decode_episode_publish(
            topic="sensel/tenant-a/site-a/edge-a/episode/v1",
            payload=payload,
            content_type="application/json",
            payload_format_indicator=0,
            expected_tenant_id="tenant-a",
            expected_site_id="site-a",
            max_payload_bytes=1_048_576,
        )
    with pytest.raises(InvalidSitePublish, match="QoS 1"):
        decode_episode_publish(
            topic="sensel/tenant-a/site-a/edge-a/episode/v1",
            payload=payload,
            content_type=TRUST_EPISODE_CONTENT_TYPE,
            payload_format_indicator=0,
            expected_tenant_id="tenant-a",
            expected_site_id="site-a",
            max_payload_bytes=1_048_576,
            qos=0,
        )
    non_finite = trust_episode_pb2.TrustEpisode.FromString(payload)
    non_finite.features.latest_values[0] = float("nan")
    with pytest.raises(InvalidSitePublish, match="must be finite"):
        decode_episode_publish(
            topic="sensel/tenant-a/site-a/edge-a/episode/v1",
            payload=non_finite.SerializeToString(),
            content_type=TRUST_EPISODE_CONTENT_TYPE,
            payload_format_indicator=0,
            expected_tenant_id="tenant-a",
            expected_site_id="site-a",
            max_payload_bytes=1_048_576,
        )


def test_feature_contract_registry_rejects_definition_tampering(tmp_path: Path) -> None:
    contract_dir = tmp_path / "contracts"
    contract_dir.mkdir()
    target = contract_dir / "feature-contract.ot-window-v1.json"
    shutil.copyfile(CONTRACT_DIR / target.name, target)
    document = json.loads(target.read_text(encoding="utf-8"))
    document["sequence_length"] = 61
    target.write_text(json.dumps(document), encoding="utf-8")

    with pytest.raises(ValueError, match="definition digest mismatch"):
        FeatureContractRegistry(contract_dir)


def test_multi_edge_retry_is_durable_and_poison_is_dead_lettered(tmp_path: Path) -> None:
    config = _config(tmp_path)
    store = SiteStore(config.db_path)
    ingress = SiteEpisodeIngress(config, store)
    try:
        first = _ingest(ingress, _episode())
        duplicate = _ingest(ingress, _episode())
        other_edge = _ingest(
            ingress,
            _episode(sensor_id="edge-b", episode_id="episode-b"),
            sensor_id="edge-b",
        )
        poison = ingress.handle(
            topic="sensel/tenant-a/site-a/edge-a/episode/v1",
            payload=b"not-protobuf",
            content_type=TRUST_EPISODE_CONTENT_TYPE,
            payload_format_indicator=0,
        )
        poison_retry = ingress.handle(
            topic="sensel/tenant-a/site-a/edge-a/episode/v1",
            payload=b"not-protobuf",
            content_type=TRUST_EPISODE_CONTENT_TYPE,
            payload_format_indicator=0,
        )
        unknown_contract = trust_episode_pb2.TrustEpisode.FromString(_episode())
        unknown_contract.features.feature_contract_id = "unknown-contract-v1"
        incompatible = _ingest(
            ingress,
            unknown_contract.SerializeToString(deterministic=True),
        )

        assert (first.status, duplicate.status, other_edge.status) == (
            "stored",
            "duplicate",
            "stored",
        )
        assert poison.status == poison_retry.status == "dead_letter"
        assert incompatible.status == "dead_letter"
        assert store.counts()["episode_receipts"] == 2
        assert store.counts()["ingress_dead_letters"] == 2
    finally:
        store.close()


def test_mqtt_manual_ack_happens_only_after_durable_handling(tmp_path: Path) -> None:
    config = _config(tmp_path)
    store = SiteStore(config.db_path)
    subscriber = SiteMqttSubscriber(config, SiteEpisodeIngress(config, store))
    client = MagicMock()
    message = SimpleNamespace(
        topic="sensel/tenant-a/site-a/edge-a/episode/v1",
        payload=_episode(),
        properties=SimpleNamespace(
            ContentType=TRUST_EPISODE_CONTENT_TYPE,
            PayloadFormatIndicator=0,
        ),
        retain=False,
        mid=42,
        qos=1,
    )
    try:
        subscriber._on_message(client, None, message)
        client.ack.assert_called_once_with(42, 1)

        subscriber.ingress.handle = MagicMock(side_effect=OSError("disk unavailable"))
        failed_message = SimpleNamespace(**{**vars(message), "mid": 43})
        subscriber._on_message(client, None, failed_message)
        assert client.ack.call_count == 1
    finally:
        store.close()


def test_mqtt_connect_resumes_persistent_session(monkeypatch, tmp_path: Path) -> None:
    config = replace(
        _config(tmp_path),
        mqtt_enabled=True,
        mqtt_host="site-broker",
        mqtt_tls=False,
    )
    store = SiteStore(config.db_path)
    subscriber = SiteMqttSubscriber(config, SiteEpisodeIngress(config, store))
    client = MagicMock()
    monkeypatch.setattr("paho.mqtt.client.Client", MagicMock(return_value=client))
    try:
        subscriber.start()
        assert client.connect.call_args.kwargs["clean_start"] is False
        assert (
            client.connect.call_args.kwargs["properties"].SessionExpiryInterval
            == 86400
        )
    finally:
        subscriber.stop()
        store.close()


def test_dataset_lineage_signing_and_tamper_detection(tmp_path: Path) -> None:
    config = _config(tmp_path)
    private, public_path = _keys(config)
    store = SiteStore(config.db_path)
    ingress = SiteEpisodeIngress(config, store)
    _ingest(ingress, _episode())
    _ingest(
        ingress,
        _episode(sensor_id="edge-b", episode_id="episode-b"),
        sensor_id="edge-b",
    )
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
    try:
        first = lineage.create_dataset(
            feature_contract_id="ot-window-v1",
            label_source="fusion_decision",
            retention_class="training-short",
        )
        duplicate = lineage.create_dataset(
            feature_contract_id="ot-window-v1",
            label_source="fusion_decision",
            retention_class="training-short",
        )
        export = lineage.export_signed(first.dataset_id)
        verified = verify_dataset_export(
            export,
            public_key=load_public_key(public_path),
            expected_tenant_id="tenant-a",
            expected_site_id="site-a",
        )

        assert first.created is True
        assert duplicate.created is False
        assert first.dataset_id == duplicate.dataset_id
        assert verified["sample_count"] == 2
        assert verified["feature_contract_definition_sha256"].startswith("sha256:")
        assert verified["samples"]["contains_raw_packets"] is False
        assert private.public_key()  # signing key fixture is usable

        samples = export / "samples.jsonl"
        samples.write_bytes(samples.read_bytes() + b"{}\n")
        with pytest.raises(ValueError, match="samples digest mismatch"):
            verify_dataset_export(
                export,
                public_key=load_public_key(public_path),
            )
    finally:
        store.close()


def test_signed_export_recovers_after_rename_before_database_mark(tmp_path: Path) -> None:
    config = _config(tmp_path)
    _keys(config)
    store = SiteStore(config.db_path)
    _ingest(SiteEpisodeIngress(config, store), _episode())
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
    original_mark = store.mark_dataset_exported
    store.mark_dataset_exported = MagicMock(side_effect=OSError("simulated crash"))
    try:
        with pytest.raises(OSError, match="simulated crash"):
            lineage.export_signed(dataset.dataset_id)
        assert (config.export_dir / dataset.dataset_id / "manifest.sig").is_file()

        store.mark_dataset_exported = original_mark
        recovered = lineage.export_signed(dataset.dataset_id)
        assert recovered == config.export_dir / dataset.dataset_id
        assert store.get_dataset(dataset.dataset_id)["export_path"] == str(recovered)
    finally:
        store.mark_dataset_exported = original_mark
        store.close()


def test_manual_label_lineage_records_actor_controlled_label_ref(tmp_path: Path) -> None:
    config = _config(tmp_path)
    _keys(config)
    store = SiteStore(config.db_path)
    _ingest(SiteEpisodeIngress(config, store), _episode())
    _ingest(
        SiteEpisodeIngress(config, store),
        _episode(sensor_id="edge-b", episode_id="episode-a"),
        sensor_id="edge-b",
    )
    with pytest.raises(LookupError, match="ambiguous"):
        store.add_manual_label(
            tenant_id="tenant-a",
            site_id="site-a",
            episode_id="episode-a",
            label="confirmed_attack",
            actor="analyst-a",
            reason="Ambiguous without the originating sensor",
        )
    label_id = store.add_manual_label(
        tenant_id="tenant-a",
        site_id="site-a",
        episode_id="episode-a",
        label="confirmed_attack",
        actor="analyst-a",
        reason="Reviewed with plant owner",
        sensor_id="edge-a",
    )
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
    try:
        result = lineage.create_dataset(
            feature_contract_id="ot-window-v1",
            label_source="manual",
            retention_class="regulated",
            limit=1,
        )
        assert result.manifest["records"][0]["label_ref"] == label_id
        assert result.manifest["retention"]["days"] == 365
        unlabeled = store.select_dataset_rows(
            tenant_id="tenant-a",
            site_id="site-a",
            feature_contract_id="ot-window-v1",
            label_source="unlabeled",
            started_at=None,
            ended_at=None,
            limit=1,
        )
        assert unlabeled[0]["sensor_id"] == "edge-b"
    finally:
        store.close()


def test_trainer_boundary_only_accepts_signed_xgboost_dataset(tmp_path: Path) -> None:
    config = _config(tmp_path)
    private, _ = _keys(config)
    store = SiteStore(config.db_path)
    _ingest(SiteEpisodeIngress(config, store), _episode())
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
    boundary = TrainerBoundary(
        store,
        tenant_id="tenant-a",
        site_id="site-a",
        inbox_root=config.trainer_inbox_dir,
        public_key=private.public_key(),
        signing_key=private,
        signing_key_id=config.signing_key_id,
        training_policy=load_xgboost_policy(TRAINER_POLICY),
    )
    try:
        request, created = boundary.prepare_job(
            dataset_id=dataset.dataset_id,
            algorithm="xgboost",
            model_id="ot-xgb",
            base_model_version="0.1.0",
            expected_feature_contract_id="ot-window-v1",
        )
        duplicate, duplicate_created = boundary.prepare_job(
            dataset_id=dataset.dataset_id,
            algorithm="xgboost",
            model_id="ot-xgb",
            base_model_version="0.1.0",
            expected_feature_contract_id="ot-window-v1",
        )
        job_path = config.trainer_inbox_dir / request["job_id"]

        assert created is True
        assert duplicate_created is False
        assert duplicate["job_id"] == request["job_id"]
        assert sorted(path.name for path in (job_path / "dataset").iterdir()) == [
            "manifest.json",
            "manifest.sig",
            "samples.jsonl",
        ]
        assert not (job_path / "candidate-outbox").exists()
        assert request["output"]["automatic_activation_allowed"] is False
        assert not list(job_path.rglob("*.db"))
        assert not list(job_path.rglob("*.pcap"))
        with pytest.raises(ValueError, match="full sequence materialization"):
            boundary.prepare_job(
                dataset_id=dataset.dataset_id,
                algorithm="tiny-lstm",
                model_id="ot-lstm",
                base_model_version="0.1.0",
                expected_feature_contract_id="ot-window-v1",
            )
        with pytest.raises(ValueError, match="local baseline"):
            boundary.prepare_job(
                dataset_id=dataset.dataset_id,
                algorithm="isolation-forest",
                model_id="ot-if",
                base_model_version="0.1.0",
                expected_feature_contract_id="ot-window-v1",
            )
    finally:
        store.close()


def test_artifact_cache_verifies_digest_and_never_activates_on_install(
    tmp_path: Path,
) -> None:
    config = _config(tmp_path)
    store = SiteStore(config.db_path)
    source = tmp_path / "policy.json"
    source.write_text('{"policy":"v1"}', encoding="utf-8")
    digest = "sha256:" + hashlib.sha256(source.read_bytes()).hexdigest()
    cache = ArtifactCache(store, tmp_path / "artifacts")
    try:
        target, created = cache.install(
            source,
            kind="policy",
            artifact_id="ot-policy",
            version="1.0.0",
            expected_sha256=digest,
            media_type="application/json",
        )
        duplicate, duplicate_created = cache.install(
            source,
            kind="policy",
            artifact_id="ot-policy",
            version="1.0.0",
            expected_sha256=digest,
            media_type="application/json",
        )
        assert target == duplicate
        assert created is True and duplicate_created is False
        with pytest.raises(ValueError, match="digest mismatch"):
            cache.install(
                source,
                kind="model",
                artifact_id="ot-model",
                version="1.0.0",
                expected_sha256="sha256:" + ("0" * 64),
                media_type="application/octet-stream",
            )
    finally:
        store.close()


def test_production_config_requires_mqtt_mtls(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setenv("SENSEL_SITE_TENANT_ID", "tenant-a")
    monkeypatch.setenv("SENSEL_SITE_ID", "site-a")
    monkeypatch.setenv("SENSEL_SITE_NODE_ID", "node-a")
    monkeypatch.setenv("SENSEL_SITE_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("SENSEL_SITE_ENV", "production")
    monkeypatch.setenv("SENSEL_SITE_MQTT_ENABLED", "true")
    monkeypatch.setenv("SENSEL_SITE_MQTT_TLS", "true")
    with pytest.raises(ValueError, match="requires CA, client cert and key"):
        SiteConfig.from_env()

    monkeypatch.setenv("SENSEL_SITE_MQTT_TLS", "false")
    with pytest.raises(ValueError, match="requires TLS"):
        SiteConfig.from_env()

    monkeypatch.setenv("SENSEL_SITE_ENV", "lab")
    monkeypatch.setenv("SENSEL_SITE_MQTT_TLS_INSECURE", "true")
    assert SiteConfig.from_env().mqtt_tls_insecure is True
