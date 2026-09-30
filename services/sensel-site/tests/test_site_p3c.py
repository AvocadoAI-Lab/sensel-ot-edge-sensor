from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from sensel_site.candidate_validator import validate_or_quarantine
from sensel_site.lineage import canonical_json, load_public_key, sha256_bytes
from sensel_site.onnx_converter import convert_validate_and_benchmark
from sensel_site.release_signer import sign_release_authorization
from sensel_site.signed_documents import verify_embedded_signed_document
from sensel_site.worker_config import ConverterWorkerConfig, ReleaseSignerConfig
from sensel_site.xgboost_trainer import train_signed_candidate
from test_site_p3b import CONTRACT_DIR, POLICY_PATH, _prepare_job, _write_keypair


def _converter(trainer: object, validator: object, tmp_path: Path) -> ConverterWorkerConfig:
    return ConverterWorkerConfig(
        tenant_id="tenant-a",
        site_id="site-a",
        job_id=trainer.job_id,
        inbox_root=trainer.inbox_root,
        validation_root=validator.results_root,
        conversion_root=tmp_path / "conversion",
        approval_bundle_root=tmp_path / "approval-bundles",
        feature_contract_dir=CONTRACT_DIR,
        policy_path=POLICY_PATH,
        site_public_key_path=trainer.site_public_key_path,
        site_key_id=trainer.site_key_id,
        trainer_public_key_path=validator.trainer_public_key_path,
        trainer_key_id=validator.trainer_key_id,
    )


def _manual_approval(bundle: dict, *, onnx_digest: str | None = None) -> dict:
    now = datetime.now(timezone.utc)
    return {
        "schema_version": "sensel.site.manual-release-approval.v1",
        "decision": "approve",
        "human_review_performed": True,
        "model_parser_used": False,
        "job_id": bundle["job_id"],
        "candidate_id": bundle["candidate_id"],
        "conversion_id": bundle["conversion_id"],
        "tenant_id": bundle["tenant_id"],
        "site_id": bundle["site_id"],
        "conversion_manifest_sha256": bundle["conversion_manifest_sha256"],
        "onnx_artifact_sha256": onnx_digest or bundle["onnx_artifact_sha256"],
        "approver": "security-reviewer@example.test",
        "ticket_id": "SEC-314",
        "reason": "Reviewed technical evidence and approved this exact artifact digest.",
        "reviewed_evidence": [
            "asset-time-holdout",
            "arm-benchmark",
            "prediction-parity",
            "ubjson-to-onnx-conversion",
        ],
        "approved_at": (now - timedelta(minutes=1)).isoformat(),
        "expires_at": (now + timedelta(hours=8)).isoformat(),
    }


def test_conversion_parity_asset_time_holdout_arm_benchmark_and_manual_release(
    tmp_path: Path,
) -> None:
    _, store, request, trainer, validator = _prepare_job(
        tmp_path,
        model_id="ot-xgb-p3c",
    )
    try:
        candidate = train_signed_candidate(trainer)
        assert validate_or_quarantine(validator)["status"] == "validated"
        converter = _converter(trainer, validator, tmp_path)
        conversion = convert_validate_and_benchmark(converter)

        assert conversion["status"] == "technically_validated"
        assert conversion["artifact"]["opset"] == 15
        assert conversion["interface"] == {
            "input_name": "features",
            "input_shape": [None, 11],
            "input_element_type": "float32",
            "output_index": 1,
            "output_name": "probabilities",
            "output_shape": [None, 2],
            "positive_class_index": 1,
        }
        assert conversion["prediction_parity"][
            "maximum_absolute_probability_error"
        ] <= conversion["prediction_parity"]["gates"][
            "maximum_absolute_probability_error"
        ]
        split = conversion["holdout"]
        assert set(split["train_asset_ids"]).isdisjoint(split["validation_asset_ids"])
        latest = split["asset_latest_ended_at"]
        assert min(latest[item] for item in split["validation_asset_ids"]) > max(
            latest[item] for item in split["train_asset_ids"]
        )
        assert conversion["arm_benchmark"]["architecture"] in {"arm64", "aarch64"}
        assert conversion["arm_benchmark"]["latency_ms"]["p95"] <= conversion[
            "arm_benchmark"
        ]["gates"]["maximum_p95_latency_ms"]
        assert conversion["release"]["signed"] is False
        assert conversion["activation"]["performed"] is False

        artifact = converter.conversion_root / request["job_id"] / "model.onnx"
        assert sha256_bytes(artifact.read_bytes()) == conversion["artifact"]["sha256"]
        import onnxruntime as ort

        edge_metadata = ort.InferenceSession(
            str(artifact), providers=["CPUExecutionProvider"]
        ).get_modelmeta().custom_metadata_map
        assert edge_metadata["feature_contract_id"] == "ot-window-v1"
        assert edge_metadata["sensel.feature_contract_definition_sha256"] == candidate[
            "feature_contract_definition_sha256"
        ]
        bundle_root = converter.approval_bundle_root / request["job_id"]
        assert sorted(path.name for path in bundle_root.iterdir()) == [
            "approval-bundle.json",
            "approval-bundle.sha256",
        ]
        bundle = json.loads((bundle_root / "approval-bundle.json").read_bytes())
        assert bundle["model_bytes_in_bundle"] is False
        assert candidate["candidate_id"] == bundle["candidate_id"]

        release_private, release_public, _ = _write_keypair(
            tmp_path / "keys", "release"
        )
        manual_path = tmp_path / "manual-approval.json"
        manual_path.write_bytes(canonical_json(_manual_approval(bundle)) + b"\n")
        release_config = ReleaseSignerConfig(
            tenant_id="tenant-a",
            site_id="site-a",
            job_id=request["job_id"],
            approval_bundle_root=converter.approval_bundle_root,
            manual_approval_path=manual_path,
            release_root=tmp_path / "releases",
            release_private_key_path=release_private,
            release_key_id="release-key-1",
        )
        release = sign_release_authorization(release_config)
        assert release["authorization"] == {
            "state": "release_signed",
            "manual_approval_required": True,
            "automatic_release_allowed": False,
            "distribution_performed": False,
            "activation_performed": False,
        }
        release_dir = release_config.release_root / request["job_id"]
        verified, _ = verify_embedded_signed_document(
            release_dir / "release.json",
            release_dir / "release.sig",
            public_key=load_public_key(release_public),
            expected_key_id="release-key-1",
        )
        assert verified["artifact"]["embedded_in_release"] is False
        assert sorted(path.name for path in release_dir.iterdir()) == [
            "release.json",
            "release.sig",
        ]
        assert not list(tmp_path.rglob("active*"))
    finally:
        store.close()


def test_release_signer_rejects_approval_for_a_different_artifact(tmp_path: Path) -> None:
    _, store, request, trainer, validator = _prepare_job(
        tmp_path,
        model_id="ot-xgb-p3c-mismatch",
    )
    try:
        train_signed_candidate(trainer)
        assert validate_or_quarantine(validator)["status"] == "validated"
        converter = _converter(trainer, validator, tmp_path)
        convert_validate_and_benchmark(converter)
        bundle = json.loads(
            (
                converter.approval_bundle_root
                / request["job_id"]
                / "approval-bundle.json"
            ).read_bytes()
        )
        release_private, _, _ = _write_keypair(tmp_path / "keys", "release")
        manual_path = tmp_path / "manual-approval.json"
        manual_path.write_bytes(
            canonical_json(_manual_approval(bundle, onnx_digest="sha256:" + "0" * 64))
            + b"\n"
        )
        config = ReleaseSignerConfig(
            tenant_id="tenant-a",
            site_id="site-a",
            job_id=request["job_id"],
            approval_bundle_root=converter.approval_bundle_root,
            manual_approval_path=manual_path,
            release_root=tmp_path / "releases",
            release_private_key_path=release_private,
            release_key_id="release-key-1",
        )
        with pytest.raises(
            ValueError,
            match="does not match technical bundle: onnx_artifact_sha256",
        ):
            sign_release_authorization(config)
        assert not config.release_root.exists()
    finally:
        store.close()
