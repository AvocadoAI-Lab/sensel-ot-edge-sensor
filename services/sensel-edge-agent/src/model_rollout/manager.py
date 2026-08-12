"""Fail-closed Edge model rollout with an atomic last-known-good pointer."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import stat
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from sensel.federation.v1 import federation_pb2

_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9@._:+-]{0,159}$")
_SHA = re.compile(r"^sha256:[0-9a-f]{64}$")
_RELEASE_ID = re.compile(r"^release-[0-9a-f]{64}$")
_CANDIDATE_ID = re.compile(r"^candidate-[0-9a-f]{64}$")
_DISTRIBUTION_ID = re.compile(r"^distribution-[0-9a-f]{64}$")


def _canonical(value: Any) -> bytes:
    return json.dumps(
        value, ensure_ascii=False, allow_nan=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def _sha(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _public_key(path: Path) -> Ed25519PublicKey:
    key = serialization.load_pem_public_key(path.read_bytes())
    if not isinstance(key, Ed25519PublicKey):
        raise ValueError("model rollout verification key must be Ed25519")
    return key


def _private_key(path: Path) -> Ed25519PrivateKey:
    if path.is_symlink() or stat.S_IMODE(path.stat().st_mode) & 0o077:
        raise ValueError("Edge report signing key must be non-symlink mode 0600 or stricter")
    key = serialization.load_pem_private_key(path.read_bytes(), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError("Edge report signing key must be Ed25519")
    return key


def _verify_release(
    document_bytes: bytes,
    signature_bytes: bytes,
    *,
    public_key: Ed25519PublicKey,
    key_id: str,
) -> dict[str, Any]:
    signed = json.loads(document_bytes)
    signature = json.loads(signature_bytes)
    if not isinstance(signed, dict) or not isinstance(signature, dict):
        raise ValueError("release authorization must be JSON objects")
    metadata = signed.pop("signature", None)
    if metadata != {
        "algorithm": "Ed25519",
        "key_id": key_id,
        "signed_fields": "canonical-document-without-signature",
    }:
        raise ValueError("release signature metadata is not trusted")
    payload = _canonical(signed)
    if any(
        (
            signature.get("algorithm") != "Ed25519",
            signature.get("key_id") != key_id,
            signature.get("signed_sha256") != _sha(payload),
        )
    ):
        raise ValueError("release detached signature metadata mismatch")
    try:
        public_key.verify(base64.b64decode(signature["signature"], validate=True), payload)
    except (InvalidSignature, KeyError, ValueError) as exc:
        raise ValueError("release authorization signature verification failed") from exc
    authorization = signed.get("authorization", {})
    if any(
        (
            signed.get("schema_version") != "sensel.site.model-release-authorization.v1",
            authorization.get("state") != "release_signed",
            authorization.get("manual_approval_required") is not True,
            authorization.get("automatic_release_allowed") is not False,
            authorization.get("distribution_performed") is not False,
            authorization.get("activation_performed") is not False,
        )
    ):
        raise ValueError("release authorization violates canary-only policy")
    return signed


def _write_json(path: Path, document: dict[str, Any]) -> None:
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    descriptor = os.open(temporary, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o640)
    try:
        payload = _canonical(document) + b"\n"
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError("failed to write rollout state")
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.replace(temporary, path)


@dataclass(frozen=True)
class RolloutConfig:
    tenant_id: str
    site_id: str
    sensor_id: str
    model_root: Path
    distribution_public_key_path: Path
    distribution_key_id: str
    release_public_key_path: Path
    release_key_id: str
    edge_report_private_key_path: Path
    edge_report_key_id: str


class ModelRolloutManager:
    def __init__(self, config: RolloutConfig) -> None:
        self.config = config
        if not all(_ID.fullmatch(item) for item in (config.tenant_id, config.site_id, config.sensor_id)):
            raise ValueError("model rollout Edge scope is invalid")
        config.model_root.mkdir(parents=True, exist_ok=True)
        (config.model_root / "releases").mkdir(exist_ok=True)
        (config.model_root / "states").mkdir(exist_ok=True)

    def _state_path(self, distribution_id: str) -> Path:
        if not _DISTRIBUTION_ID.fullmatch(distribution_id):
            raise ValueError("distribution identity is invalid")
        return self.config.model_root / "states" / f"{distribution_id}.json"

    def _state(self, distribution_id: str) -> dict[str, Any]:
        path = self._state_path(distribution_id)
        if not path.is_file() or path.is_symlink():
            raise ValueError("staged distribution state was not found")
        return json.loads(path.read_bytes())

    def stage(self, wire: bytes, *, now: datetime | None = None) -> dict[str, Any]:
        if not wire or len(wire) > 10 * 1024 * 1024:
            raise ValueError("distribution bundle size is invalid")
        bundle = federation_pb2.ModelDistributionBundle.FromString(wire)
        signature = bytes(bundle.distribution_signature)
        bundle.distribution_signature = b""
        try:
            _public_key(self.config.distribution_public_key_path).verify(
                signature, bundle.SerializeToString(deterministic=True)
            )
        except InvalidSignature as exc:
            raise ValueError("Control Plane distribution signature verification failed") from exc
        if bundle.distribution_key_id != self.config.distribution_key_id:
            raise ValueError("Control Plane distribution key is not trusted")
        if (bundle.tenant_id, bundle.site_id, bundle.sensor_id) != (
            self.config.tenant_id,
            self.config.site_id,
            self.config.sensor_id,
        ):
            raise ValueError("distribution bundle Edge scope mismatch")
        current_time = now or datetime.now(timezone.utc)
        issued_at = bundle.issued_at.ToDatetime(tzinfo=timezone.utc)
        expires_at = bundle.expires_at.ToDatetime(tzinfo=timezone.utc)
        if issued_at > current_time or expires_at <= current_time:
            raise ValueError("distribution bundle is not currently valid")
        if any(
            (
                not _DISTRIBUTION_ID.fullmatch(bundle.distribution_id),
                not _RELEASE_ID.fullmatch(bundle.release_id),
                not _CANDIDATE_ID.fullmatch(bundle.candidate_id),
                not _ID.fullmatch(bundle.model_id),
                not _ID.fullmatch(bundle.model_version),
                not _ID.fullmatch(bundle.feature_contract_id),
                bundle.artifact.media_type != "application/onnx",
                not _SHA.fullmatch(bundle.artifact.sha256),
                bundle.artifact.size_bytes != len(bundle.artifact_bytes),
                _sha(bundle.artifact_bytes) != bundle.artifact.sha256,
                not 60 <= bundle.canary_observation_seconds <= 86400,
                not 0 < bundle.maximum_p95_latency_ms <= 1000,
            )
        ):
            raise ValueError("distribution artifact/canary contract is invalid")
        proof = bundle.transparency
        checkpoint = _sha(
            _canonical(
                {"log_id": proof.log_id, "sequence": proof.sequence, "entry_hash": proof.entry_hash}
            )
        )
        if (
            proof.log_id != f"sensel-models:{bundle.tenant_id}"
            or proof.sequence < 1
            or not _SHA.fullmatch(proof.entry_hash)
            or not _SHA.fullmatch(proof.previous_hash)
            or proof.checkpoint_hash != checkpoint
        ):
            raise ValueError("distribution transparency checkpoint is invalid")
        release = _verify_release(
            bytes(bundle.release_document),
            bytes(bundle.release_signature),
            public_key=_public_key(self.config.release_public_key_path),
            key_id=self.config.release_key_id,
        )
        if any(
            (
                release.get("release_id") != bundle.release_id,
                release.get("candidate_id") != bundle.candidate_id,
                release.get("candidate_version") != bundle.model_version,
                release.get("feature_contract_id") != bundle.feature_contract_id,
                release.get("artifact", {}).get("sha256") != bundle.artifact.sha256,
            )
        ):
            raise ValueError("distribution bundle does not match signed release")
        release_dir = self.config.model_root / "releases" / bundle.release_id
        if release_dir.exists():
            existing = (release_dir / "model.onnx").read_bytes()
            if _sha(existing) != bundle.artifact.sha256:
                raise ValueError("release directory already contains another artifact")
        else:
            release_dir.mkdir(mode=0o750)
            model_path = release_dir / "model.onnx"
            descriptor = os.open(model_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o440)
            try:
                view = memoryview(bundle.artifact_bytes)
                while view:
                    written = os.write(descriptor, view)
                    if written <= 0:
                        raise OSError("failed to write model artifact")
                    view = view[written:]
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            (release_dir / "bundle.pb").write_bytes(wire)
            os.chmod(release_dir / "bundle.pb", 0o440)
            _write_json(
                release_dir / "deployment.json",
                {
                    "schema_version": "sensel.edge.verified-model-deployment.v1",
                    "adapter": "xgboost",
                    "release_id": bundle.release_id,
                    "model_id": bundle.model_id,
                    "model_version": bundle.model_version,
                    "feature_contract_id": bundle.feature_contract_id,
                    "artifact_sha256": bundle.artifact.sha256.removeprefix("sha256:"),
                    "model_filename": "model.onnx",
                    "output_index": 1,
                    "anomaly_class_index": 1,
                },
            )
            os.chmod(release_dir / "deployment.json", 0o440)
            os.chmod(release_dir, 0o550)
        state = {
            "schema_version": "sensel.edge.model-rollout-state.v1",
            "distribution_id": bundle.distribution_id,
            "release_id": bundle.release_id,
            "model_id": bundle.model_id,
            "model_version": bundle.model_version,
            "feature_contract_id": bundle.feature_contract_id,
            "artifact_sha256": bundle.artifact.sha256,
            "state": "staged",
            "previous_target": "",
            "canary_observation_seconds": bundle.canary_observation_seconds,
            "maximum_inference_errors": bundle.maximum_inference_errors,
            "maximum_p95_latency_ms": bundle.maximum_p95_latency_ms,
            "transparency_checkpoint_hash": proof.checkpoint_hash,
            "staged_at": current_time.isoformat(),
        }
        state_path = self._state_path(bundle.distribution_id)
        if state_path.exists():
            existing = self._state(bundle.distribution_id)
            if (
                existing.get("release_id") != bundle.release_id
                or existing.get("artifact_sha256") != bundle.artifact.sha256
            ):
                raise ValueError("distribution identity was reused for another artifact")
            return existing
        _write_json(state_path, state)
        return state

    def activate_canary(self, distribution_id: str, *, now: datetime | None = None) -> dict[str, Any]:
        state = self._state(distribution_id)
        if state["state"] != "staged":
            raise ValueError("only a staged model can enter canary")
        current = self.config.model_root / "current"
        previous = os.readlink(current) if current.is_symlink() else ""
        target = f"releases/{state['release_id']}"
        temporary = self.config.model_root / f".current.{os.getpid()}.tmp"
        os.symlink(target, temporary)
        os.replace(temporary, current)
        activated_at = now or datetime.now(timezone.utc)
        state.update(
            {
                "state": "canary_active",
                "previous_target": previous,
                "activated_at": activated_at.isoformat(),
                "observation_deadline": (
                    activated_at + timedelta(seconds=state["canary_observation_seconds"])
                ).isoformat(),
            }
        )
        _write_json(self._state_path(distribution_id), state)
        return state

    def _rollback(self, state: dict[str, Any], reason: str, now: datetime) -> dict[str, Any]:
        current = self.config.model_root / "current"
        previous = str(state.get("previous_target") or "")
        if previous:
            temporary = self.config.model_root / f".current.{os.getpid()}.tmp"
            os.symlink(previous, temporary)
            os.replace(temporary, current)
        elif current.is_symlink():
            current.unlink()
        state.update({"state": "rolled_back", "reason": reason, "evaluated_at": now.isoformat()})
        _write_json(self._state_path(state["distribution_id"]), state)
        return state

    def evaluate(
        self,
        distribution_id: str,
        *,
        inference_count: int,
        inference_errors: int,
        p95_latency_ms: float,
        now: datetime | None = None,
    ) -> tuple[dict[str, Any], bytes]:
        state = self._state(distribution_id)
        if state["state"] != "canary_active":
            raise ValueError("only an active canary can be evaluated")
        current_time = now or datetime.now(timezone.utc)
        reason = ""
        if inference_errors > state["maximum_inference_errors"]:
            reason = "inference error budget exceeded"
        elif p95_latency_ms > state["maximum_p95_latency_ms"]:
            reason = "inference p95 latency budget exceeded"
        if reason:
            state = self._rollback(state, reason, current_time)
            report_state = federation_pb2.MODEL_ROLLOUT_STATE_ROLLED_BACK
        elif current_time >= datetime.fromisoformat(state["observation_deadline"]):
            state.update({"state": "canary_healthy", "evaluated_at": current_time.isoformat()})
            _write_json(self._state_path(distribution_id), state)
            report_state = federation_pb2.MODEL_ROLLOUT_STATE_CANARY_HEALTHY
        else:
            report_state = federation_pb2.MODEL_ROLLOUT_STATE_CANARY_ACTIVE
        current = self.config.model_root / "current"
        active_digest = ""
        if current.is_symlink() and (current / "model.onnx").is_file():
            active_digest = _sha((current / "model.onnx").read_bytes())
        report = federation_pb2.ModelRolloutReport(
            report_id="report-" + hashlib.sha256(
                _canonical(
                    {
                        "distribution_id": distribution_id,
                        "state": state["state"],
                        "evaluated_at": current_time.isoformat(),
                    }
                )
            ).hexdigest(),
            distribution_id=distribution_id,
            tenant_id=self.config.tenant_id,
            site_id=self.config.site_id,
            sensor_id=self.config.sensor_id,
            release_id=state["release_id"],
            state=report_state,
            inference_count=max(0, inference_count),
            inference_errors=max(0, inference_errors),
            p95_latency_ms=max(0, p95_latency_ms),
            active_artifact_sha256=active_digest,
            rollback_artifact_sha256=(state["artifact_sha256"] if reason else ""),
            reason=reason,
            edge_key_id=self.config.edge_report_key_id,
        )
        report.observed_at.FromDatetime(current_time)
        report.edge_signature = _private_key(self.config.edge_report_private_key_path).sign(
            report.SerializeToString(deterministic=True)
        )
        return state, report.SerializeToString(deterministic=True)
