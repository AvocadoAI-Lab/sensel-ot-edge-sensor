"""Human-gated release signer that never imports or reads model formats."""

from __future__ import annotations

import json
import os
import re
import shutil
import uuid
from datetime import datetime, timezone
from typing import Any

from sensel_site.lineage import canonical_json, load_private_key, sha256_bytes
from sensel_site.signed_documents import (
    encode_embedded_signed_document,
    read_regular_file,
    write_exclusive,
)
from sensel_site.worker_config import ReleaseSignerConfig

MANUAL_APPROVAL_SCHEMA = "sensel.site.manual-release-approval.v1"
RELEASE_SCHEMA = "sensel.site.model-release-authorization.v1"
_TEXT_ID = re.compile(r"^[A-Za-z0-9@._:+/-]{1,160}$")
_REVIEWED_EVIDENCE = {
    "asset-time-holdout",
    "arm-benchmark",
    "prediction-parity",
    "ubjson-to-onnx-conversion",
}


def _read_audited_bundle(config: ReleaseSignerConfig) -> tuple[dict[str, Any], str]:
    root = config.approval_bundle_root / config.job_id
    if root.is_symlink() or not root.is_dir():
        raise ValueError("approval bundle directory is invalid")
    payload = read_regular_file(root / "approval-bundle.json", maximum_bytes=1_048_576)
    audit = json.loads(
        read_regular_file(root / "approval-bundle.sha256", maximum_bytes=4096)
    )
    digest = sha256_bytes(payload)
    if audit != {"algorithm": "SHA-256", "sha256": digest}:
        raise ValueError("approval bundle audit digest mismatch")
    bundle = json.loads(payload)
    if any(
        (
            bundle.get("schema_version") != "sensel.site.release-approval-bundle.v1",
            bundle.get("job_id") != config.job_id,
            (bundle.get("tenant_id"), bundle.get("site_id"))
            != (config.tenant_id, config.site_id),
            bundle.get("technical_status") != "technically_validated",
            bundle.get("model_bytes_in_bundle") is not False,
            bundle.get("activation_performed") is not False,
        )
    ):
        raise ValueError("approval bundle is not release-eligible")
    return bundle, digest


def _parse_timestamp(value: Any, name: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"manual approval {name} is invalid") from exc
    if parsed.tzinfo is None:
        raise ValueError(f"manual approval {name} requires timezone")
    return parsed.astimezone(timezone.utc)


def _read_manual_approval(
    config: ReleaseSignerConfig,
    bundle: dict[str, Any],
) -> tuple[dict[str, Any], str]:
    payload = read_regular_file(config.manual_approval_path, maximum_bytes=65_536)
    approval = json.loads(payload)
    if not isinstance(approval, dict):
        raise ValueError("manual approval must be a JSON object")
    if any(
        (
            approval.get("schema_version") != MANUAL_APPROVAL_SCHEMA,
            approval.get("decision") != "approve",
            approval.get("human_review_performed") is not True,
            approval.get("model_parser_used") is not False,
            approval.get("job_id") != config.job_id,
            (approval.get("tenant_id"), approval.get("site_id"))
            != (config.tenant_id, config.site_id),
        )
    ):
        raise ValueError("manual approval contract is invalid")
    for name in (
        "candidate_id",
        "conversion_id",
        "conversion_manifest_sha256",
        "onnx_artifact_sha256",
    ):
        if approval.get(name) != bundle.get(name):
            raise ValueError(f"manual approval does not match technical bundle: {name}")
    for name in ("approver", "ticket_id"):
        if not _TEXT_ID.fullmatch(str(approval.get(name) or "")):
            raise ValueError(f"manual approval {name} is invalid")
    reason = str(approval.get("reason") or "").strip()
    if not 8 <= len(reason) <= 1024:
        raise ValueError("manual approval reason is invalid")
    reviewed = approval.get("reviewed_evidence")
    if not isinstance(reviewed, list) or set(reviewed) != _REVIEWED_EVIDENCE:
        raise ValueError("manual approval evidence checklist is incomplete")
    approved_at = _parse_timestamp(approval.get("approved_at"), "approved_at")
    expires_at = _parse_timestamp(approval.get("expires_at"), "expires_at")
    now = datetime.now(timezone.utc)
    if approved_at > now or expires_at <= now or expires_at <= approved_at:
        raise ValueError("manual approval is not currently valid")
    return approval, sha256_bytes(canonical_json(approval))


def sign_release_authorization(config: ReleaseSignerConfig) -> dict[str, Any]:
    bundle, bundle_digest = _read_audited_bundle(config)
    approval, approval_digest = _read_manual_approval(config, bundle)
    private_key = load_private_key(config.release_private_key_path)
    identity = {
        "job_id": config.job_id,
        "candidate_id": bundle["candidate_id"],
        "conversion_id": bundle["conversion_id"],
        "onnx_artifact_sha256": bundle["onnx_artifact_sha256"],
        "approval_bundle_sha256": bundle_digest,
        "manual_approval_sha256": approval_digest,
        "release_key_id": config.release_key_id,
    }
    release_id = "release-" + sha256_bytes(canonical_json(identity)).removeprefix(
        "sha256:"
    )
    release: dict[str, Any] = {
        "schema_version": RELEASE_SCHEMA,
        "release_id": release_id,
        "job_id": config.job_id,
        "candidate_id": bundle["candidate_id"],
        "conversion_id": bundle["conversion_id"],
        "tenant_id": config.tenant_id,
        "site_id": config.site_id,
        "candidate_version": bundle["candidate_version"],
        "feature_contract_id": bundle["feature_contract_id"],
        "artifact": {
            "media_type": "application/onnx",
            "sha256": bundle["onnx_artifact_sha256"],
            "embedded_in_release": False,
        },
        "technical_evidence": {
            "approval_bundle_sha256": bundle_digest,
            "conversion_manifest_sha256": bundle["conversion_manifest_sha256"],
            "architecture": bundle["architecture"],
        },
        "manual_approval": {
            "sha256": approval_digest,
            "approver": approval["approver"],
            "ticket_id": approval["ticket_id"],
            "approved_at": approval["approved_at"],
            "expires_at": approval["expires_at"],
            "reason": approval["reason"],
            "human_review_performed": True,
        },
        "authorization": {
            "state": "release_signed",
            "manual_approval_required": True,
            "automatic_release_allowed": False,
            "distribution_performed": False,
            "activation_performed": False,
        },
        "signed_at": datetime.now(timezone.utc).isoformat(),
    }
    document, signature, _ = encode_embedded_signed_document(
        release,
        private_key=private_key,
        key_id=config.release_key_id,
    )
    final = config.release_root / config.job_id
    if final.exists():
        raise ValueError("immutable release authorization already exists")
    staging = config.release_root / ".staging" / f"{config.job_id}-{uuid.uuid4()}"
    staging.mkdir(parents=True, mode=0o750)
    try:
        write_exclusive(staging / "release.json", document)
        write_exclusive(staging / "release.sig", signature)
        final.parent.mkdir(parents=True, exist_ok=True)
        os.replace(staging, final)
        os.chmod(final, 0o555)
    except Exception:
        shutil.rmtree(staging, ignore_errors=True)
        raise
    return json.loads(document)


def main() -> None:
    result = sign_release_authorization(ReleaseSignerConfig.from_env())
    print(
        json.dumps(
            {
                "release_id": result["release_id"],
                "candidate_id": result["candidate_id"],
                "state": result["authorization"]["state"],
                "distribution_performed": False,
                "activation_performed": False,
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
