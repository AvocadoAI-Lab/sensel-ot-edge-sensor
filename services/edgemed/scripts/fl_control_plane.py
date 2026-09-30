"""Publish FL global models into Control Plane federation artifact storage."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ORG = "avocado-ai"
TENANT = "local-tenant"
DEFAULT_POSTGRES_CONTAINER = "sensel-integration-platform-postgres-1"


def _utc() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def federation_artifact_uri(round_id: str) -> str:
    return f"file://federation/{round_id}.joblib"


def default_cp_artifacts_dir() -> Path | None:
    explicit = os.environ.get("SENSEL_CP_FEDERATION_ARTIFACTS_DIR")
    if explicit:
        path = Path(explicit)
        path.mkdir(parents=True, exist_ok=True)
        return path
    edge_repo = Path(__file__).resolve().parents[3]
    candidates = (
        edge_repo.parent
        / "SenseLControlPlane-feat-i1-integration"
        / "SenseLControlPlane-feat-i1-integration"
        / "artifacts"
        / "federation-models",
        edge_repo.parent / "SenseLControlPlane-feat-i1-integration" / "artifacts" / "federation-models",
    )
    for candidate in candidates:
        if candidate.parent.parent.exists():
            candidate.mkdir(parents=True, exist_ok=True)
            return candidate
    return None


def publish_global_model(
    source: Path,
    *,
    round_id: str,
    cp_artifacts_dir: Path | None,
) -> tuple[str | None, int | None]:
    if cp_artifacts_dir is None:
        return None, None
    cp_artifacts_dir.mkdir(parents=True, exist_ok=True)
    destination = cp_artifacts_dir / f"{round_id}.joblib"
    shutil.copy2(source, destination)
    return federation_artifact_uri(round_id), int(destination.stat().st_size)


def psql(sql: str, *, container: str = DEFAULT_POSTGRES_CONTAINER) -> None:
    result = subprocess.run(
        [
            "docker",
            "exec",
            container,
            "psql",
            "-U",
            "sensel",
            "-d",
            "sensel",
            "-c",
            sql,
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        print(f"WARN postgres: {result.stderr.strip() or result.stdout.strip()}", flush=True)


def record_round(
    *,
    round_id: str,
    base_version: str,
    sample_counts: dict[str, int],
    result_sha256: str,
    epsilon: float,
    site_ids: tuple[str, ...],
    update_metadata: dict[str, dict[str, Any]] | None = None,
    artifact_uri: str | None = None,
    artifact_size_bytes: int | None = None,
    model_id: str = "ot-xgb-binary",
    created_by: str = "lab-experiment",
    robust_policy: dict[str, Any] | None = None,
) -> None:
    now = _utc()
    sites = json.dumps(list(site_ids))
    minimum_clients = len(site_ids)
    privacy = json.dumps({"accountant": "rdp-lab", "mechanism": "none-lab-proxy"})
    robust_payload = robust_policy or {
        "method": "independent-equal-tree-append",
        "minimum_clients": minimum_clients,
    }
    robust = json.dumps(robust_payload)
    artifact_uri_sql = f"'{artifact_uri}'" if artifact_uri else "NULL"
    artifact_size_sql = str(int(artifact_size_bytes)) if artifact_size_bytes is not None else "NULL"
    psql(
        "INSERT INTO federation_rounds ("
        "organization_id,tenant_id,round_id,model_id,base_model_version,feature_contract_id,"
        "state,minimum_clients,allowed_sites_json,privacy_policy_json,robust_policy_json,"
        "cumulative_epsilon,cumulative_delta,result_sha256,artifact_uri,artifact_size_bytes,"
        "created_by,created_at,updated_at"
        ") VALUES ("
        f"'{ORG}','{TENANT}','{round_id}','{model_id}','{base_version}','ciciomt-xgb-v1',"
        f"'completed',{minimum_clients},'{sites}','{privacy}','{robust}',"
        f"{epsilon},0.0,'{result_sha256}',{artifact_uri_sql},{artifact_size_sql},"
        f"'{created_by}','{now}','{now}'"
        ") ON CONFLICT (organization_id, tenant_id, round_id) DO UPDATE SET "
        f"state='completed', model_id='{model_id}', result_sha256='{result_sha256}', "
        f"artifact_uri={artifact_uri_sql}, artifact_size_bytes={artifact_size_sql}, "
        f"updated_at='{now}', cumulative_epsilon={epsilon}, "
        f"privacy_policy_json='{privacy}', robust_policy_json='{robust}';"
    )
    for site_id, count in sample_counts.items():
        update_id = str(uuid.uuid4())
        vector_payload: dict[str, Any] = {
            "kind": "xgb_tree_update",
            "site_id": site_id,
            "sample_count": count,
        }
        if update_metadata and site_id in update_metadata:
            vector_payload.update(update_metadata[site_id])
        vector = json.dumps(vector_payload)
        psql(
            "INSERT INTO federation_updates ("
            "organization_id,tenant_id,round_id,site_id,update_id,trust_domain_id,enrollment_id,"
            "rate_policy_id,vector_json,sample_count,l2_norm,clipped,epsilon_spent,delta_spent,"
            "accepted,reason,submitted_at"
            ") VALUES ("
            f"'{ORG}','{TENANT}','{round_id}','{site_id}','{update_id}','lab-domain','lab-enroll',"
            f"'lab-rate','{vector}',{int(count)},1.0,1,{epsilon / max(len(sample_counts), 1):.6f},0.0,"
            f"1,'accepted','{now}'"
            ") ON CONFLICT (organization_id, tenant_id, round_id, site_id) DO UPDATE SET "
            f"vector_json='{vector}',sample_count={int(count)},accepted=1,reason='accepted',submitted_at='{now}';"
        )
