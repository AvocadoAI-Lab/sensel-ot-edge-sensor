"""Copy existing FL global models into Control Plane federation-models and update Postgres."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from scripts.fl_control_plane import (
    DEFAULT_POSTGRES_CONTAINER,
    default_cp_artifacts_dir,
    federation_artifact_uri,
    psql,
    publish_global_model,
)

DEFAULT_CP_ROOT = (
    ROOT.parents[2].parent
    / "SenseLControlPlane-feat-i1-integration"
    / "SenseLControlPlane-feat-i1-integration"
)


def _utc() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def _round_sources(experiment_dir: Path, *, round_prefix: str, rounds: range) -> list[tuple[str, Path]]:
    models_dir = experiment_dir / "models"
    if not models_dir.is_dir():
        return []
    out: list[tuple[str, Path]] = []
    for round_no in rounds:
        round_id = round_prefix.format(n=round_no)
        candidates = (
            models_dir / f"fl-round-{round_no:03d}.joblib",
            models_dir / f"{round_id}.joblib",
        )
        for candidate in candidates:
            if candidate.is_file():
                out.append((round_id, candidate))
                break
    return out


def _cohort_round_sources(experiment_dir: Path, cohorts: tuple[str, ...], rounds: range) -> list[tuple[str, Path]]:
    models_dir = experiment_dir / "models"
    if not models_dir.is_dir():
        return []
    out: list[tuple[str, Path]] = []
    for cohort in cohorts:
        for round_no in rounds:
            round_id = f"lab-{cohort}-round-{round_no:03d}"
            candidate = models_dir / f"cohort-{cohort}-round-{round_no:03d}.joblib"
            if candidate.is_file():
                out.append((round_id, candidate))
    return out


def discover_sources(edge_artifacts: Path) -> list[tuple[str, Path, str]]:
    """Return (round_id, source_path, experiment_label)."""
    discovered: list[tuple[str, Path, str]] = []
    three_site = edge_artifacts / "fl-experiment"
    for round_id, path in _round_sources(three_site, round_prefix="lab-round-{n:03d}", rounds=range(1, 6)):
        discovered.append((round_id, path, "fl-experiment-three-site"))

    six_cohort = edge_artifacts / "fl-experiment-six-cohort-hpo-full"
    for round_id, path in _cohort_round_sources(
        six_cohort, ("wifi", "mqtt", "network"), range(1, 8)
    ):
        discovered.append((round_id, path, "fl-experiment-six-cohort-hpo-full"))

    three_cohort = edge_artifacts / "fl-experiment-three-cohort-hpo-full"
    for round_id, path in _cohort_round_sources(
        three_cohort, ("wifi", "mqtt", "network"), range(1, 8)
    ):
        discovered.append((round_id, path, "fl-experiment-three-cohort-hpo-full"))

    three_hpo = edge_artifacts / "fl-experiment-three-hpo-full"
    for round_id, path in _round_sources(three_hpo, round_prefix="lab-round-{n:03d}", rounds=range(1, 8)):
        if not any(item[0] == round_id for item in discovered):
            discovered.append((round_id, path, "fl-experiment-three-hpo-full"))
    return discovered


def postgres_available(container: str) -> bool:
    import subprocess

    result = subprocess.run(
        ["docker", "exec", container, "psql", "-U", "sensel", "-d", "sensel", "-c", "SELECT 1"],
        capture_output=True,
        text=True,
        check=False,
    )
    return result.returncode == 0


def update_postgres(round_id: str, *, digest: str, size_bytes: int, artifact_uri: str, container: str) -> None:
    now = _utc()
    psql(
        "UPDATE federation_rounds SET "
        f"artifact_uri='{artifact_uri}', artifact_size_bytes={size_bytes}, "
        f"result_sha256='{digest}', updated_at='{now}' "
        f"WHERE organization_id='avocado-ai' AND tenant_id='local-tenant' AND round_id='{round_id}';",
        container=container,
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--edge-artifacts", type=Path, default=ROOT / "artifacts")
    parser.add_argument("--cp-artifacts-dir", type=Path, default=None)
    parser.add_argument("--cp-root", type=Path, default=DEFAULT_CP_ROOT)
    parser.add_argument("--postgres-container", type=str, default=DEFAULT_POSTGRES_CONTAINER)
    parser.add_argument("--skip-postgres", action="store_true")
    args = parser.parse_args()

    cp_dir = args.cp_artifacts_dir or default_cp_artifacts_dir()
    if cp_dir is None:
        cp_dir = args.cp_root / "artifacts" / "federation-models"
    cp_dir.mkdir(parents=True, exist_ok=True)

    sources = discover_sources(args.edge_artifacts)
    if not sources:
        print("No FL model sources found under edge artifacts.", flush=True)
        return 1

    published: list[dict[str, object]] = []
    for round_id, source, experiment in sources:
        artifact_uri, size_bytes = publish_global_model(
            source, round_id=round_id, cp_artifacts_dir=cp_dir
        )
        if artifact_uri is None or size_bytes is None:
            continue
        digest = sha256_file(cp_dir / f"{round_id}.joblib")
        entry = {
            "round_id": round_id,
            "experiment": experiment,
            "source": str(source),
            "destination": str(cp_dir / f"{round_id}.joblib"),
            "artifact_uri": artifact_uri,
            "artifact_size_bytes": size_bytes,
            "artifact_sha256": digest,
        }
        published.append(entry)
        print(f"published {round_id} ({size_bytes} bytes) from {experiment}", flush=True)

    manifest = {
        "generated_at": _utc(),
        "cp_artifacts_dir": str(cp_dir),
        "published_count": len(published),
        "items": published,
    }
    manifest_path = args.cp_root / "artifacts" / "lab-validation" / "cp-federation-models-manifest.json"
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"wrote manifest: {manifest_path}", flush=True)

    sql_lines = ["-- Generated by backfill_cp_federation_models.py", f"-- {_utc()}", ""]
    if not args.skip_postgres and postgres_available(args.postgres_container):
        for item in published:
            update_postgres(
                str(item["round_id"]),
                digest=str(item["artifact_sha256"]),
                size_bytes=int(item["artifact_size_bytes"]),
                artifact_uri=str(item["artifact_uri"]),
                container=args.postgres_container,
            )
        print(f"updated postgres via {args.postgres_container}", flush=True)
    else:
        for item in published:
            sql_lines.append(
                "UPDATE federation_rounds SET "
                f"artifact_uri='{item['artifact_uri']}', "
                f"artifact_size_bytes={item['artifact_size_bytes']}, "
                f"result_sha256='{item['artifact_sha256']}', "
                f"updated_at='{_utc()}' "
                f"WHERE organization_id='avocado-ai' AND tenant_id='local-tenant' "
                f"AND round_id='{item['round_id']}';"
            )
        sql_path = manifest_path.parent / "backfill-federation-artifacts.sql"
        sql_path.write_text("\n".join(sql_lines) + "\n", encoding="utf-8")
        print(f"postgres unavailable; wrote SQL: {sql_path}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
