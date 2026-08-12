"""Durable Site episode, label, dataset lineage, and artifact metadata store."""

from __future__ import annotations

import json
import sqlite3
import threading
import uuid
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from sensel_site.contracts import EpisodeReceipt


def _json(value: Any) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    )


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


class EpisodeConflict(ValueError):
    pass


class SiteStore:
    def __init__(self, db_path: str | Path) -> None:
        self.path = Path(db_path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(
            self.path,
            check_same_thread=False,
            isolation_level=None,
        )
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=FULL")
        self._conn.execute("PRAGMA foreign_keys=ON")
        self._conn.execute("PRAGMA busy_timeout=5000")
        self._init_schema()

    @contextmanager
    def _transaction(self) -> Iterator[sqlite3.Connection]:
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                yield self._conn
            except BaseException:
                self._conn.rollback()
                raise
            else:
                self._conn.commit()

    def _init_schema(self) -> None:
        with self._transaction() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS episode_receipts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    tenant_id TEXT NOT NULL,
                    site_id TEXT NOT NULL,
                    sensor_id TEXT NOT NULL,
                    episode_id TEXT NOT NULL,
                    asset_id TEXT NOT NULL,
                    observed_at TEXT NOT NULL,
                    started_at TEXT NOT NULL,
                    ended_at TEXT NOT NULL,
                    feature_contract_id TEXT NOT NULL,
                    sequence_ref TEXT NOT NULL,
                    sequence_length INTEGER NOT NULL,
                    feature_values TEXT NOT NULL,
                    fusion_decision TEXT NOT NULL,
                    fusion_score REAL NOT NULL,
                    fusion_severity TEXT NOT NULL,
                    policy_version TEXT NOT NULL,
                    trace_id TEXT NOT NULL,
                    producer_version TEXT NOT NULL,
                    payload_sha256 TEXT NOT NULL,
                    protobuf_payload BLOB NOT NULL,
                    retention_class TEXT NOT NULL,
                    expires_at TEXT NOT NULL,
                    received_at TEXT NOT NULL,
                    UNIQUE (tenant_id, site_id, sensor_id, episode_id)
                );
                CREATE INDEX IF NOT EXISTS ix_episode_scope_contract_time
                    ON episode_receipts (
                        tenant_id, site_id, feature_contract_id, ended_at
                    );
                CREATE INDEX IF NOT EXISTS ix_episode_expiry
                    ON episode_receipts (expires_at);

                CREATE TABLE IF NOT EXISTS episode_labels (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    label_id TEXT NOT NULL UNIQUE,
                    episode_pk INTEGER NOT NULL,
                    source TEXT NOT NULL,
                    label TEXT NOT NULL,
                    actor TEXT NOT NULL,
                    reason TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY (episode_pk) REFERENCES episode_receipts(id)
                        ON DELETE CASCADE
                );
                CREATE INDEX IF NOT EXISTS ix_episode_labels_episode_source
                    ON episode_labels (episode_pk, source, id DESC);

                CREATE TABLE IF NOT EXISTS dataset_manifests (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    dataset_id TEXT NOT NULL UNIQUE,
                    tenant_id TEXT NOT NULL,
                    site_id TEXT NOT NULL,
                    feature_contract_id TEXT NOT NULL,
                    feature_contract_version TEXT NOT NULL,
                    feature_contract_definition_sha256 TEXT NOT NULL,
                    label_source TEXT NOT NULL,
                    retention_class TEXT NOT NULL,
                    retention_days INTEGER NOT NULL,
                    sample_count INTEGER NOT NULL,
                    sample_digest TEXT NOT NULL,
                    manifest_digest TEXT NOT NULL UNIQUE,
                    manifest_json TEXT NOT NULL,
                    export_path TEXT,
                    signature_key_id TEXT,
                    signature_b64 TEXT,
                    expires_at TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS ix_dataset_scope_created
                    ON dataset_manifests (tenant_id, site_id, created_at DESC);

                CREATE TABLE IF NOT EXISTS trainer_jobs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    job_id TEXT NOT NULL UNIQUE,
                    dataset_id TEXT NOT NULL,
                    algorithm TEXT NOT NULL,
                    model_id TEXT NOT NULL,
                    base_model_version TEXT NOT NULL,
                    feature_contract_id TEXT NOT NULL,
                    request_digest TEXT NOT NULL UNIQUE,
                    request_json TEXT NOT NULL,
                    inbox_path TEXT NOT NULL,
                    state TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY (dataset_id) REFERENCES dataset_manifests(dataset_id)
                );

                CREATE TABLE IF NOT EXISTS artifact_cache (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    kind TEXT NOT NULL,
                    artifact_id TEXT NOT NULL,
                    version TEXT NOT NULL,
                    sha256 TEXT NOT NULL,
                    media_type TEXT NOT NULL,
                    path TEXT NOT NULL,
                    metadata_json TEXT NOT NULL,
                    activated INTEGER NOT NULL DEFAULT 0,
                    created_at TEXT NOT NULL,
                    UNIQUE (kind, artifact_id, version)
                );

                CREATE TABLE IF NOT EXISTS ingress_dead_letters (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    topic TEXT NOT NULL,
                    payload_sha256 TEXT NOT NULL,
                    content_type TEXT NOT NULL,
                    error TEXT NOT NULL,
                    received_at TEXT NOT NULL,
                    UNIQUE (topic, payload_sha256)
                );
                """
            )

    def insert_episode(
        self,
        receipt: EpisodeReceipt,
        *,
        retention_days: int,
    ) -> bool:
        if retention_days <= 0:
            raise ValueError("episode retention_days must be positive")
        received_at = _utc_now()
        expires_at = received_at + timedelta(days=retention_days)
        with self._transaction() as conn:
            existing = conn.execute(
                """
                SELECT payload_sha256 FROM episode_receipts
                WHERE tenant_id = ? AND site_id = ? AND sensor_id = ?
                  AND episode_id = ?
                """,
                (
                    receipt.tenant_id,
                    receipt.site_id,
                    receipt.sensor_id,
                    receipt.episode_id,
                ),
            ).fetchone()
            if existing:
                if existing["payload_sha256"] != receipt.payload_sha256:
                    raise EpisodeConflict(
                        "episode identity was reused with different protobuf content"
                    )
                return False
            conn.execute(
                """
                INSERT INTO episode_receipts (
                    tenant_id, site_id, sensor_id, episode_id, asset_id,
                    observed_at, started_at, ended_at, feature_contract_id,
                    sequence_ref, sequence_length, feature_values,
                    fusion_decision, fusion_score, fusion_severity,
                    policy_version, trace_id, producer_version,
                    payload_sha256, protobuf_payload, retention_class,
                    expires_at, received_at
                ) VALUES (
                    ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                    ?, ?, ?, ?, ?
                )
                """,
                (
                    receipt.tenant_id,
                    receipt.site_id,
                    receipt.sensor_id,
                    receipt.episode_id,
                    receipt.asset_id,
                    receipt.observed_at,
                    receipt.started_at,
                    receipt.ended_at,
                    receipt.feature_contract_id,
                    receipt.sequence_ref,
                    receipt.sequence_length,
                    _json(list(receipt.feature_values)),
                    receipt.fusion_decision,
                    receipt.fusion_score,
                    receipt.fusion_severity,
                    receipt.policy_version,
                    receipt.trace_id,
                    receipt.producer_version,
                    receipt.payload_sha256,
                    sqlite3.Binary(receipt.protobuf_payload),
                    "site-security",
                    expires_at.isoformat(),
                    received_at.isoformat(),
                ),
            )
        return True

    def record_dead_letter(
        self,
        *,
        topic: str,
        payload_sha256: str,
        content_type: str,
        error: str,
    ) -> bool:
        with self._transaction() as conn:
            cursor = conn.execute(
                """
                INSERT OR IGNORE INTO ingress_dead_letters (
                    topic, payload_sha256, content_type, error, received_at
                ) VALUES (?, ?, ?, ?, ?)
                """,
                (
                    topic[:1024],
                    payload_sha256,
                    content_type[:512],
                    error[:2048],
                    _utc_now().isoformat(),
                ),
            )
        return cursor.rowcount > 0

    def add_manual_label(
        self,
        *,
        tenant_id: str,
        site_id: str,
        episode_id: str,
        label: str,
        actor: str,
        reason: str,
        sensor_id: str | None = None,
    ) -> str:
        if not all(value.strip() for value in (label, actor, reason)):
            raise ValueError("manual label, actor and reason are required")
        if len(label.strip()) > 128 or len(actor.strip()) > 128 or len(reason.strip()) > 2048:
            raise ValueError("manual label metadata is too long")
        with self._transaction() as conn:
            query = """
                SELECT id FROM episode_receipts
                WHERE tenant_id = ? AND site_id = ? AND episode_id = ?
            """
            parameters: list[Any] = [tenant_id, site_id, episode_id]
            if sensor_id:
                query += " AND sensor_id = ?"
                parameters.append(sensor_id)
            episodes = conn.execute(query + " ORDER BY id ASC LIMIT 2", parameters).fetchall()
            if not episodes:
                raise LookupError(f"episode not found: {episode_id}")
            if len(episodes) > 1:
                raise LookupError(
                    f"episode identity is ambiguous; specify sensor_id: {episode_id}"
                )
            episode = episodes[0]
            label_id = f"label-{uuid.uuid4()}"
            conn.execute(
                """
                INSERT INTO episode_labels (
                    label_id, episode_pk, source, label, actor, reason, created_at
                ) VALUES (?, ?, 'manual', ?, ?, ?, ?)
                """,
                (
                    label_id,
                    int(episode["id"]),
                    label.strip(),
                    actor.strip()[:128],
                    reason.strip()[:2048],
                    _utc_now().isoformat(),
                ),
            )
        return label_id

    def select_dataset_rows(
        self,
        *,
        tenant_id: str,
        site_id: str,
        feature_contract_id: str,
        label_source: str,
        started_at: str | None,
        ended_at: str | None,
        limit: int,
    ) -> list[dict[str, Any]]:
        if label_source not in {"fusion_decision", "manual", "unlabeled"}:
            raise ValueError("unsupported dataset label_source")
        clauses = [
            "e.tenant_id = ?",
            "e.site_id = ?",
            "e.feature_contract_id = ?",
            "e.expires_at >= ?",
        ]
        parameters: list[Any] = [
            tenant_id,
            site_id,
            feature_contract_id,
            _utc_now().isoformat(),
        ]
        if started_at:
            clauses.append("e.ended_at >= ?")
            parameters.append(started_at)
        if ended_at:
            clauses.append("e.ended_at <= ?")
            parameters.append(ended_at)
        if label_source == "manual":
            clauses.append(
                "EXISTS (SELECT 1 FROM episode_labels eligible_label "
                "WHERE eligible_label.episode_pk = e.id "
                "AND eligible_label.source = 'manual')"
            )
        elif label_source == "unlabeled":
            clauses.append(
                "NOT EXISTS (SELECT 1 FROM episode_labels existing_label "
                "WHERE existing_label.episode_pk = e.id "
                "AND existing_label.source = 'manual')"
            )
        parameters.append(limit)
        with self._lock:
            rows = self._conn.execute(
                f"""
                SELECT e.* FROM episode_receipts e
                WHERE {' AND '.join(clauses)}
                ORDER BY e.ended_at ASC, e.sensor_id ASC, e.episode_id ASC
                LIMIT ?
                """,
                parameters,
            ).fetchall()
            documents: list[dict[str, Any]] = []
            for row in rows:
                label: str | None = None
                label_ref = ""
                if label_source == "fusion_decision":
                    label = str(row["fusion_decision"])
                    label_ref = (
                        f"fusion:{row['policy_version']}:{row['payload_sha256']}"
                    )
                elif label_source == "manual":
                    manual = self._conn.execute(
                        """
                        SELECT label_id, label FROM episode_labels
                        WHERE episode_pk = ? AND source = 'manual'
                        ORDER BY id DESC LIMIT 1
                        """,
                        (int(row["id"]),),
                    ).fetchone()
                    if manual is None:
                        continue
                    label = str(manual["label"])
                    label_ref = str(manual["label_id"])
                documents.append(
                    {
                        "episode_pk": int(row["id"]),
                        "episode_id": str(row["episode_id"]),
                        "sensor_id": str(row["sensor_id"]),
                        "asset_id": str(row["asset_id"]),
                        "ended_at": str(row["ended_at"]),
                        "feature_contract_id": str(row["feature_contract_id"]),
                        "sequence_ref": str(row["sequence_ref"]),
                        "sequence_length": int(row["sequence_length"]),
                        "features": json.loads(row["feature_values"]),
                        "label": label,
                        "label_source": label_source,
                        "label_ref": label_ref,
                        "episode_payload_sha256": str(row["payload_sha256"]),
                        "producer_version": str(row["producer_version"]),
                    }
                )
        return documents

    def save_dataset_manifest(
        self,
        manifest: Mapping[str, Any],
        *,
        sample_digest: str,
        manifest_digest: str,
    ) -> bool:
        with self._transaction() as conn:
            existing = conn.execute(
                "SELECT manifest_digest FROM dataset_manifests WHERE dataset_id = ?",
                (manifest["dataset_id"],),
            ).fetchone()
            if existing:
                if existing["manifest_digest"] != manifest_digest:
                    raise EpisodeConflict(
                        "dataset identity was reused with different lineage"
                    )
                return False
            conn.execute(
                """
                INSERT INTO dataset_manifests (
                    dataset_id, tenant_id, site_id, feature_contract_id,
                    feature_contract_version,
                    feature_contract_definition_sha256, label_source,
                    retention_class, retention_days,
                    sample_count, sample_digest, manifest_digest,
                    manifest_json, expires_at, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    manifest["dataset_id"],
                    manifest["tenant_id"],
                    manifest["site_id"],
                    manifest["feature_contract_id"],
                    manifest["feature_contract_version"],
                    manifest["feature_contract_definition_sha256"],
                    manifest["label_source"],
                    manifest["retention"]["class"],
                    manifest["retention"]["days"],
                    manifest["sample_count"],
                    sample_digest,
                    manifest_digest,
                    _json(dict(manifest)),
                    manifest["retention"]["expires_at"],
                    manifest["created_at"],
                ),
            )
        return True

    def get_dataset(self, dataset_id: str) -> dict[str, Any]:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM dataset_manifests WHERE dataset_id = ?",
                (dataset_id,),
            ).fetchone()
        if row is None:
            raise LookupError(f"dataset not found: {dataset_id}")
        document = dict(row)
        document["manifest"] = json.loads(document.pop("manifest_json"))
        return document

    def mark_dataset_exported(
        self,
        *,
        dataset_id: str,
        export_path: str,
        key_id: str,
        signature_b64: str,
    ) -> None:
        with self._transaction() as conn:
            cursor = conn.execute(
                """
                UPDATE dataset_manifests
                SET export_path = ?, signature_key_id = ?, signature_b64 = ?
                WHERE dataset_id = ?
                """,
                (export_path, key_id, signature_b64, dataset_id),
            )
            if cursor.rowcount != 1:
                raise LookupError(f"dataset not found: {dataset_id}")

    def save_trainer_job(
        self,
        request: Mapping[str, Any],
        *,
        request_digest: str,
        inbox_path: str,
    ) -> bool:
        with self._transaction() as conn:
            existing = conn.execute(
                "SELECT request_digest FROM trainer_jobs WHERE job_id = ?",
                (request["job_id"],),
            ).fetchone()
            if existing:
                if existing["request_digest"] != request_digest:
                    raise EpisodeConflict(
                        "trainer job identity was reused with different content"
                    )
                return False
            conn.execute(
                """
                INSERT INTO trainer_jobs (
                    job_id, dataset_id, algorithm, model_id,
                    base_model_version, feature_contract_id, request_digest,
                    request_json, inbox_path, state, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'prepared', ?)
                """,
                (
                    request["job_id"],
                    request["dataset_id"],
                    request["algorithm"],
                    request["model_id"],
                    request["base_model_version"],
                    request["feature_contract_id"],
                    request_digest,
                    _json(dict(request)),
                    inbox_path,
                    request["created_at"],
                ),
            )
        return True

    def save_cached_artifact(
        self,
        *,
        kind: str,
        artifact_id: str,
        version: str,
        sha256: str,
        media_type: str,
        path: str,
        metadata: Mapping[str, Any],
    ) -> bool:
        with self._transaction() as conn:
            existing = conn.execute(
                """
                SELECT sha256 FROM artifact_cache
                WHERE kind = ? AND artifact_id = ? AND version = ?
                """,
                (kind, artifact_id, version),
            ).fetchone()
            if existing:
                if existing["sha256"] != sha256:
                    raise EpisodeConflict(
                        "artifact version was reused with different content"
                    )
                return False
            conn.execute(
                """
                INSERT INTO artifact_cache (
                    kind, artifact_id, version, sha256, media_type, path,
                    metadata_json, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    kind,
                    artifact_id,
                    version,
                    sha256,
                    media_type,
                    path,
                    _json(dict(metadata)),
                    _utc_now().isoformat(),
                ),
            )
        return True

    def counts(self) -> dict[str, int]:
        with self._lock:
            return {
                table: int(
                    self._conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
                )
                for table in (
                    "episode_receipts",
                    "ingress_dead_letters",
                    "dataset_manifests",
                    "trainer_jobs",
                )
            }

    def close(self) -> None:
        with self._lock:
            self._conn.close()
