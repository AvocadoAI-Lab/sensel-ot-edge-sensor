"""Exercise real Site SQLite health/snapshot recovery and emit P5-B soak evidence."""

from __future__ import annotations

import argparse
import json
import math
import os
import resource
import sqlite3
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

from sensel_site.store import SiteStore


def run_soak(
    *,
    database: Path,
    backup_dir: Path,
    duration_seconds: float,
    interval_seconds: float,
    maximum_database_bytes: int,
    maximum_wal_bytes: int,
    profile_id: str,
    profile_version: str,
    environment: str,
    tenant_id: str,
    site_id: str,
) -> dict:
    if duration_seconds <= 0 or interval_seconds <= 0 or environment not in {"lab", "production"}:
        raise ValueError("soak duration, interval, or environment is invalid")
    backup_dir.mkdir(parents=True, exist_ok=True)
    if backup_dir.is_symlink():
        raise ValueError("soak backup directory must not be a symlink")
    started = datetime.now(timezone.utc)
    started_monotonic = time.monotonic()
    deadline = started_monotonic + duration_seconds
    samples = 0
    failures = 0
    restore_attempts = 0
    snapshot_latencies: list[float] = []
    maximum_db = 0
    maximum_wal = 0
    store = SiteStore(database)
    try:
        while True:
            sample_started = time.monotonic()
            sample_failed = False
            status = store.production_status(
                maximum_database_bytes=maximum_database_bytes,
                maximum_wal_bytes=maximum_wal_bytes,
                verify_integrity=True,
            )
            samples += 1
            maximum_db = max(maximum_db, int(status["database_bytes"]))
            maximum_wal = max(maximum_wal, int(status["wal_bytes"]))
            if not status["ready"]:
                sample_failed = True
            target = backup_dir / f"soak-{time.time_ns()}-{uuid.uuid4().hex}.sqlite3"
            try:
                snapshot_started = time.monotonic()
                snapshot = store.create_verified_snapshot(target)
                snapshot_latencies.append(time.monotonic() - snapshot_started)
                with sqlite3.connect(f"file:{target}?mode=ro", uri=True) as restored:
                    restored_ok = (
                        restored.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
                        and restored.execute("PRAGMA foreign_key_check").fetchone() is None
                    )
            finally:
                target.unlink(missing_ok=True)
            restore_attempts += 1
            if snapshot["integrity"] != "ok" or not restored_ok:
                sample_failed = True
            if sample_failed:
                failures += 1
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            time.sleep(
                min(
                    interval_seconds,
                    remaining,
                    max(0.0, interval_seconds - (time.monotonic() - sample_started)),
                )
            )
    finally:
        store.close()
    finished = datetime.now(timezone.utc)
    elapsed = time.monotonic() - started_monotonic
    pass_ratio = (samples - failures) / samples if samples else 0.0
    sorted_latencies = sorted(snapshot_latencies)
    p95_index = max(
        0, min(len(sorted_latencies) - 1, math.ceil(len(sorted_latencies) * 0.95) - 1)
    )
    checks = {
        "samples_collected": samples > 0,
        "all_storage_checks_passed": failures == 0,
        "snapshot_restore_completed": restore_attempts == samples,
        "database_within_budget": maximum_db <= maximum_database_bytes,
        "wal_within_budget": maximum_wal <= maximum_wal_bytes,
    }
    return {
        "schema_version": "sensel.release-evidence.v1",
        "evidence_type": "edge_soak",
        "profile_id": profile_id,
        "profile_version": profile_version,
        "environment": environment,
        "run_id": "edge-soak-" + started.strftime("%Y%m%dT%H%M%SZ"),
        "started_at": started.isoformat(),
        "finished_at": finished.isoformat(),
        "subject": {"tenant_id": tenant_id, "site_id": site_id},
        "checks": checks,
        "metrics": {
            "duration_seconds": elapsed,
            "samples": samples,
            "failed_samples": failures,
            "pass_ratio": pass_ratio,
            "restore_attempts": restore_attempts,
            "maximum_database_bytes": maximum_db,
            "maximum_wal_bytes": maximum_wal,
            "snapshot_p95_seconds": sorted_latencies[p95_index],
            "maximum_rss_kib": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
        },
        "passed": all(checks.values()),
    }


def _write_new(path: Path, value: dict) -> None:
    flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags, 0o640)
    with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write("\n")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--database", type=Path, required=True)
    parser.add_argument("--backup-dir", type=Path, required=True)
    parser.add_argument("--duration-seconds", type=float, default=259200)
    parser.add_argument("--interval-seconds", type=float, default=900)
    parser.add_argument("--maximum-database-bytes", type=int, default=10 * 1024**3)
    parser.add_argument("--maximum-wal-bytes", type=int, default=512 * 1024**2)
    parser.add_argument("--profile-id", required=True)
    parser.add_argument("--profile-version", required=True)
    parser.add_argument("--environment", choices=("lab", "production"), default="lab")
    parser.add_argument("--tenant-id", required=True)
    parser.add_argument("--site-id", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = run_soak(
        database=args.database,
        backup_dir=args.backup_dir,
        duration_seconds=args.duration_seconds,
        interval_seconds=args.interval_seconds,
        maximum_database_bytes=args.maximum_database_bytes,
        maximum_wal_bytes=args.maximum_wal_bytes,
        profile_id=args.profile_id,
        profile_version=args.profile_version,
        environment=args.environment,
        tenant_id=args.tenant_id,
        site_id=args.site_id,
    )
    _write_new(args.output, result)
    print(json.dumps(result, sort_keys=True))
    if not result["passed"]:
        raise SystemExit(2)


if __name__ == "__main__":
    main()
