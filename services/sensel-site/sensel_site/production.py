"""P5 Site storage readiness and verified SQLite snapshot CLI."""

from __future__ import annotations

import argparse
import json
import time
from datetime import datetime, timezone
from pathlib import Path

from sensel_site.store import SiteStore


def _snapshot_name() -> str:
    return "site-" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + ".sqlite3"


def _prune(root: Path, retention_days: int) -> None:
    cutoff = time.time() - retention_days * 86400
    for path in root.glob("site-*.sqlite3"):
        if path.is_file() and not path.is_symlink() and path.stat().st_mtime < cutoff:
            path.unlink()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--database", type=Path, required=True)
    parser.add_argument("--maximum-database-bytes", type=int, default=10 * 1024**3)
    parser.add_argument("--maximum-wal-bytes", type=int, default=512 * 1024**2)
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--backup-dir", type=Path)
    parser.add_argument("--interval-seconds", type=int, default=0)
    parser.add_argument("--retention-days", type=int, default=30)
    args = parser.parse_args()
    if not args.check and args.backup_dir is None:
        parser.error("one of --check or --backup-dir is required")
    store = SiteStore(args.database)
    try:
        if args.check:
            result = store.production_status(
                maximum_database_bytes=args.maximum_database_bytes,
                maximum_wal_bytes=args.maximum_wal_bytes,
                verify_integrity=True,
            )
            print(json.dumps(result, sort_keys=True))
            raise SystemExit(0 if result["ready"] else 2)
        args.backup_dir.mkdir(parents=True, exist_ok=True)
        if args.backup_dir.is_symlink() or args.retention_days < 1:
            raise ValueError("Site backup policy is invalid")
        while True:
            result = store.create_verified_snapshot(args.backup_dir / _snapshot_name())
            _prune(args.backup_dir, args.retention_days)
            print(json.dumps(result, sort_keys=True), flush=True)
            if args.interval_seconds < 60:
                break
            time.sleep(args.interval_seconds)
    finally:
        store.close()


if __name__ == "__main__":
    main()
