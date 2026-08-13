from __future__ import annotations

import hashlib
import sqlite3

import pytest

from sensel_site.store import SiteStore


def test_site_storage_health_and_verified_snapshot(tmp_path) -> None:
    store = SiteStore(tmp_path / "site.db")
    try:
        status = store.production_status(
            maximum_database_bytes=10 * 1024**2,
            maximum_wal_bytes=10 * 1024**2,
            verify_integrity=True,
        )
        assert status["ready"] is True
        target = tmp_path / "backups" / "site-test.sqlite3"
        target.parent.mkdir()
        snapshot = store.create_verified_snapshot(target)
        assert snapshot["sha256"] == "sha256:" + hashlib.sha256(target.read_bytes()).hexdigest()
        assert target.stat().st_mode & 0o077 == 0
        with sqlite3.connect(f"file:{target}?mode=ro", uri=True) as restored:
            assert restored.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
        with pytest.raises(ValueError, match="new file"):
            store.create_verified_snapshot(target)
    finally:
        store.close()


def test_site_storage_budget_fails_closed(tmp_path) -> None:
    store = SiteStore(tmp_path / "site.db")
    try:
        status = store.production_status(
            maximum_database_bytes=1,
            maximum_wal_bytes=1,
            verify_integrity=False,
        )
        assert status["ready"] is False
        assert not status["checks"]["database_budget"]
    finally:
        store.close()
