from __future__ import annotations

from sensel_site.soak_evidence import run_soak


def test_real_sqlite_soak_emits_restore_evidence(tmp_path) -> None:
    result = run_soak(
        database=tmp_path / "site.db",
        backup_dir=tmp_path / "backups",
        duration_seconds=0.03,
        interval_seconds=0.01,
        maximum_database_bytes=10 * 1024**2,
        maximum_wal_bytes=10 * 1024**2,
        profile_id="electric-substation-iec61850",
        profile_version="1.0.0",
        environment="lab",
        tenant_id="tenant-lab",
        site_id="site-lab",
    )
    assert result["passed"] is True
    assert result["metrics"]["samples"] >= 1
    assert result["metrics"]["restore_attempts"] == result["metrics"]["samples"]
    assert result["metrics"]["pass_ratio"] == 1.0
