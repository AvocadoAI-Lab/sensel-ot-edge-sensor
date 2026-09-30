"""Managed black/white list edge apply: cache build / signed apply / idempotency."""

from __future__ import annotations

import json
from pathlib import Path

from src.config.settings import (
    AppConfig,
    LoggingConfig,
    PolicySyncConfig,
    SenselConfig,
    SensorIdentity,
)
from src.policy.listfile_sync import ListfileSync, build_cache_from_artifact

SECRET = "edge-secret-xyz"
TENANT = "tenant-a"

ARTIFACT = {
    "schema_version": "ot_listfile_feed.v1",
    "tenant_id": TENANT,
    "version": "2026.06.20.1",
    "lists": [
        {
            "id": "l1",
            "list_type": "blacklist",
            "entry_kind": "ip",
            "entries": ["203.0.113.10", "203.0.113.11", "203.0.113.10"],
        },
        {
            "id": "l2",
            "list_type": "whitelist",
            "entry_kind": "domain",
            "entries": ["trusted.example.com"],
        },
        {
            "id": "l3",
            "list_type": "blacklist",
            "entry_kind": "cidr",
            "entries": ["10.0.0.0/8"],
        },
    ],
}


def _config(tmp_path: Path) -> AppConfig:
    return AppConfig(
        sensor=SensorIdentity(id="s1", site_id="factory-lab-001"),
        sensel=SenselConfig(api_url="http://127.0.0.1:8081", api_key="k"),
        policy_sync=PolicySyncConfig(
            feed_tenant_id=TENANT,
            listfile_enabled=True,
            listfile_cache_path=str(tmp_path / "managed-listfiles.json"),
            listfile_stamp_path=str(tmp_path / "managed-listfiles.stamp"),
            ids_rule_signing_secret=SECRET,
        ),
        logging=LoggingConfig(),
    )


def test_build_cache_groups_and_dedups() -> None:
    cache = build_cache_from_artifact(ARTIFACT, tenant_id=TENANT, etag="e1")
    assert cache["deny"]["ip"] == ["203.0.113.10", "203.0.113.11"]
    assert cache["deny"]["cidr"] == ["10.0.0.0/8"]
    assert cache["allow"]["domain"] == ["trusted.example.com"]
    assert cache["item_count"] == 4


def test_apply_writes_cache_and_stamp(tmp_path: Path) -> None:
    sync = ListfileSync(_config(tmp_path))
    res = sync.apply_artifact(ARTIFACT, tenant_id=TENANT, etag="e1")
    assert res.ok and res.changed
    assert res.item_count == 4
    cache = json.loads((tmp_path / "managed-listfiles.json").read_text(encoding="utf-8"))
    assert cache["artifact_version"] == "2026.06.20.1"
    assert cache["deny"]["ip"] == ["203.0.113.10", "203.0.113.11"]
    assert (tmp_path / "managed-listfiles.stamp").is_file()


def test_apply_idempotent_same_etag(tmp_path: Path) -> None:
    sync = ListfileSync(_config(tmp_path))
    sync.apply_artifact(ARTIFACT, tenant_id=TENANT, etag="e1")
    again = sync.apply_artifact(ARTIFACT, tenant_id=TENANT, etag="e1")
    assert again.ok and not again.changed


def test_ack_callback_emitted_once_on_change(tmp_path: Path) -> None:
    acks: list[dict] = []
    sync = ListfileSync(_config(tmp_path), ack_callback=acks.append)
    sync.apply_artifact(ARTIFACT, tenant_id=TENANT, etag="e1")
    assert len(acks) == 1
    assert acks[0]["status"] == "ack"
    assert acks[0]["artifact_type"] == "listfile"
    assert acks[0]["item_count"] == 4
    # Idempotent re-apply → no new ACK.
    sync.apply_artifact(ARTIFACT, tenant_id=TENANT, etag="e1")
    assert len(acks) == 1
